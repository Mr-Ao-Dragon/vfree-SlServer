from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Dict,List,Optional
from datetime import datetime
import jwt

from config import REDIS_KEY_PREFIX, SECRET_KEY, ALGORITHM
from models.schemas import Message
from utils.redis_utils import redis_client
from utils.logger_utils import logger


router = APIRouter()

class Room:
    def __init__(self, room_id: str, password: str = None, owner: str = None):
        self.room_id = room_id
        self.password = password
        self.owner = owner
        self.users: Dict[str, WebSocket] = {}
        self.created_at = datetime.now()
        self.last_activity = datetime.now()

    def add_user(self, user_id: str, websocket: WebSocket):
        self.users[user_id] = websocket
        self.last_activity = datetime.now()
        # 记录用户加入时间到 Redis
        redis_client.hset(f"{REDIS_KEY_PREFIX}room:{self.room_id}:users", user_id, str(datetime.now()))
        # 更新房间活跃时间
        redis_client.hset(f"{REDIS_KEY_PREFIX}room:{self.room_id}", "last_activity", str(self.last_activity))

    def remove_user(self, user_id: str):
        if user_id in self.users:
            del self.users[user_id]
            self.last_activity = datetime.now()
            # 从 Redis 中移除用户
            redis_client.hdel(f"{REDIS_KEY_PREFIX}room:{self.room_id}:users", user_id)
            # 更新房间活跃时间
            redis_client.hset(f"{REDIS_KEY_PREFIX}room:{self.room_id}", "last_activity", str(self.last_activity))
            return True
        return False

    def get_users(self) -> List[str]:
        return list(self.users.keys())

    def is_empty(self) -> bool:
        return len(self.users) == 0

    def has_user(self, user_id: str) -> bool:
        return user_id in self.users

    def get_websocket(self, user_id: str) -> Optional[WebSocket]:
        return self.users.get(user_id)

    def check_password(self, password: Optional[str]) -> bool:
        return self.password is None or self.password == password

rooms: Dict[str, Room] = {}

# 连接管理和消息处理函数保持不变
async def handle_connection(websocket: WebSocket, room_id: str, user_id: str, token: str):
    # 验证 token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        token_user_id = payload.get("sub")
        if token_user_id != user_id:
            await websocket.close(code=1008, reason="Invalid user ID in token")
            return
    except Exception as e:
        logger.error(f"Token validation failed: {e}")
        await websocket.close(code=1008, reason="Invalid authentication token")
        return

    # 验证房间是否存在
    if room_id not in rooms:
        # 尝试从 Redis 加载房间
        room_data = redis_client.hgetall(f"{REDIS_KEY_PREFIX}room:{room_id}")
        if not room_data:
            await websocket.close(code=1008, reason="Room not found")
            return
        password = room_data.get("password")
        owner = room_data.get("owner")
        rooms[room_id] = Room(room_id, password, owner)

    room = rooms[room_id]

    # 验证用户是否有权限加入房间
    if not room.check_password(None):  # 简化：实际应用中应从请求中获取密码
        await websocket.close(code=1008, reason="Authentication failed")
        return

    try:
        await websocket.accept()
        room.add_user(user_id, websocket)

        # 通知房间内其他用户有新用户加入
        users = room.get_users()
        for other_user_id in users:
            if other_user_id != user_id:
                try:
                    await room.get_websocket(other_user_id).send_json({
                        "type": "user_joined",
                        "target": other_user_id,
                        "payload": {"user_id": user_id}
                    })
                except Exception as e:
                    logger.error(f"Error notifying user {other_user_id}: {e}")

        # 向新用户发送房间内现有用户列表
        await websocket.send_json({
            "type": "room_users",
            "target": user_id,
            "payload": {"users": users}
        })

        # 进入消息循环
        while True:
            data = await websocket.receive_json()
            message = Message(**data)
            await handle_message(room, user_id, message)

    except WebSocketDisconnect:
        # 处理连接断开事件
        room.remove_user(user_id)
        users = room.get_users()

        # 通知房间内其他用户该用户已离开
        for other_user_id in users:
            try:
                await room.get_websocket(other_user_id).send_json({
                    "type": "user_left",
                    "target": other_user_id,
                    "payload": {"user_id": user_id}
                })
            except Exception as e:
                logger.error(f"Error notifying user {other_user_id}: {e}")

        # 如果房间为空，考虑销毁房间
        if room.is_empty():
            del rooms[room_id]
            redis_client.delete(f"{REDIS_KEY_PREFIX}room:{room_id}")
            redis_client.delete(f"{REDIS_KEY_PREFIX}room:{room_id}:users")
            logger.info(f"Room {room_id} destroyed (empty)")

    except Exception as e:
        logger.error(f"Error handling connection for user {user_id} in room {room_id}: {e}")
        room.remove_user(user_id)
        users = room.get_users()

        # 通知房间内其他用户该用户已离开
        for other_user_id in users:
            try:
                await room.get_websocket(other_user_id).send_json({
                    "type": "user_left",
                    "target": other_user_id,
                    "payload": {"user_id": user_id}
                })
            except Exception as e:
                logger.error(f"Error notifying user {other_user_id}: {e}")

        # 如果房间为空，考虑销毁房间
        if room.is_empty():
            del rooms[room_id]
            redis_client.delete(f"{REDIS_KEY_PREFIX}room:{room_id}")
            redis_client.delete(f"{REDIS_KEY_PREFIX}room:{room_id}:users")
            logger.info(f"Room {room_id} destroyed (empty)")

# 消息处理
async def handle_message(room: Room, sender_id: str, message: Message):
    target_user_id = message.target

    # 检查目标用户是否在房间内
    if not room.has_user(target_user_id):
        logger.warning(f"Target user {target_user_id} not found in room {room.room_id}")
        try:
            sender_ws = room.get_websocket(sender_id)
            if sender_ws:
                await sender_ws.send_json({
                    "type": "error",
                    "target": sender_id,
                    "payload": {"message": f"User {target_user_id} not found"}
                })
        except Exception as e:
            logger.error(f"Error sending error message to {sender_id}: {e}")
        return

    # 转发消息
    target_ws = room.get_websocket(target_user_id)
    try:
        await target_ws.send_json({
            "type": message.type,
            "target": target_user_id,
            "payload": {
                "sender": sender_id,
                "data": message.payload
            }
        })
        logger.info(f"Message forwarded from {sender_id} to {target_user_id} in room {room.room_id}")
    except Exception as e:
        logger.error(f"Failed to forward message to {target_user_id}: {e}")
        try:
            sender_ws = room.get_websocket(sender_id)
            if sender_ws:
                await sender_ws.send_json({
                    "type": "error",
                    "target": sender_id,
                    "payload": {"message": f"Failed to deliver message to {target_user_id}"}
                })
        except Exception as e:
            logger.error(f"Error sending error message to {sender_id}: {e}")


@router.websocket("/ws/{room_id}/{user_id}")
async def websocket_endpoint(websocket: WebSocket, room_id: str, user_id: str, token: str):
    await handle_connection(websocket, room_id, user_id, token)