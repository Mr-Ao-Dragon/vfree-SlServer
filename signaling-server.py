import os
import logging
import time
import jwt
from jwt.exceptions import DecodeError
import redis
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import asyncio
from contextlib import asynccontextmanager

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# 系统配置
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_DB = int(os.getenv('REDIS_DB', 0))
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', None)
REDIS_KEY_PREFIX = 'webrtc:'

# 安全配置
SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# 创建 Redis 客户端实例
def create_redis_client():
    return redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        password=REDIS_PASSWORD,
        decode_responses=True,
        socket_timeout=5,
        socket_connect_timeout=5,
    )


redis_client = create_redis_client()


# 数据模型
class Message(BaseModel):
    """消息数据模型"""
    type: str
    target: str
    payload: dict


class RoomCreateRequest(BaseModel):
    """创建房间请求模型"""
    room_id: str
    password: Optional[str] = None
    owner: str


class UserAuth(BaseModel):
    """用户认证模型"""
    user_id: str
    password: Optional[str] = None


class Token(BaseModel):
    """认证令牌模型"""
    access_token: str
    token_type: str


# 身份验证
class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=401, detail="Invalid authentication scheme.")
            try:
                payload = self.verify_jwt(credentials.credentials)
                return payload
            except Exception as e:
                logger.error(f"Token verification failed: {e}")
                raise HTTPException(status_code=401, detail="Invalid token or expired token.")
        else:
            raise HTTPException(status_code=401, detail="Invalid authorization code.")

    def verify_jwt(self, jwt_token: str) -> dict:
        try:
            payload = jwt.decode(jwt_token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    # 修改编码方法调用
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    except DecodeError as e:
        logger.error(f"JWT encoding error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create access token")
    return encoded_jwt


# 房间和用户管理
class Room:
    def __init__(self, room_id: str, password: Optional[str] = None, owner: str = None):
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


# 信令服务器核心功能
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Server started")
    app.state.start_time = time.time()  # 移动 startup 事件逻辑到这里
    # 启动后台任务：定期清理不活跃的房间
    asyncio.create_task(cleanup_inactive_rooms())
    try:
        yield
    finally:
        logger.info("Server shutting down")
        # 清理 Redis 数据
        for key in redis_client.keys(f"{REDIS_KEY_PREFIX}*"):
            redis_client.delete(key)

app = FastAPI(lifespan=lifespan)


# 连接管理
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


# 后台任务：定期清理不活跃的房间
async def cleanup_inactive_rooms():
    while True:
        try:
            logger.info("Checking for inactive rooms...")
            now = datetime.now()
            rooms_to_delete = []

            for room_id, room in rooms.items():
                # 如果房间为空，直接删除
                if room.is_empty():
                    rooms_to_delete.append(room_id)
                    continue

                # 如果房间超过30分钟没有活动，删除
                inactive_time = (now - room.last_activity).total_seconds()
                if inactive_time > 1800:  # 30分钟
                    rooms_to_delete.append(room_id)

            # 删除标记的房间
            for room_id in rooms_to_delete:
                # 通知所有用户房间即将关闭
                room = rooms[room_id]
                users = room.get_users()
                for user_id in users:
                    try:
                        await room.get_websocket(user_id).send_json({
                            "type": "room_closed",
                            "target": user_id,
                            "payload": {"reason": "Room inactive for 30 minutes"}
                        })
                        # 关闭连接
                        await room.get_websocket(user_id).close(code=1000, reason="Room closed")
                    except Exception as e:
                        logger.error(f"Error notifying user {user_id} about room closure: {e}")

                # 从内存和 Redis 中删除房间
                del rooms[room_id]
                redis_client.delete(f"{REDIS_KEY_PREFIX}room:{room_id}")
                redis_client.delete(f"{REDIS_KEY_PREFIX}room:{room_id}:users")
                logger.info(f"Room {room_id} deleted due to inactivity")

            # 检查 Redis 中是否有孤立的房间数据
            for key in redis_client.keys(f"{REDIS_KEY_PREFIX}room:*"):
                if not key.endswith(":users"):
                    room_id = key.split(":")[-1]
                    if room_id not in rooms:
                        redis_client.delete(key)
                        redis_client.delete(f"{REDIS_KEY_PREFIX}room:{room_id}:users")
                        logger.info(f"Orphaned room data {room_id} deleted from Redis")

            # 每10分钟检查一次
            await asyncio.sleep(600)
        except Exception as e:
            logger.error(f"Error in cleanup task: {e}")
            # 发生错误时等待一段时间再重试
            await asyncio.sleep(60)


# WebSocket 端点
@app.websocket("/ws/{room_id}/{user_id}")
async def websocket_endpoint(websocket: WebSocket, room_id: str, user_id: str, token: str):
    await handle_connection(websocket, room_id, user_id, token)


# RESTful API 端点
@app.post("/rooms/", response_model=Token)
def create_room(request: RoomCreateRequest):
    """
    创建新房间

    - **request**: 创建房间的请求体，包含房间 ID、密码和房主信息。
    - **返回值**: 包含访问令牌和令牌类型的响应。
    - **异常**: 如果房间已存在，返回 400 状态码。
    """

    room_id = request.room_id

    # 检查房间是否已存在
    if redis_client.exists(f"{REDIS_KEY_PREFIX}room:{room_id}"):
        raise HTTPException(status_code=400, detail="Room already exists")

    # 存储房间信息到 Redis
    with redis_client.pipeline() as pipe:
        pipe.hset(f"{REDIS_KEY_PREFIX}room:{room_id}", "owner", request.owner)
        if request.password:
            pipe.hset(f"{REDIS_KEY_PREFIX}room:{room_id}", "password", request.password)
        pipe.hset(f"{REDIS_KEY_PREFIX}room:{room_id}", "created_at", str(datetime.now()))
        pipe.hset(f"{REDIS_KEY_PREFIX}room:{room_id}", "last_activity", str(datetime.now()))
        pipe.execute()

    # 创建访问令牌
    access_token = create_access_token(
        data={"sub": request.owner, "room": room_id, "role": "owner"},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/rooms/{room_id}/join", response_model=Token)
def join_room(room_id: str, request: UserAuth):
    """加入现有房间"""
    # 检查房间是否存在
    if not redis_client.exists(f"{REDIS_KEY_PREFIX}room:{room_id}"):
        raise HTTPException(status_code=404, detail="Room not found")

    # 验证密码
    stored_password = redis_client.hget(f"{REDIS_KEY_PREFIX}room:{room_id}", "password")
    if stored_password and stored_password != request.password:
        raise HTTPException(status_code=401, detail="Invalid password")

    # 创建访问令牌
    role = "owner" if request.user_id == redis_client.hget(f"{REDIS_KEY_PREFIX}room:{room_id}",
                                                           "owner") else "participant"
    access_token = create_access_token(
        data={"sub": request.user_id, "room": room_id, "role": role},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    # 更新房间活跃时间
    redis_client.hset(f"{REDIS_KEY_PREFIX}room:{room_id}", "last_activity", str(datetime.now()))

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/rooms/")
def list_rooms():
    """获取所有房间列表"""
    rooms = []
    for key in redis_client.keys(f"{REDIS_KEY_PREFIX}room:*"):
        if not key.endswith(":users"):
            room_id = key.split(":")[-1]
            room_data = redis_client.hgetall(key)
            rooms.append({
                "room_id": room_id,
                "owner": room_data.get("owner"),
                "created_at": room_data.get("created_at"),
                "last_activity": room_data.get("last_activity"),
                "has_password": "password" in room_data,
                "user_count": len(redis_client.hgetall(f"{REDIS_KEY_PREFIX}room:{room_id}:users"))
            })
    return rooms


@app.get("/rooms/{room_id}/users")
def get_room_users(room_id: str):
    """获取指定房间的用户列表"""
    if not redis_client.exists(f"{REDIS_KEY_PREFIX}room:{room_id}"):
        raise HTTPException(status_code=404, detail="Room not found")

    users = redis_client.hgetall(f"{REDIS_KEY_PREFIX}room:{room_id}:users")
    return [{"user_id": user_id, "joined_at": joined_at} for user_id, joined_at in users.items()]


@app.get("/stats/")
def get_server_stats():
    """
    获取服务器统计信息

    - **返回值**:
        包含活动房间数、总房间数、总用户数、启动时间和 Redis 连接信息的字典。
    """
    active_rooms = len(rooms)
    total_rooms = len(redis_client.keys(f"{REDIS_KEY_PREFIX}room:*")) // 2  # 除以2是因为每个房间有两个键
    total_users = 0

    for room_id in rooms:
        total_users += len(rooms[room_id].users)

    # 获取 Redis 连接信息
    redis_info = redis_client.info()

    return {
        "active_rooms": active_rooms,
        "total_rooms": total_rooms,
        "total_users": total_users,
        "uptime": time.time() - app.state.start_time if hasattr(app.state, 'start_time') else "N/A",
        "redis_connections": redis_info.get("connected_clients", "N/A"),
        "redis_memory_usage": f"{redis_info.get('used_memory_human', 'N/A')} / {redis_info.get('maxmemory_human', 'N/A')}"
    }


if __name__ == "__main__":
    import uvicorn
    cert_path = os.path.abspath("./server/localhost.pem")
    key_path = os.path.abspath("./server/localhost-key.pem")
    uvicorn.run(
        "signaling-server:app",
        host="localhost",
        port=8001,
        ssl_certfile=cert_path,
        ssl_keyfile=key_path,
        reload=True
    )