from fastapi import APIRouter, HTTPException
from datetime import datetime, timedelta

from config import REDIS_KEY_PREFIX,ACCESS_TOKEN_EXPIRE_MINUTES
from models.schemas import RoomCreateRequest, UserAuth, Token
from utils.redis_utils import redis_client
from utils.jwt_utils import create_access_token


router = APIRouter()

@router.post("/rooms/", response_model=Token)
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

@router.post("/rooms/{room_id}/join", response_model=Token)
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

@router.get("/rooms/")
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

@router.get("/rooms/{room_id}/users")
def get_room_users(room_id: str):
    """获取指定房间的用户列表"""
    if not redis_client.exists(f"{REDIS_KEY_PREFIX}room:{room_id}"):
        raise HTTPException(status_code=404, detail="Room not found")

    users = redis_client.hgetall(f"{REDIS_KEY_PREFIX}room:{room_id}:users")
    return [{"user_id": user_id, "joined_at": joined_at} for user_id, joined_at in users.items()]
