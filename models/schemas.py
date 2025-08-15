from pydantic import BaseModel
from typing import Optional, Dict


class SetupConnection(BaseModel):
    """设置连接模型"""
    key: str
    password: str
    status: str
    lifetime: int

class Token(BaseModel):
    """认证令牌模型"""
    access_token: str
    token_type: str

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
    user_key: str
    password: Optional[str] = None

class RoomInfo(BaseModel):
    """房间信息模型"""
    room_id: str
    owner: str
    password: Optional[str] = None
    users: Dict[str, str] = None
