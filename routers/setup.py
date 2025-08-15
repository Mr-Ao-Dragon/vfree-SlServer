from fastapi import APIRouter
from datetime import datetime, timedelta

from config import REDIS_KEY_PREFIX
from models.schemas import SetupConnection
from utils.jwt_utils import create_access_token
from utils.redis_utils import redis_client


def _status(code, message, token=None):
    return {
        "code": code,
        "message": message,
        "token": {
            "token_type": "bearer",
            "access_token": token
        }
    }


router = APIRouter()
@router.post('/setup/', summary='建立连接')
async def setup(request: SetupConnection):
    """
    建立连接，申请Token，获取服务器统计信息
    - **request**:
        - **key**: 密钥
        - **status**: 状态
        - **lifetime**: 有效期（秒）
    - **返回值**:
        - **code**: 状态码
        - **message**: 描述信息
        - **token**: 令牌，用于后续请求
    - **示例**:
        ```json
        {
            "code": 0,
            "message": "success",
            "token": {
                "access_token": "",
                "token_type": "bearer"
            }
        }
    - **错误码**:
        - 0: 成功
        - 1: 密钥错误
        - 2: 状态错误
    """
    user_key, user_status, user_lifetime = request.key,request.status, request.lifetime

    # 创建访问令牌
    access_token = create_access_token(
        data={"sub": user_key, "lifetime": user_lifetime},
        expires_delta=timedelta(minutes=user_lifetime)
    )
    # 检查user key是否已存在
    if redis_client.exists(f"{REDIS_KEY_PREFIX}users:{user_key}"):
        redis_client.hset(f"{REDIS_KEY_PREFIX}users:{user_key}", "last_activity", str(datetime.now()))
        return _status(code=0, message="key已经存在", token=access_token)
    # 存储用户信息到 Redis
    with redis_client.pipeline() as pipe:
        pipe.hset(f"{REDIS_KEY_PREFIX}users:{user_key}", "status", user_status)
        pipe.hset(f"{REDIS_KEY_PREFIX}users:{user_key}", "lifetime", user_lifetime)
        pipe.hset(f"{REDIS_KEY_PREFIX}users:{user_key}", "created_at", str(datetime.now()))
        pipe.hset(f"{REDIS_KEY_PREFIX}users:{user_key}", "last_activity", str(datetime.now()))
        pipe.execute()
    return _status(code=0, message="key已建立连接", token=access_token)
