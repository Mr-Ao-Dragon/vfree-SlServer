import redis

from config import REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD

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