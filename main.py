from contextlib import asynccontextmanager
from fastapi import FastAPI
from datetime import datetime
import asyncio,os,time

from config import REDIS_KEY_PREFIX
from utils.redis_utils import redis_client
from utils.logger_utils import logger
import routers


# 后台任务：定期清理不活跃的用户数据
async def cleanup_inactive_users():
    while True:
        logger.info("清理不活跃数据")
        try:
            # 检查 Redis 中是否有不活跃的用户数据 30分钟
            cursor = 0
            now = datetime.now()
            while True:
                # 使用 scan 方法迭代查找包含 users 的键
                cursor, keys = redis_client.scan(cursor, match=f"{REDIS_KEY_PREFIX}users:*")
                for key in keys:
                    if key:
                        last_activate_time = redis_client.hget(key, "last_activity")
                        if last_activate_time is None:
                            # 如果 last_activate_time 为 None，删除该键
                            redis_client.delete(key)
                            continue
                        try:
                            # 将 last_activate_time 转换为 datetime 对象
                            last_activate_time = datetime.fromisoformat(last_activate_time)
                            # 计算不活跃时间
                            inactive_time = (now - last_activate_time).total_seconds()
                            if inactive_time > 60*30:
                                redis_client.delete(key)
                        except ValueError:
                            # 处理时间格式错误
                            logger.error(f"Invalid datetime format for key {key}")
                            redis_client.delete(key)
                if cursor == 0:
                    break

            # 每10分钟检查一次
            await asyncio.sleep(60*10)
        except Exception as e:
            logger.error(f"Error in cleanup task: {e}")
            # 发生错误时等待一段时间再重试
            await asyncio.sleep(60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Server started")
    app.state.start_time = time.time()
    asyncio.create_task(cleanup_inactive_users())
    try:
        yield
    finally:
        logger.info("Server shutting down")
        for key in redis_client.keys(f"{REDIS_KEY_PREFIX}*"):
            redis_client.delete(key)

app = FastAPI(lifespan=lifespan)

# 挂载路由
app.include_router(routers.setup.router)
app.include_router(routers.users.router)

if __name__ == "__main__":
    import uvicorn
    cert_path = os.path.abspath("./server/localhost.pem")
    key_path = os.path.abspath("./server/localhost-key.pem")
    uvicorn.run(
        "main:app",
        host="localhost",
        port=8000,
        ssl_certfile=cert_path,
        ssl_keyfile=key_path,
        reload=True
    )