# server.py
import os
import json
import asyncio
from typing import Dict

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState
import redis.asyncio as aioredis

app = FastAPI()

# Redis 可选，用于离线 sdp/ice 缓存（如果不需要可删）
REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)
redis = aioredis.from_url(
    f"redis://{REDIS_HOST}:{REDIS_PORT}",
    password=REDIS_PASSWORD if REDIS_PASSWORD else None,
    decode_responses=True,
)

clients: Dict[str, WebSocket] = {}
clients_lock = asyncio.Lock()


async def push_offline(target: str, msg: dict):
    # store only signaling messages for later delivery
    await redis.rpush(f"signaling_queue:{target}", json.dumps(msg))


async def drain_queue(target: str, ws: WebSocket):
    key = f"signaling_queue:{target}"
    while True:
        raw = await redis.lpop(key)
        if raw is None:
            break
        await ws.send_text(raw)


@app.websocket("/ws/{client_id}")
async def ws_endpoint(ws: WebSocket, client_id: str):
    await ws.accept()
    async with clients_lock:
        clients[client_id] = ws
    print(f"[signal] {client_id} connected")

    # drain any queued signaling
    try:
        await drain_queue(client_id, ws)
    except Exception as e:
        print(f"[signal] drain error {e}")

    try:
        while True:
            text = await ws.receive_text()
            try:
                msg = json.loads(text)
                print("消息：",msg)
            except Exception:
                # ignore non-json
                continue

            t = msg.get("type")
            target = msg.get("to")
            if not (t and target):
                continue

            # only allow signaling types here
            if t not in ("offer", "answer", "ice"):
                # ignore/send back error if desired
                continue

            async with clients_lock:
                target_ws = clients.get(target)

            if target_ws is not None and target_ws.application_state == WebSocketState.CONNECTED:
                try:
                    await target_ws.send_text(json.dumps(msg))
                except Exception as e:
                    print(f"[signal] forward failed: {e}, queueing")
                    await push_offline(target, msg)
                    async with clients_lock:
                        cur = clients.get(target)
                        if cur is target_ws:
                            clients.pop(target, None)
            else:
                # target offline -> queue
                await push_offline(target, msg)

    except WebSocketDisconnect:
        print(f"[signal] {client_id} disconnected")
    except Exception as e:
        print(f"[signal] unexpected: {e}")
    finally:
        async with clients_lock:
            cur = clients.get(client_id)
            if cur is ws:
                clients.pop(client_id, None)
        try:
            if ws.application_state != WebSocketState.DISCONNECTED:
                await ws.close()
        except Exception:
            pass
        print(f"[signal] cleaned {client_id}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("test:app", host="0.0.0.0", port=8000, reload=True)
