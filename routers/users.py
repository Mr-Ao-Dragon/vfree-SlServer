from fastapi import APIRouter, WebSocket, WebSocketDisconnect



router = APIRouter()


@router.websocket("/ws/swap/")
async def swap_signal(websocket: WebSocket, user_key: str,token:str):
    """
    交换信号
    :param websocket:
    :param user_key:
    :param token:
    :return:
    """
    return {"code": 0, "msg": "success"}


