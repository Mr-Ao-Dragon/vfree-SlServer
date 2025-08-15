# 接口文档

## HTTP API

### 建立服务状态
```http request
POST https://localhost:8001/status/
```
```plaintext
用于建立连接，查看服务状态
request:
    body:
        {
            "key": string // 唯一标识符，
            "status": string // 状态，online / offline
            "lifetime": int // 连接时长，单位：秒
        }

resonse: {
    "code": int, // 状态码
    "message": string, // 描述信息
    "token": string // 令牌，用于后续请求
}
```

## WSS API

### 信令交换
```http request
WEBSOCKET wss://localhost:8001/ws/signaling？token={token}
```
```plaintext
用于信令交换
request:
    {
        "type": string, // 消息类型
        "target": string, // 目标用户
        "payload": object // 消息内容
    }
return:
    {
        "type": string, // 消息类型
        "target": string, // 目标用户
        "payload": object // 消息内容
    }
```