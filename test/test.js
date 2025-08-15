const roomId = "test_room";
const userId = "user123";
const ws = new WebSocket(`ws://localhost:8000/${roomId}/${userId}`);

// 连接建立
ws.onopen = () => {
    console.log("连接已建立");
};

// 接收消息
ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log("收到消息:", data);
};

// 发送消息
const sendMessage = (targetId, payload) => {
    ws.send(JSON.stringify({
        type: "message",
        target: targetId,
        payload: payload
    }));
};

// 发送SDP Offer示例
sendMessage("target_user", {
    type: "offer",
    sdp: "your_sdp_offer_here"
});