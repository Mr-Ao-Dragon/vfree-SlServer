# WebRTC Signaling Server

## 实现思路
1. 使用 FastAPI 作为 Web 框架，提供高性能的异步处理能力
2. 使用 WebSocket 实现实时双向通信
3. 实现房间管理功能，支持多个独立会话
4. 处理 SDP Offer/Answer 和 ICE 候选的转发




## 部署
### 1. 安装依赖
```bash
# 添加 deadsnakes PPA
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update

# 安装 Python 3.12
sudo apt install python3.12 python3.12-dev python3.12-venv

# 验证安装
python3.12 --version

# 添加 Redis 官方 APT 源
curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list

# 安装 Redis
sudo apt update
sudo apt install redis

# 配置 Redis
sudo systemctl enable redis-server
sudo systemctl start redis-server

# 配置 RabbitMQ
sudo apt install rabbitmq-server
sudo systemctl enable rabbitmq-server
sudo systemctl start rabbitmq-server

# 启用管理插件
sudo rabbitmq-plugins enable rabbitmq_management

# 创建管理员用户（可选）
sudo rabbitmqctl add_user admin your_password
sudo rabbitmqctl set_user_tags admin administrator
sudo rabbitmqctl set_permissions -p / admin ".*" ".*" ".*"

# 安装nginx
sudo apt install nginx
# 创建符号链接
sudo ln -s /etc/nginx/sites-available/signaling-server /etc/nginx/sites-enabled/
# 检查配置
sudo nginx -t
# 重启 Nginx
sudo systemctl restart nginx
```

### 2. 信令服务器安装与配置
```bash
sudo mkdir -p /opt/signaling-server
sudo chown -R $USER:$USER /opt/signaling-server
cd /opt/signaling-server

# 克隆代码仓库（或上传代码文件）
git clone <your-repo-url> .

# 克隆仓库
git clone URL_ADDRESSgit clone https://github.com/yourusername/webrtc-signaling-server.git
cd webrtc-signaling-server
# 创建并激活虚拟环境
python3.12 -m venv venv
source venv/bin/activate
# 安装依赖
pip install -r requirements.txt
# 启动服务器
uvicorn main:app --reload
```
### 3. 重载 systemd 并启动服务
```bash
# 重载 systemd 管理器配置
sudo systemctl daemon-reload

# 启动服务
sudo systemctl start signaling-server

# 设置开机自启
sudo systemctl enable signaling-server

# 检查服务状态
sudo systemctl status signaling-server
```

### 4.配置SSL证书
```bash
sudo apt install certbot python3-certbot-nginx  # Ubuntu/Debian
# 获取证书
sudo certbot --nginx -d your_domain.com
```

### 5. 测试
```bash
sudo systemctl status signaling-server

#signaling-server.service - WebRTC Signaling Server
#  Active: active (running) since Mon 2023-10-23 14:30:45 UTC; 5min ago

# 测试 API 端点
curl http://localhost:8000/health

# 安装 wscat
npm install -g wscat

# 连接到 WebSocket
wscat -c ws://localhost:8000/ws/your_token/your_room
```


