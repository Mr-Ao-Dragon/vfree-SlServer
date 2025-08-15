# 使用官方 Python 基础镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 复制项目依赖文件
COPY ../requirements.txt .
# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt

# 复制项目文件到工作目录
COPY .. .

# 第二阶段：运行 Nginx 和应用
FROM nginx:alpine

# 配置 Nginx
COPY nginx.conf /etc/nginx/nginx.conf

# 暴露应用端口
EXPOSE 8000

# 定义启动命令
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8888"]
