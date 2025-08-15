#!/bin/bash
echo "WebRTC 信令服务部署!"

apt_YL=('git' 'python3-pip' 'redis' 'rabbitmq-server' 'nginx' 'certbot' 'python3-certbot-nginx')
yum_YL=('openssl-devel','bzip2-devel','libffi-devel','wget','redis')
LOCAL_SPACE="$PWD"
WORK_SPACE="/opt/signaling-server"
VENV_ENV="$HOME/.venv"

sys_dep(){
  echo "安装系统依赖"
if [ -f "/bin/apt" ];then
  PKG="apt"
  for i in "${apt_YL[@]}";do
    sudo $PKG install -y $i
  done
elif [ -f "/bin/yum" ];then
  PKG="yum"
  for i in "${yum_YL[@]}";do
    sudo $PKG install -y $i
  done
fi
}
sys_dep
