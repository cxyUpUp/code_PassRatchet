---本代码是对论文中“Illustration of the PCKA Process for Secure Messaging within One Communication Round”的实现，最终解密的m经过
对称棘轮处理后用于产生消息加密密钥---

1. 环境要求

Python 3.x

cryptography

pandas

secrets

hashlib

socket

2. 3个主要文件：

Server.py：服务器端，负责接收 Alice 和 Bob 的连接、处理消息并协调初始化和消息交换。

Alice.py：Alice 客户端，负责初始化阶段、向服务器发送请求并接收消息。

Bob.py：Bob 客户端，等待 Alice 发起通信，进行安全消息交换

3. 运行顺序

步骤 1： 启动 Server.py
步骤 2： 先启动 Alice，后Bob.py
步骤 3： 确定双方连接Sever成功后，再输入双方的口令开启PCKA流程


运行完毕后，可手动关闭Server端


------------------------------------------AWS EC2-------------------------------------
#连接ec2, 本地powershell,server在大阪,client在伦敦
ssh -i "D:\pyProiect\aws_key.pem" ec2-user@56.155.1.40

# 进入项目目录, 若没有server-S文件夹，需要新建立
cd /home/ec2-user/server-S  

# 创建虚拟环境（最开始需新建虚拟环境），之后直接激活即可
python3 -m venv venv1

# 激活虚拟环境
source venv1/bin/activate

