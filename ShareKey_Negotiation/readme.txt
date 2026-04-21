

环境要求

Python 3.x

cryptography

pandas

secrets

hashlib

socket



-----针对非对称的情况，在PCKA之前，会先运行ShareKey方案-----
先启动 Server
然后启动 Alice 和 Bob, 确保二者完成注册后再回车进入认证阶段，认证时先输入Bob的口令，后输入Alice的口令（这样Alice端的时间更准确）

运行完毕后，可手动关闭Server端