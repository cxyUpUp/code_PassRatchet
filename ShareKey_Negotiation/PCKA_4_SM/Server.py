# Server.py
import hashlib
import socket
import threading
import json
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from math import gcd
from dataclasses import dataclass
from typing import Tuple, Optional
import time



# 服务器的参数和加密逻辑
p = 2 ** 521 - 1
g = 5
ORDER = p - 1

#A select session id randomly
sid=secrets.token_bytes(16)
# print("Session ID (sid):", sid)



def H_to_int(*parts: bytes) -> int:
    """Hash H: {0,1}* -> Z_ORDER (as integer)."""
    h = hashlib.sha256()
    for b in parts:
        h.update(b)
    return int.from_bytes(h.digest(), 'big') % ORDER

def int_to_bytes(i: int) -> bytes:
    return i.to_bytes((i.bit_length() + 7)//8 or 1, 'big')

def rand_coprime(mod):
    while True:
        x = secrets.randbelow(mod - 2) + 1
        if gcd(x, mod) == 1:
            return x

def kdf_bytes(*parts: bytes) -> bytes:
    """Simple key derivation -> 32 bytes."""
    h = hashlib.sha256()
    for b in parts:
        h.update(b)
    return h.digest()

# Symmetric encryption (SE) using AES-GCM
def SE_enc(key_bytes: bytes, plaintext: bytes) -> bytes:
    aes = AESGCM(hashlib.sha256(key_bytes).digest())  # 32-byte key
    nonce = secrets.token_bytes(12)
    ct = aes.encrypt(nonce, plaintext, None)
    return nonce + ct

def SE_dec(key_bytes: bytes, blob: bytes) -> Optional[bytes]:
    try:
        aes = AESGCM(hashlib.sha256(key_bytes).digest())
        nonce, ct = blob[:12], blob[12:]
        pt = aes.decrypt(nonce, ct, None)
        return pt
    except Exception:
        return None

# -----------------------
# States dataclasses
# -----------------------
@dataclass
class ServerState:
    sk: int                 # server  secret
    alpha_last: Optional[int] = None  # store last received alpha

@dataclass
class PartyState:
    # For both A and B: state is a pair (r, k) OR (0, k)
    r: int
    k: int

def Setup() -> Tuple[int,int,int]:
    """Setup(1^lambda) -> params: returns (p, g, ORDER) in this demo."""
    # params are module-level; simply return them
    return (p, g, ORDER)

def Init() :
    """
    Init(pwA, pwB) -> (gamma_S, gamma_A, gamma_B)
    Implements the described three-step initialization using the server as in the text.
    - A produces alpha_A0 = H(pwA)^{rA0}, sends to S
    - S computes beta_A0 = alpha_A0^{sk} and returns to A
    - A recovers kA0 = beta_A0^{1/rA0} (so kA0 = H(pwA)^{sk})
    - Same for B
    - Server state gamma_S = (sk, alpha_B0)  (per text)
    """
    # Server chooses sk
    sk = secrets.randbelow(ORDER - 2) + 2
    gamma_S = ServerState(sk=sk, alpha_last=None)
    return gamma_S


def Ser(gamma_S: ServerState, alpha_: int) -> Tuple[int, ServerState]:
    """
    Ser(gamma_S, alpha_A) -> (beta_B, gamma_S')
    - server parses its state gamma_S = (sk, alpha_last)
    - computes beta_B = alpha_A^{sk}
    - updates gamma_S' = (sk, alpha_A)
    """
    sk, alpha = gamma_S.sk, gamma_S.alpha_last
    beta = pow(alpha, sk, p)
    gamma_S.alpha_last = alpha_
    return beta, gamma_S

def KRt(gamma_S: ServerState) -> ServerState:
    """
    KRt(gamma_S) -> gamma_S'
    - server samples random r_s and computes new sk' = kdf(sk, r_s)
    - update gamma_S to (sk', alpha_A) where alpha_A is last stored alpha
    """
    rs = secrets.token_bytes(16)
    new_sk_bytes = kdf_bytes(int_to_bytes(gamma_S.sk), rs)
    # map to integer in Z_ORDER
    new_sk = int.from_bytes(new_sk_bytes, 'big') % ORDER
    if new_sk == 0:
        new_sk = 1
    gamma_S.sk = new_sk
    return gamma_S

def send_msg(conn, msg):
    message_str = json.dumps(msg) + "\n"  # 在每条消息后面加上换行符（`\n`）
    conn.sendall(message_str.encode())  # 发送数据

clients = {}  # 保存 {"Alice": connA, "Bob": connB}
session_data = {
        "Alice": {},
        "Bob": {},
        "init_done": False
    }

def handle_client(conn, addr, gamma_S):
    identity=None


    try:
        while True:
            msg_raw = conn.recv(4096).decode().strip()  # 接收并去掉空白字符和换行
            # print(f"[Debug] msg_raw from {addr}: {msg_raw}")
            if not msg_raw:
                print(f"[!] {addr} disconnected.")
                break

            # 尝试解析 JSON 数据
            try:
                msg = json.loads(msg_raw)
            except json.JSONDecodeError:
                print(f"[!] Invalid JSON from {addr}: {msg_raw}")
                continue  # 跳过当前消息，继续接收

            msg_type = msg.get("type")
            # === Step 1: 客户端发送身份 ===
            if msg_type == "identity":

                response = {"type": "ack", "msg": f"Hello {msg['name']}, registered."}
                print(f"[Server] Sending response: Hello {msg['name']}.")
                conn.sendall(json.dumps(response).encode())  # 发送确认消息

                identity = msg.get("name")
                clients[identity] = conn
                # print(f"[Server] Registered identity: {identity}")
                continue
            # 处理其他消息
            if msg_type == "session_id":
                sid = bytes.fromhex(msg["sid"])
                current_sid = sid
                print(f"[Server] Received session ID from Alice: {sid.hex()}")
                while True:
                    if "Bob" in clients:
                        send_msg(clients["Bob"], {"type": "session_id", "sid": sid.hex()})
                        break
                    else:
                        # print(f"[Server] Bob not connected yet. Cannot forward session ID.")
                        continue

                continue
            elif msg_type == "ack_sid":
                print(f"[Server] Received ACK for session ID from Bob.")
                send_msg(clients["Alice"], {"type": "ack_sid"})

                continue

            elif msg_type == "send_alpha_A0":

                alpha_A0 = int(msg["alpha_A0"], 16)
                session_data["Alice"]["alpha_A0"] = alpha_A0
                print(f"[Server-Alice] Received <alpha_A0> from Alice.")

                # 计算 beta_A0 并回给 Alice
                beta_A0 = pow(alpha_A0, gamma_S.sk, p)
                beta_A0_hex = hex(beta_A0)[2:]
                response_to_alice = {"type": "send_beta_A0", "beta_A0": beta_A0_hex}
                send_msg(clients["Alice"], response_to_alice)
                print(f"[Server-Alice] Sent <beta_A0> to Alice")

                # 循环等待 Bob 上线
                max_wait_time = 10  # 最多等待 10 秒
                interval = 0.1  # 每 0.1 秒检查一次
                waited = 0

                while "Bob" not in clients:
                    print("[Server] Waiting for Bob to connect...")
                    time.sleep(interval)
                    waited += interval
                    if waited >= max_wait_time:
                        print("[Server] Timeout: Bob not connected.")
                        break
                # 发送 "A to B" 通知给 Bob
                if "Bob" in clients:
                    response_to_bob = {"type": "A_to_B", "message": "A to B"}
                    send_msg(clients["Bob"], response_to_bob)
                    print("[Server-Bob] Sent 'A to B' to Bob.")
                else:
                    print("[Server] Bob not connected yet.")


                # 检查 Bob 是否已经发送 alpha_B0
                if "alpha_B0" in session_data["Bob"]:
                    session_data["init_done"] = True
                    print("[Server] Both Init steps done, ready for messaging.")


                continue

                # Bob 发送 alpha_B0
            elif msg_type == "send_alpha_B0":
                alpha_B0 = int(msg["alpha_B0"], 16)
                session_data["Bob"]["alpha_B0"] = alpha_B0
                gamma_S.alpha_last = alpha_B0

                print(f"[Server-Bob] Server received <alpha_B0> from Bob: {alpha_B0 % 1000000}")
                print("[Server] gamma_S :", gamma_S)
                # print(f"[Server-Bob] Server received <alpha_B0> from Bob")
                # print("session_data:", session_data)

                if "alpha_A0" in session_data["Alice"]:
                    session_data["init_done"] = True
                    print("[Server] Both Init steps done, ready for messaging.")

                if session_data["init_done"]:
                    send_msg(clients["Alice"], {"type": "ready", "msg": "Both sides Init done."})
                    send_msg(clients["Bob"], {"type": "ready", "msg": "Both sides Init done."})
                else:
                    send_msg(clients["Alice"], {"type": "info", "msg": "Waiting for Alice to send alpha_A0."})

                continue

            elif msg_type == "send_message1":
                if not session_data["init_done"]:
                    print("[Server] Secure Messaging request ignored (Init not done yet).")
                    continue

                print("---------------------------------------------------------------------------------")
                print("|                        PCKA For Secure Messaging                              |")
                print("---------------------------------------------------------------------------------")
                # print()
                print("***********************From A to B ***********************")
                # Server: Ser
                # 接收 Alice 发送的 c_10 和 alpha_A1
                print(f"[Server-Alice] Received <c_10, alpha_A1> from Alice")
                c_10, alpha_A1_hex = msg["c_10"], msg["alpha_A1"]
                alpha_A1 = int(alpha_A1_hex, 16)
                beta_B0, gamma_S = Ser(gamma_S, alpha_A1)
                print("[S] PCKA.Ser: computed beta_B and updated alpha_last")

                #发送 c_10，beta_B0给 Bob
                response = {"type": "send_c_beta_B", "c_10": c_10, "beta_B0": hex(beta_B0)[2:]}
                send_msg(clients["Bob"], response)
                print(f"[Server-Bob] Sent <c_10, beta_B0> to Bob")

                gamma_S = KRt(gamma_S)
                print("[S] PCKA.KRt: Server rotated new sk (short):", gamma_S.sk % 1000000)
                # response = {"type": "key_refresh_ack", "msg": "Server key refreshed."}
                # send_msg(conn, response)
                continue
            elif msg_type == "send_message2":
                print()
                print("***********************From B to A ***********************")
                # Server: Ser
                c_11, alpha_B1_hex = msg["c_11"], msg["alpha_B1"]
                alpha_B1 = int(alpha_B1_hex, 16)
                beta_A1, gamma_S = Ser(gamma_S, alpha_B1)
                print("[S] PCKA.Ser: computed beta_A,1 and updated alpha_last")

                #发送 c_11，beta_A1给 Alice
                response = {"type": "send_c_beta_A", "c_11": c_11, "beta_A1": hex(beta_A1)[2:]}
                send_msg(clients["Alice"], response)
                print(f"[Server-Alice] Sent <c_11, beta_A1> to Alice")
                continue


            else:
                print(f"[Server] Unknown message type from {identity}: {msg_type}")

        # print(f"clints: {clients}")

    except Exception as e:
        print(f"[!] Error in handling {addr}: {e}")

    finally:
        conn.close()
        if identity in clients:
            del clients[identity]
        print(f"[-] Connection with {identity} closed.")


def start_server(host, port):
    # Initialize server state
    print("---------------------------------------------------------------------------------")
    print("|                                 Init                                          |")
    print("---------------------------------------------------------------------------------")
    gamma_S = Init()
    # print(f"Server state gamma_S initialized: {gamma_S}")  #检查Sk0,alpha_B0****************************************

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  #IPv4,TCP
    server_socket.bind((host, port))  #绑定监听端口
    server_socket.listen(5)  #最大设备连接数
    print(f"Server listening on {host}:{port}")

    #循环等待客户端连接
    while True:
        conn, addr = server_socket.accept() #等待连接
        print(f"Connection from {addr}")
        threading.Thread(target=handle_client, args=(conn, addr, gamma_S)).start()


if __name__ == "__main__":
    start_server("0.0.0.0", 9000)
