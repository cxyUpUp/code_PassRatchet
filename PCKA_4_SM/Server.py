import socket
import threading
import json
import secrets
import pandas as pd
from dataclasses import dataclass
from typing import Optional
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from ecdsa import curves
from ecdsa.ellipticcurve import Point
from ecdsa.ellipticcurve import INFINITY

from CONFIG import *

# -----------------------
# ECC setup
# -----------------------
# curve = curves.NIST256p
# order = curve.order
# generator = curve.generator # ECC 基点

# def int_from_point(point):
#     """将 ECC 点转整数用于 KDF"""
#     if hasattr(point, "to_affine"):  # PointJacobi → Point
#         point = point.to_affine()
#     if point == INFINITY:
#         return 0
#     return point.x() + point.y()
#
# def kdf_bytes(*parts: bytes) -> bytes:
#     h = hashes.Hash(hashes.SHA256())
#     for b in parts:
#         h.update(b)
#     return h.finalize()
#
# def to_affine(P):
#     """Convert PointJacobi to affine Point if needed"""
#     if hasattr(P, "to_affine"):
#         return P.to_affine()
#     return P
#
# def point_to_bytes(P: Point) -> bytes:
#     """Point -> 64 bytes (x||y)"""
#     if hasattr(P, "to_affine"):  # 如果是 PointJacobi
#         P = P.to_affine()
#     return P.x().to_bytes(32, 'big') + P.y().to_bytes(32, 'big')
#
# def bytes_to_point(b: bytes) -> Point:
#     """64 bytes -> Point"""
#     x = int.from_bytes(b[:32], 'big')
#     y = int.from_bytes(b[32:], 'big')
#     return Point(curve.curve, x, y)


# Symmetric encryption (AES-GCM)
# def SE_enc(key_bytes: bytes, plaintext: bytes) -> bytes:
#     from cryptography.hazmat.primitives.ciphers.aead import AESGCM
#     import hashlib
#     aes = AESGCM(hashlib.sha256(key_bytes).digest())
#     nonce = secrets.token_bytes(12)
#     ct = aes.encrypt(nonce, plaintext, None)
#     return nonce + ct
#
# def SE_dec(key_bytes: bytes, blob: bytes) -> Optional[bytes]:
#     try:
#         import hashlib
#         aes = AESGCM(hashlib.sha256(key_bytes).digest())
#         nonce, ct = blob[:12], blob[12:]
#         return aes.decrypt(nonce, ct, None)
#     except Exception:
#         return None

# -----------------------
# Server State
# -----------------------
@dataclass
class ServerState:
    sk: int
    alpha_last: Optional[object] = None  # ECC 点

clients = {}  # {"Alice": conn, "Bob": conn}
session_data = {"Alice": {}, "Bob": {}, "init_done": False, "pre_beta": 0}

# -----------------------
# ECC Server Operations
# -----------------------
def Init():
    # Server chooses sk
    sk = secrets.randbelow(order - 1) + 1
    return ServerState(sk=sk, alpha_last=None)

def Ser(gamma_S: ServerState, alpha_):
    """Server computes beta = alpha^sk"""
    sk, alpha = gamma_S.sk, gamma_S.alpha_last
    beta = sk * alpha
    gamma_S.alpha_last = alpha_
    return beta, gamma_S

def KRt(gamma_S: ServerState):
    rs = secrets.token_bytes(16)
    new_sk_bytes = kdf_bytes(int(gamma_S.sk).to_bytes(COORD_BYTE_LEN, 'big'), rs)
    new_sk = int.from_bytes(new_sk_bytes, 'big') % order
    if new_sk == 0:
        new_sk = 1
    gamma_S.sk = new_sk
    return gamma_S

# def send_msg(conn, msg):
#     conn.sendall((json.dumps(msg) + "\n").encode())

# -----------------------
# Handle Client
# -----------------------
def handle_client(conn, addr, gamma_S):
    identity = None
    communication_times = []
    communication_times1 = []
    try:
        while True:
            msg_raw = conn.recv(4096).decode().strip()
            if not msg_raw:
                print(f"[!] {addr} disconnected.")
                break
            try:
                msg = json.loads(msg_raw)
            except json.JSONDecodeError:
                print(f"[!] Invalid JSON from {addr}: {msg_raw}")
                continue
            msg_type = msg.get("type")

            # 1. 注册身份
            if msg_type == "identity":
                response = {"type": "ack", "msg": f"Hello {msg['name']}, registered."}
                print(f"[Server] Sending response: Hello {msg['name']}.")
                conn.sendall(json.dumps(response).encode())  # 发送确认消息

                identity = msg.get("name")
                clients[identity] = conn
                # send_msg(conn, {"type": "ack", "msg": f"Hello {identity}, registered."})
                continue

            # 2. session_id
            if msg_type == "session_id":
                sid = bytes.fromhex(msg["sid"])
                current_sid = sid
                print(f"[Server] Received session ID from Alice: {sid.hex()}")

                while "Bob" not in clients:
                    time.sleep(0.1)
                send_msg(clients["Bob"], {"type": "session_id", "sid": sid.hex()})
                continue

            # 3. ack_sid
            if msg_type == "ack_sid":
                print(f"[Server] Received ACK for session ID from Bob.")
                send_msg(clients["Alice"], {"type": "ack_sid"})
                continue

            # 4. 接收 alpha_A0
            if msg_type == "send_alpha_A0":
                alpha_A0_bytes = bytes.fromhex(msg["alpha_A0"])
                alpha_A0 = bytes_to_point(alpha_A0_bytes)
                # alpha_A0 = int(msg["alpha_A0"], 16) * generator  # ECC 点
                session_data["Alice"]["alpha_A0"] = alpha_A0
                print(f"[Server-Alice] Received <alpha_A0> from Alice.")

                beta_A0 = alpha_A0 * gamma_S.sk
                # print("DDDDebug sk0:", gamma_S.sk)

                response_to_alice = {"type": "send_beta_A0", "beta_A0": point_to_bytes(beta_A0).hex()}
                # response_to_alice = {"type": "send_beta_A0", "beta_A0": str(beta_A0)}
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

            # 5. 接收 alpha_B0
            if msg_type == "send_alpha_B0":
                alpha_B0_bytes = bytes.fromhex(msg["alpha_B0"])
                alpha_B0 = bytes_to_point(alpha_B0_bytes)

                # alpha_B0 = int(msg["alpha_B0"], 16) * generator
                session_data["Bob"]["alpha_B0"] = alpha_B0
                gamma_S.alpha_last = alpha_B0
                print(f"[Server-Bob] Server received <alpha_B0> from Bob: {alpha_B0}")
                # print("[Server] gamma_S :", gamma_S)

                if "alpha_A0" in session_data["Alice"]:
                    session_data["init_done"] = True
                    print("[Server] Both Init steps done, ready for messaging.")
                if session_data["init_done"]:
                    send_msg(clients["Alice"], {"type": "ready", "msg": "Both sides Init done."})
                    send_msg(clients["Bob"], {"type": "ready", "msg": "Both sides Init done."})
                else:
                    send_msg(clients["Alice"], {"type": "info", "msg": "Waiting for Alice to send alpha_A0."})

                time0 = time.perf_counter()
                session_data["pre_beta"] = gamma_S.sk * gamma_S.alpha_last
                print(
                    f"[Server] Pre-computed beta_B0 (Time taken: {(time.perf_counter() - time0) * 1000:.4f} ms)")

                continue

            # 6. A -> B 消息
            if msg_type == "send_message1":

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
                ts = time.perf_counter()
                c_10 = msg["c_10"]
                beta_B0 = session_data["pre_beta"]

                # 发送 c_10，beta_B0给 Bob
                send_msg(clients["Bob"],
                         {"type": "send_c_beta_B", "c_10": c_10, "beta_B0": point_to_bytes(beta_B0).hex()})

                ts_end = time.perf_counter()
                print(f"[Server1111] Time Server: {(ts_end - ts) * 1000:.4f} ms")


                print(f"[Server-Bob] Sent <c_10, beta_B0> to Bob")

                t1 = time.perf_counter()
                alpha_A1_bytes = bytes.fromhex(msg["alpha_A1"])
                alpha_A1 = bytes_to_point(alpha_A1_bytes)

                gamma_S.alpha_last = alpha_A1

                t2 = time.perf_counter()

                # beta_B0, gamma_S = Ser(gamma_S, alpha_A1)
                # print("DDDebug sk0':", gamma_S.sk)

                # print("[S] PCKA.Ser: computed beta_B and updated alpha_last")
                # t_RKt_start = time.perf_counter()
                gamma_S = KRt(gamma_S)
                # t_RKt_end = time.perf_counter()
                # communication_times1.append((t_RKt_end - t_RKt_start) * 1000)
                print("[S] PCKA.KRt: Server rotated new sk and updated alpha_last")

                time1 = time.perf_counter()
                session_data["pre_beta"] = gamma_S.sk * gamma_S.alpha_last

                time1_end= time.perf_counter()
                # communication_times.append((time1_end - time1) * 1000 + (t2 - t1) * 1000)

                print(
                    f"[Server] KRt done, new pre_beta (Time taken: {(time1_end - time1) * 1000:.4f} ms)")
                continue

            # 7. B -> A 消息
            if msg_type == "send_message2":
                print()
                print("***********************From B to A ***********************")

                # Server: Ser
                c_11 = msg["c_11"]
                beta_A1 = session_data["pre_beta"]

                # 发送 c_11，beta_A1给 Alice
                response = {"type": "send_c_beta_A", "c_11": c_11, "beta_A1": point_to_bytes(beta_A1).hex()}
                send_msg(clients["Alice"], response)
                # send_msg(clients["Alice"], {"type": "send_c_beta_A", "c_11": c_11, "beta_A1": str(beta_A1)})
                print(f"[Server-Alice] Sent <c_11, beta_A1> to Alice")

                alpha_B1_bytes = bytes.fromhex(msg["alpha_B1"])
                alpha_B1 = bytes_to_point(alpha_B1_bytes)

                gamma_S.alpha_last = alpha_B1

                time2 = time.perf_counter()
                session_data["pre_beta"] = gamma_S.sk * gamma_S.alpha_last
                print(
                    f"[Server] Pre-computed beta_B (Time taken: {(time.perf_counter() - time2) * 1000:.4f} ms)")

                # beta_A1, gamma_S = Ser(gamma_S, alpha_B1)
                # print("[S] PCKA.Ser: computed beta_A,1 and updated alpha_last")

                continue

        # df3 = pd.DataFrame(communication_times, columns=["PCKA.Ser Time (ms)"])
        # print("\n--- PCKA.Ser Time Summary ---")
        # print(df3)
        #
        # df4 = pd.DataFrame(communication_times1, columns=["PCKA.RKt Time (ms)"])
        # print("\n--- PCKA.RKt Time Summary ---")
        # print(df4)

        # df.to_excel(r"D:\pyProiect\code_PassRatchaet\Experiment_result\PCKA_Ser.xlsx", index=False)
        # df1.to_excel(r"D:\pyProiect\code_PassRatchaet\Experiment_result\PCKA_RKt.xlsx", index=False)

        # with pd.ExcelWriter(r"D:\pyProiect\code_PassRatchaet\Experiment_result\PCKA_Ser.xlsx", engine='openpyxl',
        #                     mode='a', if_sheet_exists='replace') as writer:
        #     df3.to_excel(writer, sheet_name='Ser_256', index=False)
        #
        # with pd.ExcelWriter(r"D:\pyProiect\code_PassRatchaet\Experiment_result\PCKA_RKt.xlsx", engine='openpyxl',
        #                     mode='a', if_sheet_exists='replace') as writer:
        #     df4.to_excel(writer, sheet_name='RKt_256', index=False)

    except Exception as e:
        print(f"Error handling client {identity}: {e}")
        # raise e

    finally:
        conn.close()
        if identity in clients:
            del clients[identity]
        print(f"[-] Connection with {identity} closed.")


# -----------------------
# Start Server
# -----------------------
def start_server(host, port):
    print("---------------------------------------------------------------------------------")
    print("|                                 Init                                          |")
    print("---------------------------------------------------------------------------------")

    # print(f"Server state gamma_S initialized: {gamma_S}")  #检查Sk0,alpha_B0****************************************

    gamma_S = Init()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server listening on {host}:{port}")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connection from {addr}")
        threading.Thread(target=handle_client, args=(conn, addr, gamma_S)).start()

if __name__ == "__main__":
    start_server("0.0.0.0", 9000)
