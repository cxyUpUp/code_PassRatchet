import socket
import json
import secrets
import hashlib
from dataclasses import dataclass
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import time
import pandas as pd
from ecdsa import curves
from ecdsa.ellipticcurve import Point
from ecdsa.ellipticcurve import INFINITY

from CONFIG import *

# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.backends import default_backend


# -----------------------
# Group & crypto helpers
# -----------------------

# @dataclass
# class PartyState:
#     r: int
#     k: object  # ECC 点


# Symmetric encryption (SE) using AES-GCM
# def SE_enc(key_bytes: bytes, plaintext: bytes) -> bytes:
#     aes = AESGCM(hashlib.sha256(key_bytes).digest())  # 32-byte key
#     nonce = secrets.token_bytes(12)
#     ct = aes.encrypt(nonce, plaintext, None)
#     return nonce + ct
#
#
# def SE_dec(key_bytes: bytes, blob: bytes) -> Optional[bytes]:
#     try:
#         aes = AESGCM(hashlib.sha256(key_bytes).digest())
#         nonce, ct = blob[:12], blob[12:]
#         pt = aes.decrypt(nonce, ct, None)
#         return pt
#     except Exception:
#         return None
#
#
# def connect_to_server(host, port):
#     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     sock.connect((host, port))
#     return sock
#
#
# def send_message(sock, msg):
#     message_str = json.dumps(msg) + "\n"
#     sock.sendall(message_str.encode())
#
#
# def receive_message(sock):
#     data = sock.recv(4096).decode()
#     if not data:
#         return None
#     return json.loads(data)


# -----------------------
# ECC Setup
# -----------------------

# curve = curves.NIST256p
# order = curve.order
# generator = curve.generator  # ECC 基础点


# print(f"Using curve: NIST256p, order: {order}")
# print(f"Generator point: ({generator.x()}, {generator.y()})")


# def to_affine(P):
#     """Convert PointJacobi to affine Point if needed"""
#     if hasattr(P, "to_affine"):
#         return P.to_affine()
#     return P
#
#
# def point_to_bytes(P: Point) -> bytes:
#     """Point -> 64 bytes (x||y)"""
#     if hasattr(P, "to_affine"):  # 如果是 PointJacobi
#         P = P.to_affine()
#     return P.x().to_bytes(32, 'big') + P.y().to_bytes(32, 'big')
#
#
# def bytes_to_point(b: bytes) -> Point:
#     """64 bytes -> Point"""
#     x = int.from_bytes(b[:32], 'big')
#     y = int.from_bytes(b[32:], 'big')
#     return Point(curve.curve, x, y)
#
#
# def H_to_point(pw: bytes):
#     """Hash-to-curve (simplified)"""
#     digest = hashes.Hash(hashes.SHA256())
#     digest.update(pw)
#     h_int = int.from_bytes(digest.finalize(), 'big') % order
#     return h_int, generator


# def Init(pwA: bytes):
#     """Alice 初始化，生成盲化点 alpha_A0"""
#     rA0 = secrets.randbelow(order - 1) + 1
#     h_scalar, base_point = H_to_point(pwA)
#     alpha_A0 = rA0 * base_point  # ECC 点乘
#     return alpha_A0, rA0

# def Init(pwA: bytes, sid: bytes):
#     rA0 = secrets.randbelow(order - 1) + 1
#     digest = hashlib.sha256(sid + pwA).digest()
#     base_int = int.from_bytes(digest, 'big') % order
#     alpha_A0 = base_int * generator
#     alpha_A0 = rA0 * alpha_A0  # manghua
#     # print(type(alpha_A0))
#     return alpha_A0, rA0
#
#
# def unblind(beta_A0, rA0):
#     """去盲化 ECC 点"""
#     inv_rA0 = pow(rA0, -1, order)
#     kA0 = inv_rA0 * beta_A0
#     return kA0
#
#
# def int_from_point(point):
#     """将 ECC 点转换为整数用于 KDF"""
#     if hasattr(point, "to_affine"):  # PointJacobi → Point
#         point = point.to_affine()
#     if point == INFINITY:
#         return 0
#     return point.x() + point.y()
#
#
# def kdf_bytes(*parts: bytes) -> bytes:
#     h = hashlib.sha256()
#     for b in parts:
#         h.update(b)
#     return h.digest()
#
#
def Snd(gamma_: PartyState, m: bytes) -> Tuple[bytes, object, PartyState]:
    """发送消息"""
    r_ = gamma_.r
    key_bytes = kdf_bytes(int_from_point(gamma_.k).to_bytes(KDF_BYTE_LEN, 'big'))
    c = SE_enc(key_bytes, m)

    r_prime = secrets.randbelow(order - 1) + 1
    # hk_scalar = int_from_point(gamma_.k) % order
    alpha_ = r_prime * gamma_.k
    new_gamma = PartyState(r=r_prime, k=gamma_.k)
    return c, alpha_, new_gamma
#
#
# def Rcv(gamma_: PartyState, c: bytes, beta_) -> Tuple[Optional[bytes], PartyState]:
#     """接收消息"""
#     inv_r = pow(gamma_.r, -1, order)
#     k_prime = inv_r * beta_
#
#     key_from_kprime = kdf_bytes(int_from_point(k_prime).to_bytes(64, 'big'))
#     key_from_k = kdf_bytes(int_from_point(gamma_.k).to_bytes(64, 'big'))
#
#     m1 = SE_dec(key_from_kprime, c)
#     m2 = SE_dec(key_from_k, c)
#     success1 = (m1 is not None)
#     success2 = (m2 is not None)
#     if success1 and not success2:
#         new_state = PartyState(r=0, k=k_prime)
#         return m1, new_state
#     elif success2 and not success1:
#         new_state = PartyState(r=0, k=gamma_.k)
#         return m2, new_state
#     else:
#         return None, gamma_


def get_pw(length):
    with open('passwords.txt', 'r', encoding='utf-8') as f:
        for line in f:
            if f"{length}:" in line:
                return line.split(':', 1)[1].strip()
    return None


# -----------------------
# Main run()
# -----------------------

def run(pwA: bytes, sock):
    communication_times = []
    communication_times1 = []
    communication_times2 = []

    print("---------------------------------------------------------------------------------")
    print("|                                 Init                                          |")
    print("---------------------------------------------------------------------------------")
    # session id
    sid = secrets.token_bytes(16)
    send_message(sock, {"type": "session_id", "sid": sid.hex()})
    print(f"Alice sent session_id: {sid.hex()}")

    # wait ack
    # while True:
    #     resp = receive_message(sock)
    #     if resp and resp.get("type") == "ack_sid":
    #         print("Alice received ack for session_id.")
    #         break

    response = receive_message(sock)
    print("Alice received ack for session_id.")

    # Init OPRF
    start_time = time.perf_counter()
    alpha_A0, rA0 = Init(pwA, sid)
    end_time = time.perf_counter()

    send_message(sock, {"type": "send_alpha_A0", "alpha_A0": point_to_bytes(alpha_A0).hex()})
    print(f"Alice sent <alpha_A0>: {alpha_A0}")

    # Receive beta_A0 from Server
    response = receive_message(sock)
    print(f"Alice received <beta_A0>: {response['beta_A0']}")

    beta_bytes = bytes.fromhex(response['beta_A0'])
    beta_A0 = bytes_to_point(beta_bytes)
    kA0 = unblind(beta_A0, rA0)

    # beta_A0 = response['beta_A0']  # ECC 点对象
    # kA0 = unblind(beta_A0, rA0)  # equals baseA^sk mod p

    print(f"Init(OPRF) time: {(end_time - start_time)} s")

    gamma_A = PartyState(r=0, k=kA0)
    print("Alice's gamma_A:", gamma_A)

    # Wait ready
    while True:
        ready = receive_message(sock)
        if ready.get("type") == "ready":
            print("[A] Secure Messaging started.")
            break

    # Messaging loop
    for i in range(10):
        # 定义消息空间 M = {0,1}^{8·L}, L ∈ [8, 64], 即消息长度在 8 到 64 字节之间
        def random_message(L_min=8, L_max=64):
            L = secrets.randbelow(L_max - L_min + 1) + L_min
            return secrets.token_bytes(L)

        print("***********************From A to B ***********************")
        m_10 = random_message()
        # print(f"Alice 随机从消息空间 M 中选取消息 m (长度 {len(m_10)} 字节)")
        print(f"[A] A select m_1,0 ({len(m_10)} bytes):", m_10.hex())

        # A: Snd
        t1 = time.perf_counter()
        st = time.perf_counter()
        c_10, alpha_A1, gamma_A = Snd(gamma_A, m_10)
        st_end = time.perf_counter()
        communication_times1.append((st_end - st)*1000)


        # print("DDDebug c1,0", c_10.hex())

        send_message(sock, {"type": "send_message1", "c_10": c_10.hex(), "alpha_A1": point_to_bytes(alpha_A1).hex()})
        t2 = time.perf_counter()

        # send_message(sock, {"type": "send_message1", "c_10": c_10.hex(), "alpha_A1": str(alpha_A1)})
        print("[A] PCKA.Snd: sent c and alpha_A")

        print()
        print("*********************From B to A *********************")

        # A: Rcv
        t3 = time.perf_counter()

        resp = receive_message(sock)
        # print(f"[A] received response: {resp}")
        c_11 = bytes.fromhex(resp['c_11'])

        beta_bytes = bytes.fromhex(resp['beta_A1'])
        beta_A1 = bytes_to_point(beta_bytes)

        rt = time.perf_counter()
        m_11out, gamma_A = Rcv(gamma_A, c_11, beta_A1)
        rt_end = time.perf_counter()
        communication_times2.append((rt_end - rt)*1000)

        t4 = time.perf_counter()

        if m_11out is None:
            print("Failed to decrypt (output ⊥).")
        else:
            print(f"Decrypted message: {m_11out.hex()}")

        print(f"[Time] From A to B: {(t2 - t1) * 1000} ms")
        print(f"[Time] From B to A: {(t4 - t3) * 1000} ms")
        communication_times.append((t2 - t1 + t4 - t3) * 1000)

    df = pd.DataFrame(communication_times, columns=["Messaging Time (ms)"])
    print("\n--- PCKA Messaging Time Summary ---")
    print(df)

    df1 = pd.DataFrame(communication_times1, columns=["Snd Time (ms)"])
    print("\n--- PCKA Snd Time Summary ---")
    print(df1)

    df2 = pd.DataFrame(communication_times2, columns=["Rcv Time (ms)"])
    print("\n--- PCKA Rcv Time Summary ---")
    print(df2)

    # df.to_excel(r"D:\pyProiect\code_PassRatchaet\Experiment_result\pw_PCKA.xlsx", index=False)
    # df.to_excel(r"D:\pyProiect\code_PassRatchaet\Experiment_result\para_PCKA.xlsx", index=False)

    # df1.to_excel(r"D:\pyProiect\code_PassRatchaet\Experiment_result\PCKA_Snd.xlsx", index=False)
    # df2.to_excel(r"D:\pyProiect\code_PassRatchaet\Experiment_result\PCKA_Rcv.xlsx", index=False)

    # with pd.ExcelWriter(r"D:\pyProiect\code_PassRatchaet\Experiment_result\_pw_PCKA.xlsx",
    #                     engine='openpyxl',
    #                     mode='a') as writer:
    #     df.to_excel(writer, sheet_name='aws-128', index=False)

    # with pd.ExcelWriter(r"D:\pyProiect\code_PassRatchaet\Experiment_result\_para_PCKA.xlsx",
    #                     engine='openpyxl',
    #                     mode='a') as writer:
    #     df.to_excel(writer, sheet_name='aws-256-', index=False)

    # with pd.ExcelWriter(r"D:\pyProiect\code_PassRatchaet\Experiment_result\AWS_PCKA.xlsx", engine='openpyxl',
    #                     mode='a') as writer:
    #     df.to_excel(writer, sheet_name='-1000----', index=False)
    #
    # with pd.ExcelWriter(r"D:\pyProiect\code_PassRatchaet\Experiment_result\client_pcka.xlsx", engine='openpyxl',
    #                     mode='a') as writer:
    #     df2.to_excel(writer, sheet_name='Rcv1000-', index=False)


# -----------------------
# Entry point
# -----------------------

if __name__ == "__main__":
    sock = connect_to_server("127.0.0.1", 9000)
    # sock = connect_to_server("13.208.161.119", 9000)
    print("Alice connected to server.")

    send_message(sock, {"type": "identity", "name": "Alice"})
    print("Alice sent identity.")

    response = receive_message(sock)
    print(f"Alice received: {response}")

    pwA = get_pw(8).encode()
    run(pwA, sock)
