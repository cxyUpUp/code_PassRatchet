"""
ShareKey_Bob — ECC (ecdsa) 版本
================================
将原先基于模幂运算 (Z_p*) 的 ShareKey Bob 端协议
迁移到 NIST P-256 椭圆曲线 (ecdsa 库)。

运算映射:
  原: pow(g, x, p)         → 现: x * generator  (标量乘基点)
  原: pow(a, sk, p)        → 现: sk * a_point    (标量乘任意点)
  原: (a * b) % p          → 现: a_point + b_point (点加)
  原: pow(a, -1, ORDER)    → 现: pow(a, -1, order) (标量模逆)
  原: int 值作为密钥       → 现: ECC 点序列化后作为密钥

依赖: ecdsa, cryptography
"""

import socket
import json
import hashlib
import secrets
import time
import math
import pandas as pd
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ecdsa import curves
from ecdsa.ellipticcurve import Point, INFINITY
from CONFIG import *

# -----------------------
# ECC Setup
# -----------------------
# curve = curves.NIST256p
# order = curve.order
# generator = curve.generator
# H_func = hashlib.sha256  # NIST256p 对应 128-bit 安全级别, 用 SHA256


# -----------------------
# ECC Point helpers
# -----------------------

# def point_to_bytes(P) -> bytes:
#     """Point -> 64 bytes (x||y), big-endian"""
#     if hasattr(P, "to_affine"):
#         P = P.to_affine()
#     return P.x().to_bytes(32, 'big') + P.y().to_bytes(32, 'big')
#
#
# def bytes_to_point(b: bytes) -> Point:
#     """64 bytes -> Point on curve"""
#     x = int.from_bytes(b[:32], 'big')
#     y = int.from_bytes(b[32:], 'big')
#     return Point(curve.curve, x, y)
#
#
# # -----------------------
# # Hash / KDF helpers
# # -----------------------
#
# def kdf_bytes(*parts: bytes) -> bytes:
#     """Simple key derivation -> 32 bytes."""
#     h = H_func()
#     for b in parts:
#         h.update(b)
#     return h.digest()
#
#
# def H_bytes(*parts: bytes) -> bytes:
#     h = H_func()
#     for p in parts:
#         h.update(p)
#     return h.digest()
#
#
# def H_int(*parts: bytes, mod: int) -> int:
#     return int(int.from_bytes(H_bytes(*parts), 'big') % mod)
#
#
# def H_to_int(*parts: bytes) -> int:
#     """Hash H: {0,1}* -> Z_order (as integer mod curve order)."""
#     h = H_func()
#     for b in parts:
#         h.update(b)
#     return int(int.from_bytes(h.digest(), 'big') % order)
#
#
# def int_to_bytes(i: int) -> bytes:
#     return i.to_bytes((i.bit_length() + 7) // 8 or 1, 'big')


# -----------------------
# Symmetric encryption
# -----------------------

# def SE_enc(key_bytes: bytes, plaintext: bytes) -> bytes:
#     aes = AESGCM(hashlib.sha256(key_bytes).digest())  # 32-byte key
#     nonce = secrets.token_bytes(12)
#     ct = aes.encrypt(nonce, plaintext, None)
#     return nonce + ct
#
#
# def SE_dec(key_bytes: bytes, blob: bytes):
#     try:
#         aes = AESGCM(hashlib.sha256(key_bytes).digest())
#         nonce, ct = blob[:12], blob[12:]
#         pt = aes.decrypt(nonce, ct, None)
#         return pt
#     except Exception:
#         return None


# -----------------------
# Network helpers
# -----------------------

def connect_to_server(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock


def send_message(sock, msg):
    message_str = json.dumps(msg) + "\n"
    sock.sendall(message_str.encode())


def receive_message(sock):
    data = sock.recv(4096).decode()
    if not data:
        return None
    return json.loads(data)


# -----------------------
# Utility
# -----------------------

def rand_scalar():
    """生成 [1, order-1] 范围内的随机标量 (ECC order 是素数, 必然互素)"""
    return secrets.randbelow(order - 1) + 1


def map_pw_to_point(pw: str):
    """将密码映射到标量 mod order"""
    h = int(int.from_bytes(H_bytes(pw.encode()), 'big') % order)
    if h == 0:
        h = 1
    return h


# -----------------------
# Data structures (留作参考)
# -----------------------

@dataclass
class BulletinBoard:
    env_a: object = None  # ECC point
    env_b: object = None  # ECC point


@dataclass
class Server:
    sk: int
    store_a: tuple = None
    store_b: tuple = None

    def reg_response(self, a_point):
        """原: pow(a_val, sk, p)  →  现: sk * a_point"""
        return self.sk * a_point

    def store_commit(self, who: str, y_point, cm: int):
        if who == 'A':
            self.store_a = (y_point, cm)
        else:
            self.store_b = (y_point, cm)


# -----------------------
# Bob class
# -----------------------

class Bob:
    def __init__(self, pw: str):
        self.id_str = 'B'
        self.pw = pw
        self.key = None
        self.x = None
        self.y = None       # ECC point
        self.cm = None       # int (scalar)
        self.rwd2 = None     # int (scalar)
        self.r_c = None

    # ---- 注册阶段 (class method, 留作参考) ----
    def register(self):
        while True:
            self.r = secrets.randbelow(order - 2) + 1
            if math.gcd(self.r, order) == 1:
                break
        h_pw = map_pw_to_point(self.pw)
        base_point = h_pw * generator
        a = self.r * base_point

        b = self.server.reg_response(a)  # ECC point

        r_inv = pow(self.r, -1, order)
        t_k = r_inv * b  # ECC point

        self.rwd = H_int(self.id_str.encode(), point_to_bytes(t_k),
                         self.pw.encode(), mod=order)
        self.env = self.rwd * generator  # ECC point
        self.board.env_b = self.env

        print("[Bob] Registration complete, env_b posted.")
        return self.env

    # ---- 认证阶段 (class method, 留作参考) ----
    def start_auth(self):
        pw_try = input("[Bob] 再次输入密码以认证: ")
        while True:
            self.r2 = secrets.randbelow(order - 2) + 1
            if math.gcd(self.r2, order) == 1:
                break
        h_pw = H_to_int(pw_try.encode())
        base_point = h_pw * generator
        a2 = self.r2 * base_point

        b2 = self.server.reg_response(a2)

        r_inv = pow(self.r2, -1, order)
        t_k2 = r_inv * b2

        self.rwd2 = H_int(self.id_str.encode(), point_to_bytes(t_k2),
                          pw_try.encode(), mod=order)
        print("[Bob] Authentication a' sent to server.")

    # ---- 提交阶段 ----
    def commit_phase(self):
        """原: y = pow(g, x, p)  →  现: y = x * G"""
        self.x = secrets.randbelow(order - 2) + 1
        self.y = self.x * generator  # ECC point
        return self.y

    # ---- 派生共享密钥 ----
    def compute_sharekey(self, env_a_point, y_a_point) -> bytes:
        """
        认证阶段新协议:
          k_B = H(env_A^{rwd'_B}, y_A^{x_B})
        ECC: env_A^{rwd'_B} -> rwd'_B * env_A ; y_A^{x_B} -> x_B * y_A
        """
        term1 = self.rwd2 * env_a_point
        term2 = self.x * y_a_point
        print("[Bob] rwd'_B * env_A =", point_to_bytes(term1).hex()[:32], "...")
        print("[Bob] x_B * y_A =", point_to_bytes(term2).hex()[:32], "...")

        self.sharekey = H_bytes(point_to_bytes(term1), point_to_bytes(term2))
        print("[Bob] ShareKey derived.")
        return self.sharekey


# -----------------------
# Main entry
# -----------------------

def main():

    from PCKA_4_SM.Bob import run
    sock = connect_to_server("127.0.0.1", 8000)
    print("Bob connected to server.")

    identity_msg = {"type": "identity", "name": "Bob"}
    send_message(sock, identity_msg)
    print("Bob sent identity.")

    response = receive_message(sock)
    if response:
        print(f"Alice received: {response}")

    for _ in range(100):

        print("---------------------------------------------------------------------------------")
        print("|                                 Register                                      |")
        print("---------------------------------------------------------------------------------")

        # password = input("请输入 Bob 的口令: ")
        password = "bob_password"  # 固定密码，便于测试

        bob = Bob(password)

        time1 = time.perf_counter()

        # ======== 注册阶段 (内联实现) ========
        r1 = rand_scalar()
        h_pw = H_to_int(password.encode())                  # 标量 mod order
        base_point = h_pw * generator                        # h_pw * G → ECC 点
        a_point = r1 * base_point                            # r1 * h_pw * G → 盲化的 ECC 点

        # 发送 alpha (ECC 点序列化为 hex)
        msg = {"type": "register", "name": "B", "a": point_to_bytes(a_point).hex()}
        send_message(sock, msg)
        print("[Bob] Sent <a> to server. ")

        # 接收 beta (ECC 点)
        response = receive_message(sock)
        print(f"[Bob] Received <b> from server. {response}")
        b_point = bytes_to_point(bytes.fromhex(response['b']))
        print(f"[Bob] Received <b> from server: {point_to_bytes(b_point).hex()[:32]}...")

        # 去盲化: t_k = r1^{-1} * b = sk * h_pw * G
        r1_inv = pow(r1, -1, order)
        t_k = r1_inv * b_point  # ECC point

        # rwd_b = H(id || point_to_bytes(t_k) || pw) mod order
        rwd_b = H_int(bob.id_str.encode(), point_to_bytes(t_k), password.encode(), mod=order)

        # env_b = rwd_b * G  (ECC 点)
        env_b = rwd_b * generator

        msg = {"type": "post_env", "name": "B", "env": point_to_bytes(env_b).hex()}
        send_message(sock, msg)
        print("[Bob] Sent <env_b> to server. ")

        time2 = time.perf_counter()

        response = receive_message(sock)
        print(f"[Bob] Received ack from server.{response}")
        print("[Bob] Registration completed.")


        print("---------------------------------------------------------------------------------")
        print("|                                 Authentication                                |")
        print("---------------------------------------------------------------------------------")

        # ======== 认证阶段 ========
        # password1 = input("再次输入 Bob 的口令: ")
        password1 = "bob_password"  # 固定密码，便于测试

        time3 = time.perf_counter()
        r2 = rand_scalar()
        h_pw_try = H_to_int(password1.encode())              # 标量
        base_point2 = h_pw_try * generator                    # H(pw') * G
        a2_point = r2 * base_point2                           # a'_B
        bob.x = secrets.randbelow(order - 2) + 1
        y_b_point = bob.x * generator
        bob.y = y_b_point

        msg = {
            "type": "auth_start",
            "name": "B",
            "a2": point_to_bytes(a2_point).hex(),
            "y": point_to_bytes(y_b_point).hex(),
        }
        send_message(sock, msg)
        print("[Bob] Sent <a2, y_b> to server. ")
        time3_ = time.perf_counter()

        response = receive_message(sock)
        time4 = time.perf_counter()
        b2_point = bytes_to_point(bytes.fromhex(response['b2']))
        cm_b = int(response['cm'], 16)
        env_a_hex = response['env']
        y_a_hex = response['y']
        print(f"[Bob] Received <b2, cm_b, env_a, y_a> from server.{response}")

        # 去盲化
        r2_inv = pow(r2, -1, order)
        t_k2 = r2_inv * b2_point  # ECC point

        rwd2 = H_int(bob.id_str.encode(), point_to_bytes(t_k2), password1.encode(), mod=order)
        bob.rwd2 = rwd2
        bob.cm = cm_b

        env_a_point = bytes_to_point(bytes.fromhex(env_a_hex))
        y_a_point = bytes_to_point(bytes.fromhex(y_a_hex))

        sharekey_b = bob.compute_sharekey(env_a_point, y_a_point)
        print(f"[Bob] Computed sharekey: {sharekey_b.hex()}")

        s_b = (rwd2 + cm_b * bob.x) % order
        msg = {"type": "auth_proof", "name": "B", "s": hex(s_b)}
        send_message(sock, msg)
        print("[Bob] Sent <s_b> to server.")

        time4_ = time.perf_counter()
        time_Init = (time2 - time1) * 1000
        time_Auth = (time4_ - time4 + time3_ - time3) * 1000

        # 进入 PCKA 安全通信阶段
        # run(sharekey_b, sock)

        print(f"[Time-ShareKey_Negotiation]  time for Bob:  {(time_Init + time_Auth):.4f} ms")


if __name__ == "__main__":
    main()
