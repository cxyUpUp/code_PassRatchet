# Bob_ECC.py
import socket
import json
import secrets
import hashlib
from dataclasses import dataclass
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pandas as pd
import time
from cryptography.hazmat.primitives.asymmetric import ec
from ecdsa import curves
from ecdsa.ellipticcurve import Point
from ecdsa.ellipticcurve import INFINITY

from CONFIG import *

# -----------------------
# ECC parameters
# -----------------------
# curve = curves.NIST256p#
# order = curve.order
# generator = curve.generator

# print(f"Using curve: NIST256p, order: {order}")
# print(f"Generator point: ({generator.x()}, {generator.y()})")


# def int_from_point(point):
#     """将 ECC 点转整数用于 KDF"""
#     if hasattr(point, "to_affine"):  # PointJacobi → Point
#         point = point.to_affine()
#     if point == INFINITY:
#         return 0
#     return point.x() + point.y()
#
# def kdf_bytes(*parts: bytes) -> bytes:
#     h = hashlib.sha256()
#     for b in parts:
#         h.update(b)
#     return h.digest()
#
# def to_affine(P):
#     """Convert PointJacobi to affine Point if needed"""
#     if hasattr(P, "to_affine"):
#         return P.to_affine()
#     return P
#
#
# def point_to_bytes(P: Point) -> bytes:
#     if hasattr(P, "to_affine"):  # 如果是 PointJacobi
#         P = P.to_affine()
#     return P.x().to_bytes(32, 'big') + P.y().to_bytes(32, 'big')
#
#
# def bytes_to_point(b: bytes) -> Point:
#      """64 bytes -> Point"""
#      x = int.from_bytes(b[:32], 'big')
#      y = int.from_bytes(b[32:], 'big')
#      return Point(curve.curve, x, y)
#
#
# def SE_enc(key_bytes: bytes, plaintext: bytes) -> bytes:
#     aes = AESGCM(hashlib.sha256(key_bytes).digest())
#     nonce = secrets.token_bytes(12)
#     ct = aes.encrypt(nonce, plaintext, None)
#     return nonce + ct
#
# def SE_dec(key_bytes: bytes, blob: bytes) -> Optional[bytes]:
#     try:
#         aes = AESGCM(hashlib.sha256(key_bytes).digest())
#         nonce, ct = blob[:12], blob[12:]
#         return aes.decrypt(nonce, ct, None)
#     except:
#         return None

# -----------------------
# Socket helpers
# -----------------------
# def connect_to_server(host, port):
#     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     sock.connect((host, port))
#     return sock
#
# def send_message(sock, msg):
#     sock.sendall((json.dumps(msg) + "\n").encode())
#
# def receive_message(sock):
#     data = sock.recv(4096).decode()
#     return json.loads(data)

# -----------------------
# Party state
# -----------------------
# @dataclass
# class PartyState:
#     r: int
#     k: object  # ECC 点

# -----------------------
# Helpers
# -----------------------
# def rand_coprime(mod):
#     while True:
#         x = secrets.randbelow(mod - 2) + 1
#         if x > 1:  # ECC 无需 gcd
#             return x
#
# def Init(pwB: bytes, sid: bytes):
#     rB0 = secrets.randbelow(order - 1) + 1
#     # base = H(sid||pwB) * G
#     digest = hashlib.sha256(sid + pwB).digest()
#     base_int = int.from_bytes(digest, 'big') % order
#     alpha_B0 = base_int * generator
#     alpha_B0 = rB0 * alpha_B0  # manghua
#     return alpha_B0, rB0
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

# def Rcv(gamma_: PartyState, c: bytes, beta_):
#     r_, k_ = gamma_.r, gamma_.k
#     # print("k_ debug:", k_)
#     # print("DDDDDDDDDDDDDDebug, kB", type(k_))
#     # 去盲化: k' = beta_^ (1/r)
#     # 对 ECC 简化为 beta_ * r^-1 mod order
#     inv_r = pow(r_, -1, order)
#     k_prime = inv_r * beta_  # ECC 点缩放
#     # print("k_prime debug:", k_prime)
#
#     key_bytes_kprime = kdf_bytes(int_from_point(k_prime).to_bytes(64, 'big'))
#     key_bytes_k = kdf_bytes(int_from_point(k_).to_bytes(64, 'big'))
#
#     m1 = SE_dec(key_bytes_kprime, c)
#     m2 = SE_dec(key_bytes_k, c)
#
#     success1 = (m1 is not None)
#     success2 = (m2 is not None)
#     if success1 and not success2:
#         new_state = PartyState(r=0, k=k_prime)
#         return m1, new_state
#     elif success2 and not success1:
#         new_state = PartyState(r=0, k=k_)
#         return m2, new_state
#     else:
#         return None, gamma_
#
#     # if m is not None:
#     #     new_state = PartyState(r=0, k=k_prime)
#     #     return m, new_state
#     # else:
#     #     return None, gamma_

def get_pw(length):
    with open('passwords.txt', 'r', encoding='utf-8') as f:
        for line in f:
            if f"{length}:" in line or f"LENGTH_{length}:" in line:
                return line.split(':', 1)[1].strip()
    return None

# -----------------------
# Run
# -----------------------
def run(pwB: bytes, sock):

    print("---------------------------------------------------------------------------------")
    print("|                                 Init                                          |")
    print("---------------------------------------------------------------------------------")

    # 接收 sid
    sid_msg = receive_message(sock)
    print(f"Bob received sid message: {sid_msg}")
    sid = bytes.fromhex(sid_msg["sid"])
    print(f"Bob received sid: {sid.hex()}")

    send_message(sock, {"type": "ack_sid"})
    print("Bob sent ack_sid")

    alpha_B0, rB0 = Init(pwB, sid)

    # 等待 "A to B" 通知
    response = receive_message(sock)
    print(f"Bob received message: {response}")

    send_message(sock, {"type": "send_alpha_B0", "alpha_B0": point_to_bytes(alpha_B0).hex()})

    gamma_B = PartyState(r=rB0, k=0 * generator)
    print("Bob sent <alpha_B0> to server.")
    print("Bob's gamma_B:", gamma_B)

    # 等待 ready
    while True:
        ready = receive_message(sock)
        if ready.get("type") == "ready":
            print("[A] Secure Messaging started.")
            break

    communication_times = []

    def random_message(L_min=8, L_max=64) -> bytes:
        L = secrets.randbelow(L_max - L_min + 1) + L_min
        return secrets.token_bytes(L)

    for i in range(10):
        print("---------------------------------------------------------------------------------")
        print("|                         PCKA For Secure Messaging                             |")
        print("---------------------------------------------------------------------------------")


        print()
        print("*********************From A to B *********************")

        # B: Rcv
        t1 = time.perf_counter()
        response = receive_message(sock)

        c_10= bytes.fromhex(response["c_10"])
        # print(f"[DDDebug] B received c_1,0:", c_10.hex())

        beta_B0_bytes = bytes.fromhex(response['beta_B0'])
        beta_B0 = bytes_to_point(beta_B0_bytes)

        m_10out, gamma_B = Rcv(gamma_B, c_10, beta_B0)

        t2 = time.perf_counter()
        if m_10out is None:
            print("[B] PCKA.Rcv: failed to decrypt (output ⊥).")
        else:
            print("[B] PCKA.Rcv: decrypted message:", m_10out.hex())

        print("*********************From B to A *********************")

        m_11 = random_message()
        print(f"[B] B select m_1,1 ({len(m_11)} bytes):", m_11.hex())

        # B: Snd
        t3 = time.perf_counter()
        c_11, alpha_B1, gamma_B = Snd(gamma_B, m_11)
        # print("DDDDebug", alpha_B1)
        send_message(sock, {"type": "send_message2", "c_11": c_11.hex(), "alpha_B1": point_to_bytes(alpha_B1).hex()})
        t4 = time.perf_counter()
        print("[B] PCKA.Snd: sent c_1,1 and alpha_B,1")

        print(f"[Time] From A to B: {(t2 - t1) * 1000} ms")
        print(f"[Time] From B to A: {(t4 - t3) * 1000} ms")
        communication_times.append((t2 - t1 + t4 - t3) * 1000)

    df = pd.DataFrame(communication_times, columns=["Messaging Time (ms)"])
    print("\n--- PCKA Messaging Time Summary ---")
    print(df)

# -----------------------
# Main
# -----------------------
if __name__ == "__main__":
    sock = connect_to_server("127.0.0.1", 9000)
    print("Bob connected to server.")
    send_message(sock, {"type": "identity", "name": "Bob"})
    response = receive_message(sock)
    if response:
        print(f"Bob received: {response}")

    pwB = get_pw(8).encode()

    run(pwB, sock)
