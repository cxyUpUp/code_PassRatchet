"""
pcka_config.py
==============
PCKA Protocol Public Configuration - Alice / Bob / Server - Unified import for all three parties. 
★ Switching the security level only requires modifying the "CURVE_NAME" line ★
Just keep the three parts consistent, and there is no need to make any changes to the other code.

"""

import socket
import time
import json
import secrets
import hashlib
from dataclasses import dataclass
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes

from ecdsa import curves
from ecdsa.ellipticcurve import Point, INFINITY


# ======================================================================
# ★ Modify here to switch security level (the three settings must be consistent) ★
# ======================================================================
CURVE_NAME = "NIST256p"
# CURVE_NAME = "NIST384p"
# CURVE_NAME = "NIST521p"
# ======================================================================


# ---------- Curve → Recommended Hash Mapping ----------
_CURVE_HASH = {
    "NIST256p":        (hashlib.sha256, hashes.SHA256()),
    "NIST384p":        (hashlib.sha384, hashes.SHA384()),
    "NIST521p":        (hashlib.sha512, hashes.SHA512()),
    "SECP256k1":       (hashlib.sha256, hashes.SHA256())
}

# ---------- Curve → Security Level (bit) ----------
_CURVE_SECURITY = {
    "NIST256p":        128,
    "NIST384p":        192,
    "NIST521p":        256,
    "SECP256k1":       128
}


# ==================== Automatically derived curve parameters ====================

curve = getattr(curves, CURVE_NAME)
order = curve.order
generator = curve.generator

_H_lib, _H_crypto = _CURVE_HASH[CURVE_NAME]
security_bits = _CURVE_SECURITY[CURVE_NAME]

COORD_BYTE_LEN = (order.bit_length() + 7) // 8   
KDF_BYTE_LEN   = COORD_BYTE_LEN * 2               

print(f"[pcka_config] {CURVE_NAME}  |  {security_bits}-bit security  |  "
      f"order {order.bit_length()}-bit  |  hash {_H_lib().name.upper()}  |  "
      f"point {COORD_BYTE_LEN * 2} bytes")


# ==================== Data Structure====================
#
@dataclass
class PartyState:
    r: int
    k: object  # ECC point


# ==================== ECC Point Tool====================

def to_affine(P):
    """Convert PointJacobi to affine Point if needed"""
    if hasattr(P, "to_affine"):
        return P.to_affine()
    return P


def point_to_bytes(P: Point) -> bytes:
    """Point -> COORD_BYTE_LEN*2 bytes (x||y)"""
    if hasattr(P, "to_affine"):
        P = P.to_affine()
    return P.x().to_bytes(COORD_BYTE_LEN, 'big') + P.y().to_bytes(COORD_BYTE_LEN, 'big')


def bytes_to_point(b: bytes) -> Point:
    """bytes -> Point on curve"""
    x = int.from_bytes(b[:COORD_BYTE_LEN], 'big')
    y = int.from_bytes(b[COORD_BYTE_LEN:], 'big')
    return Point(curve.curve, x, y)


def int_from_point(point):
    if hasattr(point, "to_affine"):
        point = point.to_affine()
    if point == INFINITY:
        return 0
    return point.x() + point.y()


# ==================== Hash / KDF ====================

def kdf_bytes(*parts: bytes) -> bytes:
    h = _H_lib()
    for b in parts:
        h.update(b)
    return h.digest()


def H_to_point(pw: bytes):
    """Hash-to-curve (simplified)"""
    digest = hashes.Hash(_H_crypto)
    digest.update(pw)
    h_int = int.from_bytes(digest.finalize(), 'big') % order
    return h_int, generator


def H_to_int(*parts: bytes) -> int:
    """Hash H: {0,1}* -> Z_order"""
    h = _H_lib()
    for b in parts:
        h.update(b)
    return int(int.from_bytes(h.digest(), 'big') % order)


def H_int(*parts: bytes, mod: int) -> int:
    """Hash -> int mod arbitrary modulus"""
    return int(int.from_bytes(kdf_bytes(*parts), 'big') % mod)


def H_bytes(*parts: bytes) -> bytes:
    h = _H_lib()
    for p in parts:
        h.update(p)
    return h.digest()


def int_to_bytes(i: int) -> bytes:
    return i.to_bytes((i.bit_length() + 7) // 8 or 1, 'big')


# ==================== Symmetric Encryption====================

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


def aesgcm_encrypt(key_bytes: bytes, plaintext: bytes) -> bytes:
    key = hashlib.sha256(key_bytes).digest()
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    return nonce + aes.encrypt(nonce, plaintext, None)


def aesgcm_decrypt(key_bytes: bytes, blob: bytes) -> bytes:
    key = hashlib.sha256(key_bytes).digest()
    aes = AESGCM(key)
    nonce, ct = blob[:12], blob[12:]
    return aes.decrypt(nonce, ct, None)


# ==================== OPRF ====================

def Init(pw: bytes, sid: bytes):
    r0 = secrets.randbelow(order - 1) + 1
    digest = _H_lib(sid + pw).digest()
    base_int = int.from_bytes(digest, 'big') % order
    alpha = base_int * generator
    alpha = r0 * alpha  # 盲化
    return alpha, r0


def unblind(beta, r0):
    inv_r = pow(r0, -1, order)

    return inv_r * beta

def Snd(gamma_: PartyState, m: bytes) -> Tuple[bytes, object, PartyState]:
    """发送消息"""
    r_ = gamma_.r
    key_bytes = kdf_bytes(int_from_point(gamma_.k).to_bytes(KDF_BYTE_LEN, 'big'))
    c = SE_enc(key_bytes, m)

    r_prime = secrets.randbelow(order - 1) + 1
    hk_scalar = int_from_point(gamma_.k) % order
    alpha_ = r_prime * gamma_.k
    new_gamma = PartyState(r=r_prime, k=gamma_.k)
    return c, alpha_, new_gamma

def Rcv(gamma_: PartyState, c: bytes, beta_) -> Tuple[Optional[bytes], PartyState]:
    inv_r = pow(gamma_.r, -1, order)
    k_prime = inv_r * beta_

    key_from_kprime = kdf_bytes(int_from_point(k_prime).to_bytes(KDF_BYTE_LEN, 'big'))
    key_from_k = kdf_bytes(int_from_point(gamma_.k).to_bytes(KDF_BYTE_LEN, 'big'))

    m1 = SE_dec(key_from_kprime, c)
    m2 = SE_dec(key_from_k, c)
    success1 = (m1 is not None)
    success2 = (m2 is not None)
    if success1 and not success2:
        new_state = PartyState(r=0, k=k_prime)
        return m1, new_state
    elif success2 and not success1:
        new_state = PartyState(r=0, k=gamma_.k)
        return m2, new_state
    else:
        return None, gamma_


# ==================== Network tools ====================

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


def send_msg(conn, msg):
    message_str = json.dumps(msg) + "\n"
    conn.sendall(message_str.encode())


# ==================== Auxiliary====================

def rand_scalar():
    return secrets.randbelow(order - 1) + 1


def rand_coprime(mod):
    from math import gcd
    while True:
        x = secrets.randbelow(mod - 2) + 1
        if gcd(x, mod) == 1:
            return x


def map_pw_to_point(pw: str):
    h = int(int.from_bytes(H_bytes(pw.encode()), 'big') % order)
    if h == 0:
        h = 1
    return h
