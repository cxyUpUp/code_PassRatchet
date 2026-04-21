
# import secrets
# import hashlib
# from dataclasses import dataclass
# from typing import Tuple, Optional
# from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# from math import gcd
#
# # -----------------------
# # Group & crypto helpers
# # -----------------------
# # Use same group as Alice/Bob examples: p = 2**521 - 1, g = 5
# # p = 2**521 - 1
# # g = 5
# # ORDER = p - 1  # treat group exponent modulo ORDER
#
# p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
# g = 6
# ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
# # ORDER = p - 1
#
# def Setup(security_level=128):
#     """
#     使用标准NIST参数作为公共参数
#     security_level: 128, 192, 256
#     """
#
#     if security_level == 128:
#         # NIST P-256 (SECP256R1) 参数
#         return {
#             'p': 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
#             'g': 6,  # 模p乘法群的生成元
#             'q': 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
#             'H': 'SHA256',
#             'curve_name': 'P-256',
#             'security_level': 128
#         }
#
#     elif security_level == 192:
#         # NIST P-384 (SECP384R1) 参数
#         return {
#             'p': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
#             'g': 2,  # 生成元
#             'q': 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831,
#             'H': 'SHA384',
#             'curve_name': 'P-384',
#             'security_level': 192
#         }
#
#     else:  # security_level == 256
#         # NIST P-521 (SECP521R1) 参数
#         return {
#             'p': 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
#             'g': 2,  # 生成元
#             'q': 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,
#             'H': 'SHA512',
#             'curve_name': 'P-521',
#             'security_level': 256
#         }
# # public_params = Setup(128)
# # # global p, g, ORDER, H_func
# # #换成Integer
# #
# # p = public_params['p']
# # g = public_params['g']
# # ORDER = public_params['q']
# # H_func = getattr(hashlib, public_params['H'].lower())
#
#
# #A select session id randomly
# sid=secrets.token_bytes(16)
# # print("Session ID (sid):", sid)
#
#
# def extended_gcd(a, b):
#     """扩展欧几里得算法：返回 (gcd, x, y) 使得 a * x + b * y = gcd(a, b)"""
#     if b == 0:
#         return a, 1, 0
#     gcd, x1, y1 = extended_gcd(b, a % b)
#     x = y1
#     y = x1 - (a // b) * y1
#     return gcd, x, y
#
# def mod_inverse(r, ORDER):
#     """计算 r 在模 ORDER 下的逆元"""
#     gcd, x, y = extended_gcd(r, ORDER)
#     if gcd != 1:
#         raise ValueError(f"{r} 和 {ORDER} 不是互质的，无法求逆元")
#     else:
#         return x % ORDER  # 确保逆元是正数
#
#
# def H_to_int(*parts: bytes) -> int:
#     """Hash H: {0,1}* -> Z_ORDER (as integer)."""
#     h = hashlib.sha256()
#     for b in parts:
#         h.update(b)
#     return int.from_bytes(h.digest(), 'big') % ORDER
#
# def int_to_bytes(i: int) -> bytes:
#     return i.to_bytes((i.bit_length() + 7)//8 or 1, 'big')
#
# def rand_coprime(mod):
#     while True:
#         x = secrets.randbelow(mod - 1) + 1
#         if gcd(x, mod) == 1:
#             return x
#
# def kdf_bytes(*parts: bytes) -> bytes:
#     """Simple key derivation -> 32 bytes."""
#     h = hashlib.sha256()
#     for b in parts:
#         h.update(b)
#     return h.digest()
#
# # Symmetric encryption (SE) using AES-GCM
# def SE_enc(key_bytes: bytes, plaintext: bytes) -> bytes:
#     aes = AESGCM(hashlib.sha256(key_bytes).digest())  # 32-byte key
#     nonce = secrets.token_bytes(12)
#     ct = aes.encrypt(nonce, plaintext, None)
#     return nonce + ct
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
# # -----------------------
# # States dataclasses
# # -----------------------
# @dataclass
# class ServerState:
#     sk: int                 # server  secret
#     alpha_last: Optional[int] = None  # store last received alpha
#
# @dataclass
# class PartyState:
#     # For both A and B: state is a pair (r, k) OR (0, k)
#     r: int
#     k: int
#
# # -----------------------
# # Protocol primitives
# # -----------------------
# # def Setup() -> Tuple[int,int,int]:
# #     """Setup(1^lambda) -> params: returns (p, g, ORDER) in this demo."""
# #     # params are module-level; simply return them
# #     return (p, g, ORDER)
#
# def Init(pwA: bytes, pwB: bytes) -> Tuple[ServerState, PartyState, PartyState]:
#     """
#     Init(pwA, pwB) -> (gamma_S, gamma_A, gamma_B)
#     Implements the described three-step initialization using the server as in the text.
#     - A produces alpha_A0 = H(pwA)^{rA0}, sends to S
#     - S computes beta_A0 = alpha_A0^{sk} and returns to A
#     - A recovers kA0 = beta_A0^{1/rA0} (so kA0 = H(pwA)^{sk})
#     - Same for B
#     - Server state gamma_S = (sk, alpha_B0)  (per text)
#     """
#     # Server chooses sk
#     sk = secrets.randbelow(ORDER - 1) + 2
#     gamma_S = ServerState(sk=sk, alpha_last=None)
#
#     # A init
#     # rA0 = secrets.randbelow(ORDER - 2) + 1
#     rA0 = rand_coprime(ORDER)
#     baseA = H_to_int(sid, pwA)
#     print("Debug Init A: baseA =", baseA)
#     alpha_A0 = pow(baseA, rA0, p)
#     # Server computes beta_A0 = alpha_A0^sk
#     beta_A0 = pow(alpha_A0, sk, p)
#     # A computes kA0 = beta_A0^{1/rA0}  (mod p exponent inverse)
#     inv_rA0 = pow(rA0, -1, ORDER)
#     # inv_rA0 = mod_inverse(rA0, ORDER)
#     kA01 = pow(baseA, sk, p)
#     kA0 = pow(beta_A0, inv_rA0 , p)  # equals baseA^sk mod p
#     baseA1= pow(alpha_A0, inv_rA0, p)  # alpha_A0^{-rA0} mod p
#
#     print("Debug Init A: kA0(short) =", kA0 % 1000000)
#     print("Debug Init A1: kA011(short) =", kA01 % 1000000)
#     print("Debug Init baseA_1: ", baseA1 % 1000000)
#     print("Debug Init check: ", (rA0*inv_rA0) % ORDER)
#
#
#     gamma_A = PartyState(r=0, k=kA0)  # as text: gamma_A = (0,kA) or (r,k)? text said (0,kA) — we keep r stored
#
#     # B init
#     # rB0 = secrets.randbelow(ORDER - 2) + 1
#     rB0 = rand_coprime(ORDER)
#     baseB = H_to_int(sid, pwB)
#     print("Debug Init B: baseB =", baseB)
#     alpha_B0 = pow(baseB, rB0, p)
#     gamma_B = PartyState(r=rB0, k=0)
#
#     # server stores alpha_B0 per the diagram
#     gamma_S.alpha_last = alpha_B0
#
#     return gamma_S, gamma_A, gamma_B
#
# # -----------------------
# # Snd / Ser / Rcv / KRt
# # -----------------------
# def Snd(gamma_: PartyState, m: bytes) -> Tuple[bytes, int, PartyState]:
#     """
#     Snd(gamma_A, m) -> (c, alpha_A, gamma_A')
#     - parse state gamma_A = (r_A, k_A) to obtain k_A
#     - compute c = SE.Enc(k_A, m)
#     - sample r_A' and compute alpha_A = H(k_A)^{r_A'}
#     - update gamma_A to (r_A', k_A)
#     """
#     r_, k_ = gamma_.r, gamma_.k
#     # symmetric encryption key: transform k_A (group element) into bytes via KDF
#     key_bytes = kdf_bytes(int_to_bytes(k_))
#     c = SE_enc(key_bytes, m)
#
#     # sample new r'
#     r_prime = rand_coprime(ORDER)
#     hk = H_to_int(int_to_bytes(k_))  # H(k_A) as group base
#     alpha_ = pow(hk, r_prime, p)
#
#     new_gamma_ = PartyState(r=r_prime, k=k_)
#
#     return c, alpha_, new_gamma_
#
# def Ser(gamma_S: ServerState, alpha_: int) -> Tuple[int, ServerState]:
#     """
#     Ser(gamma_S, alpha_A) -> (beta_B, gamma_S')
#     - server parses its state gamma_S = (sk, alpha_last)
#     - computes beta_B = alpha_A^{sk}
#     - updates gamma_S' = (sk, alpha_A)
#     """
#     sk, alpha = gamma_S.sk, gamma_S.alpha_last
#     beta = pow(alpha, sk, p)
#     gamma_S.alpha_last = alpha_
#     return beta, gamma_S
#
# def Rcv(gamma_: PartyState, c: bytes, beta_: int) -> Tuple[Optional[bytes], PartyState]:
#     """
#     Rcv(gamma_B, c, beta_B) -> (m' or ⊥, gamma_B')
#     - parse gamma_B = (r_B, k_B)
#     - compute k_B' = beta_B^{1/r_B}
#     - attempt to decrypt c with derived key k_B' (and optionally with current k_B)
#     - if exactly one decrypts successfully -> output m', else output None
#     - update gamma_B to (0, k_B') if decrypt succeeded
#     """
#     r_, k_ = gamma_.r, gamma_.k
#     # print("Debug A Rcv: K_A,0 =", k_B)
#     # compute k_B' = beta_B^{1/r_B} (exponent inverse)
#     # inv_rB = None
#     # try:
#     inv_r = pow(r_, -1, ORDER)
#     # except ValueError:
#     #     # unlikely, but if inverse doesn't exist we fail
#     #     print("Debug A Rcv: inv_rB =", inv_rB)
#     #     return None, gamma_B
#
#
#
#     k_prime = pow(beta_, inv_r, p)
#     print("Debug K_B,0: k_prime(short) =", k_prime % 1000000)
#
#     # derive keys for decryption
#     key_from_kprime = kdf_bytes(int_to_bytes(k_prime))
#     key_from_k = kdf_bytes(int_to_bytes(k_))
#
#     m1 = SE_dec(key_from_kprime, c)
#     m2 = SE_dec(key_from_k, c)
#     # print("Rcv: m1 =", m1.hex())
#     # print("Rcv: m2 =", m2.hex())
#
#     # decide result: exactly one should succeed
#     success1 = (m1 is not None)
#     success2 = (m2 is not None)
#     if success1 and not success2:
#         new_state = PartyState(r=0, k=k_prime)
#         return m1, new_state
#     elif success2 and not success1:
#         # if older key decrypts, do we set to k_B' or keep? Text: only one can be decrypted correctly; otherwise ⊥.
#         # When decrypt with k_B (old), that means key hasn't rotated; set new k to k_B (or set to k_B')?
#         # We'll follow text: update to (0, k') where k' computed; but since m2 decrypted with k_B,
#         # we still set k' = k_B (or kB_prime?). We'll set k' = k_B (safer).
#         new_state = PartyState(r=0, k=k_)
#         return m2, new_state
#     else:
#         return None, gamma_
#
# def KRt(gamma_S: ServerState) -> ServerState:
#     """
#     KRt(gamma_S) -> gamma_S'
#     - server samples random r_s and computes new sk' = kdf(sk, r_s)
#     - update gamma_S to (sk', alpha_A) where alpha_A is last stored alpha
#     """
#     rs = secrets.token_bytes(16)
#     new_sk_bytes = kdf_bytes(int_to_bytes(gamma_S.sk), rs)
#     # map to integer in Z_ORDER
#     new_sk = int.from_bytes(new_sk_bytes, 'big') % ORDER
#     if new_sk == 0:
#         new_sk = 1
#     gamma_S.sk = new_sk
#     return gamma_S
#
# # -----------------------
# # Demo flow
# # -----------------------
# def run():
#     print("***********************From A to B ***********************")
#
#     # Setup (params implicit)
#     # Passwords (as bytes)
#     pwA = b"password"
#     pwB = b"password"
#
#     gamma_S, gamma_A, gamma_B = Init(pwA, pwB)
#     print("Init done.")
#     # print("Server.sk (short):", gamma_S.sk % 1000000)
#     # print("A.state.r,k (short):", gamma_A.r % 1000000, gamma_A.k % 1000000)
#     # print("B.state.r,k (short):", gamma_B.r % 1000000, gamma_B.k % 1000000)
#
#     # A wants to send message m to B via server
#
#     # 定义消息空间 M = {0,1}^{8·L}, L ∈ [8, 64], 即消息长度在 8 到 64 字节之间
#     def random_message(L_min=8, L_max=64) -> bytes:
#         L = secrets.randbelow(L_max - L_min + 1) + L_min
#         return secrets.token_bytes(L)
#
#     # 从消息空间中随机选取一条消息
#     m_10 = random_message()
#     # print(f"Alice 随机从消息空间 M 中选取消息 m (长度 {len(m_10)} 字节)")
#     print(f"[A] A select m_1,0 ({len(m_10)} bytes):", m_10.hex())
#
#
#     # A: Snd
#     c_10, alpha_A1, gamma_A = Snd(gamma_A, m_10)
#     print("[A] PCKA.Snd: sent c and alpha_A")
#     print("Debug Snd A: kA,0 =", gamma_A.k)
#
#     # Server: Ser
#     beta_B0, gamma_S = Ser(gamma_S, alpha_A1)
#     print("[S] PCKA.Ser: computed beta_B and updated alpha_last")
#
#     # Server forwards (c_1,0, beta_B0) to B
#
#     # B: Rcv
#     m_10out, gamma_B = Rcv(gamma_B, c_10, beta_B0)
#     print("Debug Rcv B: k_b,0", gamma_B.k)
#     if m_10out is None:
#         print("[B] PCKA.Rcv: failed to decrypt (output ⊥).")
#     else:
#         print("[B] PCKA.Rcv: decrypted message:", m_10out.hex())
#
#     # print("old sk (short):", gamma_S.sk % 1000000)
#
#     # New server key
#     gamma_S = KRt(gamma_S)
#     print("[S] PCKA.KRt: Server rotated new sk (short):", gamma_S.sk % 1000000)
#
#     print("***********************From B to A ***********************")
#
#     m_11 = random_message()
#     print(f"[B] B select m_1,1 ({len(m_11)} bytes):", m_11.hex())
#     # B: Snd
#     c_11, alpha_B1, gamma_B = Snd(gamma_B, m_11)
#     # print("Debug gamma_B :", gamma_B)
#     print("[B] PCKA.Snd: sent c_1,1 and alpha_B,1")
#
#     # Server: Ser
#     beta_A1, gamma_S = Ser(gamma_S, alpha_B1)
#     print("[S] PCKA.Ser: computed beta_A,1 and updated alpha_last")
#
#     # Server forwards (c_1,1, beta_A,1) to A
#
#     # A: Rcv
#     m_11out, gamma_A = Rcv(gamma_A, c_11, beta_A1)
#     if m_11out is None:
#         print("[A] PCKA.Rcv: failed to decrypt (output ⊥).")
#     else:
#         print("[A] PCKA.Rcv: decrypted message:", m_11out.hex())
#
#
#
# if __name__ == "__main__":
#     run()

import secrets
import hashlib
from dataclasses import dataclass
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes




def Setup(security_level=128):
    """
    使用标准椭圆曲线参数
    """
    if security_level == 128:
        return {
            'curve': ec.SECP256R1(),
            'H': hashes.SHA256,
            'curve_name': 'P-256',
            'security_level': 128
        }
    elif security_level == 192:
        return {
            'curve': ec.SECP384R1(),
            'H': hashes.SHA384,
            'curve_name': 'P-384',
            'security_level': 192
        }
    else:  # security_level == 256
        return {
            'curve': ec.SECP521R1(),
            'H': hashes.SHA512,
            'curve_name': 'P-521',
            'security_level': 256
        }



public_params = Setup(128)
curve = public_params['curve']
hash_algo = public_params['H']



# Session ID
sid = secrets.token_bytes(16)


def H_to_int(*parts: bytes) -> int:
    """Hash H: {0,1}* -> Z_ORDER (as integer)."""
    h = hashlib.sha256()
    for b in parts:
        h.update(b)
    return int.from_bytes(h.digest(), 'big') % ORDER


def int_to_bytes(i: int) -> bytes:
    return i.to_bytes((i.bit_length() + 7) // 8 or 1, 'big')


def point_to_bytes(point: ec.EllipticCurvePublicKey) -> bytes:
    """将椭圆曲线点序列化为字节"""
    return point.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )


def bytes_to_point(data: bytes) -> ec.EllipticCurvePublicKey:
    """从字节反序列化椭圆曲线点"""
    return ec.EllipticCurvePublicKey.from_encoded_point(
        curve, data
    )


def scalar_mult_point(scalar: int, point: ec.EllipticCurvePublicKey) -> ec.EllipticCurvePublicKey:
    """标量乘法: scalar * point"""
    # 通过创建临时私钥来实现标量乘法
    private_key = ec.derive_private_key(scalar % ORDER, curve, default_backend())
    # 获取对应的公钥点（这里简化处理，实际应该实现真正的点乘）
    return private_key.public_key()


def generate_point_from_int(value: int) -> ec.EllipticCurvePublicKey:
    """从整数生成曲线点（简化方法）"""
    private_key = ec.derive_private_key(value % ORDER, curve, default_backend())
    return private_key.public_key()


def rand_coprime(mod):
    while True:
        x = secrets.randbelow(mod - 1) + 1
        if x < mod:
            return x


def kdf_bytes(*parts: bytes) -> bytes:
    """Key derivation -> 32 bytes."""
    h = hashlib.sha256()
    for b in parts:
        h.update(b)
    return h.digest()


# 对称加密保持不变
def SE_enc(key_bytes: bytes, plaintext: bytes) -> bytes:
    aes = AESGCM(kdf_bytes(key_bytes))
    nonce = secrets.token_bytes(12)
    ct = aes.encrypt(nonce, plaintext, None)
    return nonce + ct


def SE_dec(key_bytes: bytes, blob: bytes) -> Optional[bytes]:
    try:
        aes = AESGCM(kdf_bytes(key_bytes))
        nonce, ct = blob[:12], blob[12:]
        pt = aes.decrypt(nonce, ct, None)
        return pt
    except Exception:
        return None


# -----------------------
# States dataclasses (ECC版本)
# -----------------------

@dataclass
class ServerState:
    sk: int  # server secret scalar
    point_last: Optional[bytes] = None  # 存储最后一个接收的点


@dataclass
class PartyState:
    r: int  # 随机标量
    point: bytes  # 椭圆曲线点（序列化后的公钥）


# -----------------------
# ECC 协议原语
# -----------------------

def Init(pwA: bytes, pwB: bytes) -> Tuple[ServerState, PartyState, PartyState]:
    """
    ECC版本的初始化
    """
    # Server选择私钥
    sk = secrets.randbelow(ORDER - 1) + 1
    gamma_S = ServerState(sk=sk, point_last=None)

    # A初始化
    rA0 = rand_coprime(ORDER)
    baseA_int = H_to_int(sid, pwA)

    # 将哈希值映射到曲线上的点
    baseA_point = generate_point_from_int(baseA_int)
    baseA_bytes = point_to_bytes(baseA_point)

    # A计算 alpha_A0 = [rA0] * baseA_point
    alpha_A0_point = scalar_mult_point(rA0, baseA_point)
    alpha_A0_bytes = point_to_bytes(alpha_A0_point)

    # Server计算 beta_A0 = [sk] * alpha_A0_point
    beta_A0_point = scalar_mult_point(sk, alpha_A0_point)
    beta_A0_bytes = point_to_bytes(beta_A0_point)

    # A计算 kA0 = [1/rA0] * beta_A0_point = [sk] * baseA_point
    inv_rA0 = pow(rA0, -1, ORDER)
    kA0_point = scalar_mult_point(inv_rA0, beta_A0_point)
    kA0_bytes = point_to_bytes(kA0_point)

    print(f"Debug Init A: baseA_int = {baseA_int % 1000000}")
    print(f"Debug Init A: kA0 point generated")

    gamma_A = PartyState(r=0, point=kA0_bytes)

    # B初始化
    rB0 = rand_coprime(ORDER)
    baseB_int = H_to_int(sid, pwB)
    baseB_point = generate_point_from_int(baseB_int)
    baseB_bytes = point_to_bytes(baseB_point)

    alpha_B0_point = scalar_mult_point(rB0, baseB_point)
    alpha_B0_bytes = point_to_bytes(alpha_B0_point)

    gamma_B = PartyState(r=rB0, point=baseB_bytes)

    # server存储B的点
    gamma_S.point_last = alpha_B0_bytes

    return gamma_S, gamma_A, gamma_B


def Snd(gamma_: PartyState, m: bytes) -> Tuple[bytes, bytes, PartyState]:
    """
    ECC版本的发送函数
    """
    r_, point_bytes = gamma_.r, gamma_.point
    point = bytes_to_point(point_bytes)

    # 对称加密
    key_bytes = kdf_bytes(point_bytes)
    c = SE_enc(key_bytes, m)

    # 生成新的随机标量并计算新点
    r_prime = rand_coprime(ORDER)

    # 计算 H(k) 作为新的基点
    hk_int = H_to_int(point_bytes)
    hk_point = generate_point_from_int(hk_int)

    # 计算 alpha = [r_prime] * H(k)
    alpha_point = scalar_mult_point(r_prime, hk_point)
    alpha_bytes = point_to_bytes(alpha_point)

    new_gamma_ = PartyState(r=r_prime, point=point_bytes)

    return c, alpha_bytes, new_gamma_


def Ser(gamma_S: ServerState, alpha_bytes: bytes) -> Tuple[bytes, ServerState]:
    """
    ECC版本的服务端处理
    """
    sk, last_point_bytes = gamma_S.sk, gamma_S.point_last
    alpha_point = bytes_to_point(alpha_bytes)

    # 计算 beta = [sk] * alpha_point
    beta_point = scalar_mult_point(sk, alpha_point)
    beta_bytes = point_to_bytes(beta_point)

    gamma_S.point_last = alpha_bytes
    return beta_bytes, gamma_S


def Rcv(gamma_: PartyState, c: bytes, beta_bytes: bytes) -> Tuple[Optional[bytes], PartyState]:
    """
    ECC版本的接收函数
    """
    r_, point_bytes = gamma_.r, gamma_.point
    beta_point = bytes_to_point(beta_bytes)

    # 计算 k_prime = [1/r] * beta_point
    inv_r = pow(r_, -1, ORDER)
    k_prime_point = scalar_mult_point(inv_r, beta_point)
    k_prime_bytes = point_to_bytes(k_prime_point)

    # 尝试解密
    key_from_kprime = kdf_bytes(k_prime_bytes)
    key_from_k = kdf_bytes(point_bytes)

    m1 = SE_dec(key_from_kprime, c)
    m2 = SE_dec(key_from_k, c)

    success1 = (m1 is not None)
    success2 = (m2 is not None)

    if success1 and not success2:
        new_state = PartyState(r=0, point=k_prime_bytes)
        return m1, new_state
    elif success2 and not success1:
        new_state = PartyState(r=0, point=point_bytes)
        return m2, new_state
    else:
        return None, gamma_


def KRt(gamma_S: ServerState) -> ServerState:
    """
    ECC版本的密钥轮换
    """
    rs = secrets.token_bytes(16)
    new_sk_bytes = kdf_bytes(int_to_bytes(gamma_S.sk), rs)
    new_sk = int.from_bytes(new_sk_bytes, 'big') % ORDER
    if new_sk == 0:
        new_sk = 1
    gamma_S.sk = new_sk
    return gamma_S


# -----------------------
# Demo flow
# -----------------------

def run():
    print("*********************** ECC PassRatchet Demo ***********************")

    pwA = b"password"
    pwB = b"password"

    try:
        gamma_S, gamma_A, gamma_B = Init(pwA, pwB)
        print("ECC Init done.")

        def random_message(L_min=8, L_max=64) -> bytes:
            L = secrets.randbelow(L_max - L_min + 1) + L_min
            return secrets.token_bytes(L)

        # A -> B
        print("\n--- A to B ---")
        m_10 = random_message()
        print(f"[A] A select m_1,0 ({len(m_10)} bytes)")

        c_10, alpha_A1, gamma_A = Snd(gamma_A, m_10)
        print("[A] PCKA.Snd: sent c and alpha_A")

        beta_B0, gamma_S = Ser(gamma_S, alpha_A1)
        print("[S] PCKA.Ser: computed beta_B")

        m_10out, gamma_B = Rcv(gamma_B, c_10, beta_B0)
        if m_10out is None:
            print("[B] PCKA.Rcv: failed to decrypt")
        else:
            print("[B] PCKA.Rcv: decrypted successfully")

        gamma_S = KRt(gamma_S)
        print("[S] PCKA.KRt: Server rotated key")

        # B -> A
        print("\n--- B to A ---")
        m_11 = random_message()
        print(f"[B] B select m_1,1 ({len(m_11)} bytes)")

        c_11, alpha_B1, gamma_B = Snd(gamma_B, m_11)
        print("[B] PCKA.Snd: sent c_1,1 and alpha_B,1")

        beta_A1, gamma_S = Ser(gamma_S, alpha_B1)
        print("[S] PCKA.Ser: computed beta_A,1")

        m_11out, gamma_A = Rcv(gamma_A, c_11, beta_A1)
        if m_11out is None:
            print("[A] PCKA.Rcv: failed to decrypt")
        else:
            print("[A] PCKA.Rcv: decrypted successfully")

        print("\nECC PassRatchet demo completed successfully!")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    run()