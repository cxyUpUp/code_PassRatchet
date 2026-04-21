
import secrets
import hashlib
from dataclasses import dataclass
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from math import gcd

# -----------------------
# Group & crypto helpers
# -----------------------
# Use same group as Alice/Bob examples: p = 2**521 - 1, g = 5
p = 2**521 - 1
g = 5
ORDER = p - 1  # treat group exponent modulo ORDER

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

# -----------------------
# Protocol primitives
# -----------------------
def Setup() -> Tuple[int,int,int]:
    """Setup(1^lambda) -> params: returns (p, g, ORDER) in this demo."""
    # params are module-level; simply return them
    return (p, g, ORDER)

def Init(pwA: bytes, pwB: bytes) -> Tuple[ServerState, PartyState, PartyState]:
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

    # A init
    # rA0 = secrets.randbelow(ORDER - 2) + 1
    rA0 = rand_coprime(ORDER)
    baseA = H_to_int(sid, pwA)
    # print("Debug Init A: baseA =", baseA)
    alpha_A0 = pow(baseA, rA0, p)
    # Server computes beta_A0 = alpha_A0^sk
    beta_A0 = pow(alpha_A0, sk, p)
    # A computes kA0 = beta_A0^{1/rA0}  (mod p exponent inverse)
    inv_rA0 = pow(rA0, -1, ORDER)
    kA0 = pow(beta_A0, inv_rA0, p)  # equals baseA^sk mod p
    # print("Debug Init A: kA0(short) =", kA0 % 1000000)
    gamma_A = PartyState(r=0, k=kA0)  # as text: gamma_A = (0,kA) or (r,k)? text said (0,kA) — we keep r stored

    # B init
    # rB0 = secrets.randbelow(ORDER - 2) + 1
    rB0 = rand_coprime(ORDER)
    baseB = H_to_int(sid, pwB)
    # print("Debug Init B: baseB =", baseB)
    alpha_B0 = pow(baseB, rB0, p)
    gamma_B = PartyState(r=rB0, k=0)

    # server stores alpha_B0 per the diagram
    gamma_S.alpha_last = alpha_B0

    return gamma_S, gamma_A, gamma_B

# -----------------------
# Snd / Ser / Rcv / KRt
# -----------------------
def Snd(gamma_: PartyState, m: bytes) -> Tuple[bytes, int, PartyState]:
    """
    Snd(gamma_A, m) -> (c, alpha_A, gamma_A')
    - parse state gamma_A = (r_A, k_A) to obtain k_A
    - compute c = SE.Enc(k_A, m)
    - sample r_A' and compute alpha_A = H(k_A)^{r_A'}
    - update gamma_A to (r_A', k_A)
    """
    r_, k_ = gamma_.r, gamma_.k
    # symmetric encryption key: transform k_A (group element) into bytes via KDF
    key_bytes = kdf_bytes(int_to_bytes(k_))
    c = SE_enc(key_bytes, m)

    # sample new r'
    r_prime = rand_coprime(ORDER)
    hk = H_to_int(int_to_bytes(k_))  # H(k_A) as group base
    alpha_ = pow(hk, r_prime, p)

    new_gamma_ = PartyState(r=r_prime, k=k_)

    return c, alpha_, new_gamma_

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

def Rcv(gamma_: PartyState, c: bytes, beta_: int) -> Tuple[Optional[bytes], PartyState]:
    """
    Rcv(gamma_B, c, beta_B) -> (m' or ⊥, gamma_B')
    - parse gamma_B = (r_B, k_B)
    - compute k_B' = beta_B^{1/r_B}
    - attempt to decrypt c with derived key k_B' (and optionally with current k_B)
    - if exactly one decrypts successfully -> output m', else output None
    - update gamma_B to (0, k_B') if decrypt succeeded
    """
    r_, k_ = gamma_.r, gamma_.k
    # print("Debug A Rcv: K_A,0 =", k_B)
    # compute k_B' = beta_B^{1/r_B} (exponent inverse)
    # inv_rB = None
    # try:
    inv_r = pow(r_, -1, ORDER)
    # except ValueError:
    #     # unlikely, but if inverse doesn't exist we fail
    #     print("Debug A Rcv: inv_rB =", inv_rB)
    #     return None, gamma_B



    k_prime = pow(beta_, inv_r, p)
    # print("Debug Init A: k_prime(short) =", k_prime % 1000000)

    # derive keys for decryption
    key_from_kprime = kdf_bytes(int_to_bytes(k_prime))
    key_from_k = kdf_bytes(int_to_bytes(k_))

    m1 = SE_dec(key_from_kprime, c)
    m2 = SE_dec(key_from_k, c)
    # print("Rcv: m1 =", m1.hex())
    # print("Rcv: m2 =", m2.hex())

    # decide result: exactly one should succeed
    success1 = (m1 is not None)
    success2 = (m2 is not None)
    if success1 and not success2:
        new_state = PartyState(r=0, k=k_prime)
        return m1, new_state
    elif success2 and not success1:
        # if older key decrypts, do we set to k_B' or keep? Text: only one can be decrypted correctly; otherwise ⊥.
        # When decrypt with k_B (old), that means key hasn't rotated; set new k to k_B (or set to k_B')?
        # We'll follow text: update to (0, k') where k' computed; but since m2 decrypted with k_B,
        # we still set k' = k_B (or kB_prime?). We'll set k' = k_B (safer).
        new_state = PartyState(r=0, k=k_)
        return m2, new_state
    else:
        return None, gamma_

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

# -----------------------
# Demo flow
# -----------------------
def run():
    print("***********************From A to B ***********************")

    # Setup (params implicit)
    # Passwords (as bytes)
    pwA = b"password"
    pwB = b"password"

    gamma_S, gamma_A, gamma_B = Init(pwA, pwB)
    print("Init done.")
    # print("Server.sk (short):", gamma_S.sk % 1000000)
    # print("A.state.r,k (short):", gamma_A.r % 1000000, gamma_A.k % 1000000)
    # print("B.state.r,k (short):", gamma_B.r % 1000000, gamma_B.k % 1000000)

    # A wants to send message m to B via server

    # 定义消息空间 M = {0,1}^{8·L}, L ∈ [8, 64], 即消息长度在 8 到 64 字节之间
    def random_message(L_min=8, L_max=64) -> bytes:
        L = secrets.randbelow(L_max - L_min + 1) + L_min
        return secrets.token_bytes(L)

    # 从消息空间中随机选取一条消息
    m_10 = random_message()
    # print(f"Alice 随机从消息空间 M 中选取消息 m (长度 {len(m_10)} 字节)")
    print(f"[A] A select m_1,0 ({len(m_10)} bytes):", m_10.hex())


    # A: Snd
    c_10, alpha_A1, gamma_A = Snd(gamma_A, m_10)
    print("[A] PCKA.Snd: sent c and alpha_A")
    # print("Debug Snd A: kA,0 =", gamma_A.k)

    # Server: Ser
    beta_B0, gamma_S = Ser(gamma_S, alpha_A1)
    print("[S] PCKA.Ser: computed beta_B and updated alpha_last")

    # Server forwards (c_1,0, beta_B0) to B
    # B: Rcv
    m_10out, gamma_B = Rcv(gamma_B, c_10, beta_B0)
    # print("Debug Rcv B: gamma_B", gamma_B)
    if m_10out is None:
        print("[B] PCKA.Rcv: failed to decrypt (output ⊥).")
    else:
        print("[B] PCKA.Rcv: decrypted message:", m_10out.hex())

    # print("old sk (short):", gamma_S.sk % 1000000)

    # New server key
    gamma_S = KRt(gamma_S)
    print("[S] PCKA.KRt: Server rotated new sk (short):", gamma_S.sk % 1000000)

    print("***********************From B to A ***********************")

    m_11 = random_message()
    print(f"[B] B select m_1,1 ({len(m_11)} bytes):", m_11.hex())
    # B: Snd
    c_11, alpha_B1, gamma_B = Snd(gamma_B, m_11)
    # print("Debug gamma_B :", gamma_B)
    print("[B] PCKA.Snd: sent c_1,1 and alpha_B,1")

    # Server: Ser
    beta_A1, gamma_S = Ser(gamma_S, alpha_B1)
    print("[S] PCKA.Ser: computed beta_A,1 and updated alpha_last")

    # Server forwards (c_1,1, beta_A,1) to A

    # A: Rcv
    m_11out, gamma_A = Rcv(gamma_A, c_11, beta_A1)
    if m_11out is None:
        print("[A] PCKA.Rcv: failed to decrypt (output ⊥).")
    else:
        print("[A] PCKA.Rcv: decrypted message:", m_11out.hex())



if __name__ == "__main__":
    run()
