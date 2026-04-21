import hashlib
import socket
import threading
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from math import gcd
from typing import Tuple, Optional
import time
import secrets
from dataclasses import dataclass
from typing import Dict, Tuple
from ecdsa import curves
from ecdsa.ellipticcurve import Point, INFINITY
from CONFIG import *

print(f"[CHECK] 当前曲线: {CURVE_NAME}, order bit-length: {order.bit_length()}")
# ========== ECC 公共参数 ==========
# curve = curves.NIST256p
# order = curve.order
# generator = curve.generator
# H_func = hashlib.sha256  # NIST256p 对应 128-bit 安全级别, 用 SHA256


# ========== ECC Point helpers ==========

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


@dataclass
class ServerState:
    sk: int                 # server  secret
    alpha_last: Optional[object] = None  # store last received alpha (ECC point)

@dataclass
class PartyState:
    # For both A and B: state is a pair (r, k) OR (0, k)
    r: int
    k: object  # ECC point



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
    sk = secrets.randbelow(order - 2) + 2
    gamma_S = ServerState(sk=sk, alpha_last=None)
    return gamma_S


def Ser(gamma_S: ServerState, alpha_new) -> Tuple[object, ServerState]:
    """
    Ser(gamma_S, alpha_A) -> (beta_B, gamma_S')
    - server parses its state gamma_S = (sk, alpha_last)
    - computes beta_B = alpha_A^{sk}  →  beta = sk * alpha_last (ECC)
    - updates gamma_S' = (sk, alpha_A)
    """
    sk = gamma_S.sk
    alpha_old = gamma_S.alpha_last
    beta = sk * alpha_old  # ECC 标量乘
    gamma_S.alpha_last = alpha_new
    return beta, gamma_S

def KRt(gamma_S: ServerState) -> ServerState:
    """
    KRt(gamma_S) -> gamma_S'
    - server samples random r_s and computes new sk' = kdf(sk, r_s)
    - update gamma_S to (sk', alpha_A) where alpha_A is last stored alpha
    """
    rs = secrets.token_bytes(16)
    new_sk_bytes = kdf_bytes(int_to_bytes(gamma_S.sk), rs)
    # map to integer in Z_order
    new_sk = int.from_bytes(new_sk_bytes, 'big') % order
    if new_sk == 0:
        new_sk = 1
    gamma_S.sk = new_sk
    return gamma_S


# ========== 数据结构 ==========
@dataclass
class BulletinBoard:
    """公告板，存储注册和认证时的公共值"""
    env_a: str = None   # hex string of ECC point (was int)
    env_b: str = None   # hex string of ECC point (was int)
    # 认证阶段保存 (y_hex, cm_int)
    commits: Dict[str, Tuple[str, int]] = None

    def __post_init__(self):
        self.commits = {}


# def kdf_bytes(*parts: bytes) -> bytes:
#     """Simple key derivation -> 32 bytes."""
#     h = H_func()
#     for b in parts:
#         h.update(b)
#     return h.digest()
#
# def H_to_int(*parts: bytes) -> int:
#     """Hash H: {0,1}* -> Z_order (as integer)."""
#     h = H_func()
#     for b in parts:
#         h.update(b)
#     return int(int.from_bytes(h.digest(), 'big') % order)
#
# def int_to_bytes(i: int) -> bytes:
#     return i.to_bytes((i.bit_length() + 7)//8 or 1, 'big')
#
# def H_bytes(*parts: bytes) -> bytes:
#     h = H_func()
#     for p in parts:
#         h.update(p)
#     return h.digest()
# #
# def H_int(*parts: bytes, mod: int) -> int:
#     return int(int.from_bytes(H_bytes(*parts), 'big') % mod)


def rand_coprime(mod):
    while True:
        x = secrets.randbelow(mod - 2) + 1
        if gcd(x, mod) == 1:
            return x


def send_msg(conn, msg):
    message_str = json.dumps(msg) + "\n"  # 在每条消息后面加上换行符（`\n`）
    conn.sendall(message_str.encode())  # 发送数据


class Server:
    """
    模拟协议图中的 Server(sk)：
      1. 负责接收 a 或 a' 并返回 b = a^sk  →  b = sk * a_point (ECC)
      2. 记录认证阶段的 y 与 cm
      3. 提供公告板存取
    """
    def __init__(self):
        # 服务端的长期秘密 sk
        self.sk = secrets.randbelow(order - 2) + 2
        self.board = BulletinBoard()
        print(f"[Server] 初始化完成，sk 已生成 (曲线 NIST P-256, order {order.bit_length()} bits)")

    # ---------- 注册阶段 ----------
    def reg_response(self, who: str, a_point) -> object:
        """
        接收来自 Alice/Bob 的 a (ECC point)，
        返回 b = sk * a_point (ECC point)。
        """
        b_point = self.sk * a_point  # ECC 标量乘
        print(f"[Server] Registration/Auth: 收到 {who} 的 a 值并返回 b")
        return b_point

    def post_env(self, who: str, env_hex: str):
        """
        保存 Alice/Bob 的 env 到公告板。
        env_hex: ECC point 的 hex 编码
        """
        if who == 'Alice':
            self.board.env_a = env_hex
        else:
            self.board.env_b = env_hex
        print(f"[Server] {who} 的 env 已写入公告板")

    # ---------- 认证阶段 ----------
    def store_commit(self, who: str, y_hex: str, cm: int):
        """
        保存 y (hex string) 与 cm (int) 以便另一方读取。
        """
        self.board.commits[who] = (y_hex, cm)
        print(f"[Server] 存储 {who} 的 (y, cm)")

    # ---------- 读取公共数据 ----------
    def get_peer_commit(self, who: str):
        """
        返回对方的 (y_hex, cm_int)。
        """
        peer = 'Bob' if who == 'Alice' else 'Alice'
        return self.board.commits.get(peer)

    def get_peer_env(self, who: str):
        """
        返回对方的 env (hex string)。
        """
        return self.board.env_b if who == 'Alice' else self.board.env_a



clients = {}  # 保存 {"Alice": connA, "Bob": connB}
session_data = {
        "Alice": {},
        "Bob": {},
        "init_done": False,
        "pre_beta": 0
    }

# ShareKey 认证阶段: 等待双方同时提交 (a', y) 后一次性下发挑战与对端参数
_auth_barrier_lock = threading.Lock()
_auth_parts = {}  # "Alice"|"Bob" -> (a2_point, y_hex)
_auth_verify_ctx = {}  # identity -> {"cm": int, "y_hex": str}
_auth_server_holder = {}  # {"server": Server}
auth_barrier = None  # Barrier(2, ...) 在 start_server 中初始化


def _dispatch_auth_bundles():
    """双方在 barrier 上会合后发送 (b', cm, env_peer, y_peer)，并记录校验所需 cm、y。"""
    srv = _auth_server_holder["server"]
    board = srv.board
    (a2_a, y_a_hex) = _auth_parts["Alice"]
    (a2_b, y_b_hex) = _auth_parts["Bob"]
    b2_a = srv.sk * a2_a
    b2_b = srv.sk * a2_b
    cm_a = rand_scalar()
    cm_b = rand_scalar()
    _auth_verify_ctx.clear()
    _auth_verify_ctx["Alice"] = {"cm": cm_a, "y_hex": y_a_hex}
    _auth_verify_ctx["Bob"] = {"cm": cm_b, "y_hex": y_b_hex}
    cm_a_hex = hex(cm_a)[2:]
    cm_b_hex = hex(cm_b)[2:]
    resp_alice = {
        "type": "auth_bundle",
        "b2": point_to_bytes(b2_a).hex(),
        "cm": cm_a_hex,
        "env": board.env_b,
        "y": y_b_hex,
    }
    resp_bob = {
        "type": "auth_bundle",
        "b2": point_to_bytes(b2_b).hex(),
        "cm": cm_b_hex,
        "env": board.env_a,
        "y": y_a_hex,
    }
    send_msg(clients["Alice"], resp_alice)
    send_msg(clients["Bob"], resp_bob)
    print("[Server] Sent auth_bundle (b2, cm, env_peer, y_peer) to Alice and Bob.")
    _auth_parts.clear()


def handle_client(conn, addr, server, gamma_S):
    identity = None
    # print(f"[Server] Connection from {addr} established.")
    try:
        while True:
            data = conn.recv(4096).decode().strip()
            if not data:
                break

             # 尝试解析 JSON 数据
            try:
                msg = json.loads(data)
            except json.JSONDecodeError:
                print(f"[!] Invalid JSON from {addr}: {data}")
                continue  # 跳过当前消息，继续接收

            msg_type = msg.get("type")

            # === Step 1: 客户端发送身份 ===
            if msg_type == "identity":

                response = {"type": "ack", "msg": f"Hello {msg['name']}, register start."}
                conn.sendall(json.dumps(response).encode())  # 发送确认消息
                print(f"[Server] Sending identity response.")

                identity = msg.get("name")
                clients[identity] = conn
                # print(f"[Server] Registered identity: {identity}")
                print("---------------------------------------------------------------------------------")
                print(f"|                           Register ({identity})                              |")
                print("---------------------------------------------------------------------------------")
                continue

            # === Step 2: 处理注册和认证请求 ===
            if msg_type == "register":
                # 原: a_val = int(msg["a"], 16)   →  现: a_point = bytes_to_point(...)
                a_point = bytes_to_point(bytes.fromhex(msg["a"]))
                b_point = server.reg_response(identity, a_point)
                b_hex = point_to_bytes(b_point).hex()
                response = {"type": "register_response", "b": b_hex}
                send_msg(clients[identity], response)
                print(f"[Server] Sent <b> to {identity}.")

                continue

            elif msg_type == "post_env":
                # 原: env_val = int(msg["env"], 16)  →  现: 直接存 hex string
                env_hex = msg["env"]
                server.post_env(identity, env_hex)

                response = {"type": "ack", "msg": f"Env from {identity} stored."}
                send_msg(clients[identity], response)
                # print(f"[Server] Stored env from {identity}.")
                continue

            elif msg_type == "auth_start":
                print("---------------------------------------------------------------------------------")
                print(f"|                          Authentication ({identity})                         |")
                print("---------------------------------------------------------------------------------")
                a2_point = bytes_to_point(bytes.fromhex(msg["a2"]))
                y_hex = msg["y"]
                with _auth_barrier_lock:
                    _auth_parts[identity] = (a2_point, y_hex)
                auth_barrier.wait()
                continue

            elif msg_type == "auth_proof":
                t_ver = time.perf_counter()
                s_val = int(msg["s"], 16)
                ctx = _auth_verify_ctx.get(identity)
                if ctx is None:
                    print(f"[Server] auth_proof: no pending auth context for {identity}")
                    continue
                cm_val = ctx["cm"]
                y_hex = ctx["y_hex"]
                env_hex = server.board.env_a if identity == "Alice" else server.board.env_b
                env_pt = bytes_to_point(bytes.fromhex(env_hex))
                y_pt = bytes_to_point(bytes.fromhex(y_hex))
                lhs = s_val * generator
                rhs = env_pt + cm_val * y_pt
                if lhs == rhs:
                    print(f"[Server] Authentication verified for {identity}: g^s == env * y^cm")
                else:
                    print(f"[Server] Authentication FAILED for {identity}: verification mismatch")
                    # 口令/承诺校验失败：终止本次认证，通知双方并断开连接
                    fail_msg = {
                        "type": "auth_failed",
                        "reason": "verification_failed",
                        "party": identity,
                    }
                    for name in ("Alice", "Bob"):
                        peer_conn = clients.get(name)
                        if peer_conn is not None:
                            try:
                                send_msg(peer_conn, fail_msg)
                            except OSError:
                                pass
                    _auth_verify_ctx.clear()
                    for name in ("Alice", "Bob"):
                        oc = clients.pop(name, None)
                        if oc is not None:
                            try:
                                oc.shutdown(socket.SHUT_RDWR)
                            except OSError:
                                pass
                            try:
                                oc.close()
                            except OSError:
                                pass
                    break
                t_ver_ = time.perf_counter()
                print(f"[Server] Proof verification time: {(t_ver_ - t_ver)*1000:.2f} ms")
                continue

            elif msg_type == "store_commit":
                # 原: y_val = int(msg["y"], 16)
                # 现: y 是 ECC point 的 hex, 直接存 hex string
                y_hex = msg["y"]
                # cm = H(M || y_bytes) mod order
                # 原: cm_val = H_int(M, int_to_bytes(y_val), mod=ORDER)
                # 现: cm_val = H_int(M, bytes.fromhex(y_hex), mod=order)
                M = secrets.token_bytes(16)
                cm_val = H_int(M, bytes.fromhex(y_hex), mod=order)
                cm_val_hex = hex(cm_val)[2:]

                server.store_commit(identity, y_hex, cm_val)
                # print("store_commit",server.board.)

                response = {"type": "commit", "cm": cm_val_hex}
                send_msg(clients[identity], response)
                # print(f"[Server] Stored commit from {identity}.")
                continue

            elif msg_type == "request_env":

                print("request_env from ", identity)
                # 原: peer_env = server.get_peer_env(identity); peer_env_hex = hex(peer_env)[2:]
                # 现: peer_env_hex 已经是 hex string
                peer_env_hex = server.get_peer_env(identity)
                # print("=======peer_env: ", peer_env)

                while True:
                    peer_tu = server.get_peer_commit(identity)
                    # print("=======peer_tu: ", peer_tu)
                    if peer_tu is not None:
                        peer_y_hex = peer_tu[0]   # hex string of ECC point
                        peer_cm = peer_tu[1]       # int
                        response = {"type": "peer_env", "env": peer_env_hex, "cm": peer_cm, "y": peer_y_hex}
                        send_msg(clients[identity], response)
                        print(f"[Server] Sent < env,cm,y > to {identity}.")
                        break
                    else:
                        # print("Waiting for peer commit...")
                        # time.sleep(0.1)
                        continue
                continue

            # ===  PCKA ===
            elif msg_type == "session_id":
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
                # 原: alpha_A0 = int(msg["alpha_A0"], 16)
                # 现: alpha_A0 是 ECC point
                alpha_A0_hex = msg["alpha_A0"]
                alpha_A0_point = bytes_to_point(bytes.fromhex(alpha_A0_hex))
                session_data["Alice"]["alpha_A0"] = alpha_A0_hex
                print(f"[Server-Alice] Received <alpha_A0> from Alice.")

                # 计算 beta_A0 并回给 Alice
                # 原: beta_A0 = pow(alpha_A0, gamma_S.sk, p)
                # 现: beta_A0 = gamma_S.sk * alpha_A0_point
                beta_A0_point = gamma_S.sk * alpha_A0_point
                beta_A0_hex = point_to_bytes(beta_A0_point).hex()
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
                # 原: alpha_B0 = int(msg["alpha_B0"], 16)
                # 现: alpha_B0 是 ECC point
                alpha_B0_hex = msg["alpha_B0"]
                alpha_B0_point = bytes_to_point(bytes.fromhex(alpha_B0_hex))
                session_data["Bob"]["alpha_B0"] = alpha_B0_hex
                gamma_S.alpha_last = alpha_B0_point

                print(f"[Server-Bob] Server received <alpha_B0> from Bob")
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

                time0 = time.perf_counter()
                session_data["pre_beta"] = gamma_S.sk * gamma_S.alpha_last
                print(
                    f"[Server] Pre-computed beta_B0 (Time taken: {(time.perf_counter() - time0) * 1000:.4f} ms)")

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
                c_10 = msg["c_10"]
                beta_B0 = session_data["pre_beta"]

                # 发送 c_10，beta_B0给 Bob
                response = {"type": "send_c_beta_B", "c_10": c_10, "beta_B0": point_to_bytes(beta_B0).hex()}
                send_msg(clients["Bob"], response)
                print(f"[Server-Bob] Sent <c_10, beta_B0> to Bob")

                #gengxin
                alpha_A1_hex = msg["alpha_A1"]
                alpha_A1_point = bytes_to_point(bytes.fromhex(alpha_A1_hex))
                gamma_S.alpha_last = alpha_A1_point

                # beta_B0_point, gamma_S = Ser(gamma_S, alpha_A1_point)
                print("[S] PCKA.Ser: computed beta_B and updated alpha_last")

                gamma_S = KRt(gamma_S)
                print("[S] PCKA.KRt: Server rotated new sk (short):", gamma_S.sk % 1000000)
                # response = {"type": "key_refresh_ack", "msg": "Server key refreshed."}
                # send_msg(conn, response)

                time1 = time.perf_counter()
                session_data["pre_beta"] = gamma_S.sk * gamma_S.alpha_last
                print(
                    f"[Server] KRt done, new pre_beta (Time taken: {(time.perf_counter() - time1) * 1000:.4f} ms)")
                continue
            elif msg_type == "send_message2":
                print()
                print("***********************From B to A ***********************")

                # Server: Ser
                c_11 = msg["c_11"]
                beta_A1 = session_data["pre_beta"]

                # 发送 c_11，beta_A1给 Alice
                response = {"type": "send_c_beta_A", "c_11": c_11, "beta_A1": point_to_bytes(beta_A1).hex()}
                send_msg(clients["Alice"], response)
                print(f"[Server-Alice] Sent <c_11, beta_A1> to Alice")

                alpha_B1_hex = msg["alpha_B1"]
                alpha_B1_point = bytes_to_point(bytes.fromhex(alpha_B1_hex))
                gamma_S.alpha_last = alpha_B1_point

                # beta_A1_point, gamma_S = Ser(gamma_S, alpha_B1_point)
                print("[S] PCKA.Ser: computed beta_A,1 and updated alpha_last")

                time2 = time.perf_counter()
                session_data["pre_beta"] = gamma_S.sk * gamma_S.alpha_last
                print(
                    f"[Server] Pre-computed beta_B (Time taken: {(time.perf_counter() - time2) * 1000:.4f} ms)")

                continue

            else:
                print(f"[Server] Unknown message type from {identity}: {msg_type}")

    except Exception as e:
        print(f"[!] Error in handling {addr}: {e}")
        import traceback; traceback.print_exc()

    finally:
        conn.close()
        if identity in clients:
            del clients[identity]
        print(f"[-] Connection with {identity} closed.")

    # print("[Server] Board:", server.board)

def start_server(host, port):
    global auth_barrier
    server = Server()
    _auth_server_holder["server"] = server
    auth_barrier = threading.Barrier(2, action=_dispatch_auth_bundles)
    gamma_S = Init()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(5)
    print(f"Server listening on {host}:{port}")

    while True:

        conn, addr = s.accept()
        print(f"Connection from {addr}")
        threading.Thread(target=handle_client, args=(conn, addr, server, gamma_S)).start()
        # handle_client_connection(conn, addr, server)



if __name__ == "__main__":

    start_server("0.0.0.0", 8000)
    # print("[Server] Server 已启动，可供 Alice 和 Bob 调用接口。")
