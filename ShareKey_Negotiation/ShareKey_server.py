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

print(f"[CHECK] The current curve: {CURVE_NAME}, order bit-length: {order.bit_length()}")


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
    # Server chooses sk
    sk = secrets.randbelow(order - 2) + 2
    gamma_S = ServerState(sk=sk, alpha_last=None)
    return gamma_S


def Ser(gamma_S: ServerState, alpha_new) -> Tuple[object, ServerState]:
    sk = gamma_S.sk
    alpha_old = gamma_S.alpha_last
    beta = sk * alpha_old  
    gamma_S.alpha_last = alpha_new
    return beta, gamma_S

def KRt(gamma_S: ServerState) -> ServerState:
    rs = secrets.token_bytes(16)
    new_sk_bytes = kdf_bytes(int_to_bytes(gamma_S.sk), rs)
    # map to integer in Z_order
    new_sk = int.from_bytes(new_sk_bytes, 'big') % order
    if new_sk == 0:
        new_sk = 1
    gamma_S.sk = new_sk
    return gamma_S


# ========== Data Structure ==========
@dataclass
class BulletinBoard:
    """Notice board, storing common values during registration and authentication"""
    env_a: str = None   # hex string of ECC point (was int)
    env_b: str = None   # hex string of ECC point (was int)
    commits: Dict[str, Tuple[str, int]] = None

    def __post_init__(self):
        self.commits = {}


def rand_coprime(mod):
    while True:
        x = secrets.randbelow(mod - 2) + 1
        if gcd(x, mod) == 1:
            return x


def send_msg(conn, msg):
    message_str = json.dumps(msg) + "\n"  
    conn.sendall(message_str.encode())  


class Server:
    def __init__(self):
        self.sk = secrets.randbelow(order - 2) + 2
        self.board = BulletinBoard()
        print(f"[Server] Initialization completed. sk has been generated. ( NIST P-256, order {order.bit_length()} bits)")


    def reg_response(self, who: str, a_point) -> object:
        b_point = self.sk * a_point  
        print(f"[Server] Registration/Auth: Receive the value 'a' from {who} and return 'b'")
        return b_point


    def post_env(self, who: str, env_hex: str):
        if who == 'Alice':
            self.board.env_a = env_hex
        else:
            self.board.env_b = env_hex
        print(f"[Server] The env of {who} has been posted on the bulletin board.")


    def store_commit(self, who: str, y_hex: str, cm: int):
        self.board.commits[who] = (y_hex, cm)
        print(f"[Server] 存储 {who} 的 (y, cm)")


    def get_peer_commit(self, who: str):
        peer = 'Bob' if who == 'Alice' else 'Alice'
        return self.board.commits.get(peer)


    def get_peer_env(self, who: str):
        return self.board.env_b if who == 'Alice' else self.board.env_a



clients = {}  
session_data = {
        "Alice": {},
        "Bob": {},
        "init_done": False,
        "pre_beta": 0
    }

# ShareKey Authentication Phase
_auth_barrier_lock = threading.Lock()
_auth_parts = {}  # "Alice"|"Bob" -> (a2_point, y_hex)
_auth_verify_ctx = {}  # identity -> {"cm": int, "y_hex": str}
_auth_server_holder = {}  # {"server": Server}
auth_barrier = None  # Barrier(2, ...) Initialize in the "start_server" function


def _dispatch_auth_bundles():
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

            try:
                msg = json.loads(data)
            except json.JSONDecodeError:
                print(f"[!] Invalid JSON from {addr}: {data}")
                continue  

            msg_type = msg.get("type")

            # === Step 1: Client sends identity ===
            if msg_type == "identity":

                response = {"type": "ack", "msg": f"Hello {msg['name']}, register start."}
                conn.sendall(json.dumps(response).encode()) 
                print(f"[Server] Sending identity response.")

                identity = msg.get("name")
                clients[identity] = conn
                # print(f"[Server] Registered identity: {identity}")
                print("---------------------------------------------------------------------------------")
                print(f"|                           Register ({identity})                              |")
                print("---------------------------------------------------------------------------------")
                continue

            # === Step 2: Handle registration and authentication requests ===
            if msg_type == "register":
                a_point = bytes_to_point(bytes.fromhex(msg["a"]))
                b_point = server.reg_response(identity, a_point)
                b_hex = point_to_bytes(b_point).hex()
                response = {"type": "register_response", "b": b_hex}
                send_msg(clients[identity], response)
                print(f"[Server] Sent <b> to {identity}.")

                continue

            elif msg_type == "post_env":
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
                    # Password verification failed: Terminate this authentication process and disconnect.
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
                y_hex = msg["y"]
                M = secrets.token_bytes(16)
                cm_val = H_int(M, bytes.fromhex(y_hex), mod=order)
                cm_val_hex = hex(cm_val)[2:]

                server.store_commit(identity, y_hex, cm_val)

                response = {"type": "commit", "cm": cm_val_hex}
                send_msg(clients[identity], response)
                # print(f"[Server] Stored commit from {identity}.")
                continue

            elif msg_type == "request_env":

                print("request_env from ", identity)
                peer_env_hex = server.get_peer_env(identity)

                while True:
                    peer_tu = server.get_peer_commit(identity)

                    if peer_tu is not None:
                        peer_y_hex = peer_tu[0]   # hex string of ECC point
                        peer_cm = peer_tu[1]       # int
                        response = {"type": "peer_env", "env": peer_env_hex, "cm": peer_cm, "y": peer_y_hex}
                        send_msg(clients[identity], response)
                        print(f"[Server] Sent < env,cm,y > to {identity}.")
                        break
                    else:
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
                alpha_A0_hex = msg["alpha_A0"]
                alpha_A0_point = bytes_to_point(bytes.fromhex(alpha_A0_hex))
                session_data["Alice"]["alpha_A0"] = alpha_A0_hex
                print(f"[Server-Alice] Received <alpha_A0> from Alice.")

                beta_A0_point = gamma_S.sk * alpha_A0_point
                beta_A0_hex = point_to_bytes(beta_A0_point).hex()
                response_to_alice = {"type": "send_beta_A0", "beta_A0": beta_A0_hex}
                send_msg(clients["Alice"], response_to_alice)
                print(f"[Server-Alice] Sent <beta_A0> to Alice")


                max_wait_time = 10  
                interval = 0.1  
                waited = 0

                while "Bob" not in clients:
                    print("[Server] Waiting for Bob to connect...")
                    time.sleep(interval)
                    waited += interval
                    if waited >= max_wait_time:
                        print("[Server] Timeout: Bob not connected.")
                        break
                
                if "Bob" in clients:
                    response_to_bob = {"type": "A_to_B", "message": "A to B"}
                    send_msg(clients["Bob"], response_to_bob)
                    print("[Server-Bob] Sent 'A to B' to Bob.")
                else:
                    print("[Server] Bob not connected yet.")

                if "alpha_B0" in session_data["Bob"]:
                    session_data["init_done"] = True
                    print("[Server] Both Init steps done, ready for messaging.")


                continue
               
            elif msg_type == "send_alpha_B0":

                alpha_B0_hex = msg["alpha_B0"]
                alpha_B0_point = bytes_to_point(bytes.fromhex(alpha_B0_hex))
                session_data["Bob"]["alpha_B0"] = alpha_B0_hex
                gamma_S.alpha_last = alpha_B0_point

                print(f"[Server-Bob] Server received <alpha_B0> from Bob")
                print("[Server] gamma_S :", gamma_S)

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
                print(f"[Server-Alice] Received <c_10, alpha_A1> from Alice")
                c_10 = msg["c_10"]
                beta_B0 = session_data["pre_beta"]

                response = {"type": "send_c_beta_B", "c_10": c_10, "beta_B0": point_to_bytes(beta_B0).hex()}
                send_msg(clients["Bob"], response)
                print(f"[Server-Bob] Sent <c_10, beta_B0> to Bob")

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

