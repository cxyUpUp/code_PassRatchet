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

print(f"[CHECK] The current curve: {CURVE_NAME}, order bit-length: {order.bit_length()}")


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
    return secrets.randbelow(order - 1) + 1


def map_pw_to_point(pw: str):
    h = int(int.from_bytes(H_bytes(pw.encode()), 'big') % order)
    if h == 0:
        h = 1
    return h


# -----------------------
# Data structures
# -----------------------

@dataclass
class BulletinBoard:
    env_a: object = None  # ECC point (was int)
    env_b: object = None  # ECC point (was int)


@dataclass
class Server:
    sk: int
    store_a: tuple = None
    store_b: tuple = None

    def reg_response(self, a_point):
        return self.sk * a_point

    def store_commit(self, who: str, y_point, cm: int):
        if who == 'A':
            self.store_a = (y_point, cm)
        else:
            self.store_b = (y_point, cm)


# -----------------------
# Alice class
# -----------------------

class Alice:
    def __init__(self, pw: str):
        self.id_str = 'A'
        self.pw = pw
        self.key = None
        self.x = None
        self.y = None       # ECC point
        self.cm = None       # int (scalar)
        self.rwd2 = None     # int (scalar)
        self.r_c = None

    # ---- Registration stage ----
    def register(self):
        while True:
            self.r = secrets.randbelow(order - 2) + 1
            if math.gcd(self.r, order) == 1:
                break
        h_pw = H_to_int(self.pw.encode())
        base_point = h_pw * generator
        a = self.r * base_point  # ECC point (blinded)

        # server.reg_response(a) returns sk * a
        b = self.server.reg_response(a)  # ECC point

        r_inv = pow(self.r, -1, order)
        t_k = r_inv * b  # ECC point (unblinded)

        self.rwd = H_int(self.id_str.encode(), point_to_bytes(t_k),
                         self.pw.encode(), mod=order)

        self.env = self.rwd * generator  # ECC point
        self.board.env_a = self.env

        print("[Alice] tk:", point_to_bytes(t_k).hex()[:32], "...")
        print("[Alice] 注册时 env_a:", point_to_bytes(self.env).hex()[:32], "...")
        print("[Alice] rwd_a:", self.rwd)
        print("[Alice] Registration complete, env_a posted.")

    # ---- Certification stage  ----
    def start_auth(self):
        pw_try = input("[Alice] Please re-enter the password to verify.: ")
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
        print("[Alice] tk':", point_to_bytes(t_k2).hex()[:32], "...")
        print("[Alice] rwd_a':", self.rwd2)
        print("[Alice] Authentication a' sent to server.")

    # ---- commit----
    def commit_phase(self):
        self.x = secrets.randbelow(order - 2) + 1
        self.y = self.x * generator  # ECC point
        return self.y

    # ---- Derived shared key ----
    def compute_sharekey(self, env_b_point, y_b_point) -> bytes:
        term1 = self.rwd2 * env_b_point
        term2 = self.x * y_b_point
        print("[Alice] rwd'_A * env_B =", point_to_bytes(term1).hex()[:32], "...")
        print("[Alice] x_A * y_B =", point_to_bytes(term2).hex()[:32], "...")

        self.sharekey = H_bytes(point_to_bytes(term1), point_to_bytes(term2))
        print("[Alice] ShareKey derived.")
        return self.sharekey


# -----------------------
# Main entry
# -----------------------

def main():
    from PCKA_4_SM.Alice import run
    communication_times = []

    sock = connect_to_server("127.0.0.1", 8000)
    print("Alice connected to server.")

    identity_msg = {"type": "identity", "name": "Alice"}
    send_message(sock, identity_msg)
    print("Alice sent identity.")

    response = receive_message(sock)
    if response:
        print(f"Alice received: {response}")

    for _ in range(100):#Set the running test to facilitate testing. The default setting is 1.

        print("---------------------------------------------------------------------------------")
        print("|                                 Register                                      |")
        print("---------------------------------------------------------------------------------")

        # password = input("Please enter Alice's password: ") # Enter the password manually.
        password = "alice_password" # Fixed password, convenient for testing

        alice = Alice(password)

        time1 = time.perf_counter()

        # ======== Registration stage  ========
        r1 = rand_scalar()
        h_pw = H_to_int(password.encode())                 # mod order
        base_point = h_pw * generator                       # h_pw * G → ECC point
        a_point = r1 * base_point                           

        time1_ = time.perf_counter()

        # send alpha 
        msg = {"type": "register", "name": "A", "a": point_to_bytes(a_point).hex()}
        send_message(sock, msg)
        print("[Alice] Sent <a> to server. ")

        # receive beta 
        response = receive_message(sock)
        b_point = bytes_to_point(bytes.fromhex(response['b']))
        print(f"[Alice] Received <b> from server: {point_to_bytes(b_point).hex()[:32]}...")

        time2 = time.perf_counter()

        # unblinded: t_k = r1^{-1} * b = sk * h_pw * G
        r1_inv = pow(r1, -1, order)
        t_k = r1_inv * b_point  # ECC point

        # rwd_a = H(id || point_to_bytes(t_k) || pw) mod order
        rwd_a = H_int(alice.id_str.encode(), point_to_bytes(t_k), password.encode(), mod=order)

        # env_a = rwd_a * G  (ECC point)
        env_a = rwd_a * generator

        msg = {"type": "post_env", "name": "A", "env": point_to_bytes(env_a).hex()}
        send_message(sock, msg)
        print("[Alice] Sent <env_a> to server. ")
        time2_ = time.perf_counter()

        response = receive_message(sock)
        print(f"[Alice] Received ack from server. {response}")
        print("[Alice] Registration completed.")

        print("---------------------------------------------------------------------------------")
        print("|                                 Authentication                                |")
        print("---------------------------------------------------------------------------------")

        # ======== Certification stage ========
        # password1 = input("Re-enter Alice's password: ")
        password1 = "alice_password"  # Fixed password, convenient for testing

        time3 = time.perf_counter()
        r2 = rand_scalar()
        h_pw_try = H_to_int(password1.encode())             
        base_point2 = h_pw_try * generator                   # H(pw') * G
        a2_point = r2 * base_point2                          # a'_A = H(pw')^{r'}
        alice.x = secrets.randbelow(order - 2) + 1
        y_a_point = alice.x * generator                     # y_A = g^{x_A}
        alice.y = y_a_point

        msg = {
            "type": "auth_start",
            "name": "A",
            "a2": point_to_bytes(a2_point).hex(),
            "y": point_to_bytes(y_a_point).hex(),
        }

        time3_ = time.perf_counter()
        send_message(sock, msg)
        print("[Alice] Sent <a2, y_a> to server. ")

        response = receive_message(sock)

        time4 = time.perf_counter()
        b2_point = bytes_to_point(bytes.fromhex(response['b2']))
        cm_a = int(response['cm'], 16)
        env_b_hex = response['env']
        y_b_hex = response['y']
        print(f"[Alice] Received <b2, cm_a, env_b, y_b> from server. {response}")

        
        r2_inv = pow(r2, -1, order)
        t_k2 = r2_inv * b2_point  # ECC point

        rwd2 = H_int(alice.id_str.encode(), point_to_bytes(t_k2), password1.encode(), mod=order)
        alice.rwd2 = rwd2
        alice.cm = cm_a

        env_b_point = bytes_to_point(bytes.fromhex(env_b_hex))
        y_b_point = bytes_to_point(bytes.fromhex(y_b_hex))

        sharekey_a = alice.compute_sharekey(env_b_point, y_b_point)
        time4_ = time.perf_counter()

        print(f"[Alice] Computed sharekey: {sharekey_a.hex()}")

        t_ver = time.perf_counter()
        s_a = (rwd2 + cm_a * alice.x) % order
        msg = {"type": "auth_proof", "name": "A", "s": hex(s_a)}
        send_message(sock, msg)
        print("[Alice] Sent <s_a> to server.")
        t_ver_ = time.perf_counter()

        time_Init = (time2_ - time1) * 1000
        time_Auth = (time4_ - time3) * 1000
        time_Verify = (t_ver_ - t_ver) * 1000


        # Wait to ensure that Bob has also completed the calculation
        time.sleep(0.5)

        # Enter the PCKA secure communication 
        # run(sharekey_a, sock)

        print(f"[Time-ShareKey_Negotiation]  time for Alice:  {(time_Init + time_Auth):.4f} ms")
        print(f"[Time-Registration]  time for Alice:  {time_Init:.4f} ms")
        print(f"[Time-Authentication]  time for Alice:  {time_Auth:.4f} ms")
        print(f"[Time-Verification]  time for Alice:  {time_Verify:.4f} ms")
        communication_times.append(time_Init + time_Auth)

    df = pd.DataFrame(communication_times, columns=["Messaging Time (ms)"])
    print(df)



if __name__ == "__main__":
    main()
