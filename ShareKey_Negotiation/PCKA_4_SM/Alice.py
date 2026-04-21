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

    # beta_A0 = response['beta_A0']  # ECC 
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
    for i in range(100):

        def random_message(L_min=8, L_max=64):
            L = secrets.randbelow(L_max - L_min + 1) + L_min
            return secrets.token_bytes(L)

        print("***********************From A to B ***********************")
        m_10 = random_message()

        print(f"[A] A select m_1,0 ({len(m_10)} bytes):", m_10.hex())

        # A: Snd
        t1 = time.perf_counter()
        st = time.perf_counter()
        c_10, alpha_A1, gamma_A = Snd(gamma_A, m_10)
        st_end = time.perf_counter()
        communication_times1.append((st_end - st)*1000)

        send_message(sock, {"type": "send_message1", "c_10": c_10.hex(), "alpha_A1": point_to_bytes(alpha_A1).hex()})
        t2 = time.perf_counter()

        print("[A] PCKA.Snd: sent c and alpha_A")

        print()
        print("*********************From B to A *********************")

        # A: Rcv
        t3 = time.perf_counter()

        resp = receive_message(sock)

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


if __name__ == "__main__":
    sock = connect_to_server("127.0.0.1", 9000)
    print("Alice connected to server.")

    send_message(sock, {"type": "identity", "name": "Alice"})
    print("Alice sent identity.")

    response = receive_message(sock)
    print(f"Alice received: {response}")

    pwA = b"password"
    run(pwA, sock)
