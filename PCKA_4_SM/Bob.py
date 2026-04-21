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

    # Receive sid
    sid_msg = receive_message(sock)
    print(f"Bob received sid message: {sid_msg}")
    sid = bytes.fromhex(sid_msg["sid"])
    print(f"Bob received sid: {sid.hex()}")

    send_message(sock, {"type": "ack_sid"})
    print("Bob sent ack_sid")

    alpha_B0, rB0 = Init(pwB, sid)

    # wait "A to B" 
    response = receive_message(sock)
    print(f"Bob received message: {response}")

    send_message(sock, {"type": "send_alpha_B0", "alpha_B0": point_to_bytes(alpha_B0).hex()})

    gamma_B = PartyState(r=rB0, k=0 * generator)
    print("Bob sent <alpha_B0> to server.")
    print("Bob's gamma_B:", gamma_B)

    # wait ready
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
