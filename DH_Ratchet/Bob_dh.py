import socket
import time
import secrets
import pandas as pd
import hashlib
import json
from ecdsa import curves, ellipticcurve
from ecdsa.ellipticcurve import Point
from ecdsa.numbertheory import square_root_mod_prime


def _affine_generator(curve):
    g = curve.generator
    if hasattr(g, "to_affine"):
        g = g.to_affine()
    return g

HOST = '127.0.0.1'
PORT = 8000
CLIENT_NAME = "Bob"

# -------------------------
# Communication
# -------------------------

def send_message(sock, msg):
    message_str = json.dumps(msg) + "\n"
    sock.sendall(message_str.encode())

def receive_message(sock):
    data = sock.recv(4096).decode()
    if not data:
        return None
    return json.loads(data)

# -------------------------
# ECC 
# -------------------------

DEFAULT_CURVE = curves.NIST256p

SECURITY_CONFIGS = {
    128: {
        "curve": curves.NIST256p,
        "hash_alg": hashlib.sha256,
    },
    192: {
        "curve": curves.NIST384p,
        "hash_alg": hashlib.sha384,
    },
    256: {
        "curve": curves.NIST521p,
        "hash_alg": hashlib.sha512,
    }
}


class ECCKeyPair:

    def __init__(self, private_key=None, curve=None):
        self.curve = curve if curve else DEFAULT_CURVE
        self.curve_obj = self.curve.curve

        if private_key is None:
            n = self.curve.order
            self.private_key = secrets.randbelow(n - 1) + 1
        else:
            self.private_key = private_key

        self.public_point = self.private_key * _affine_generator(self.curve)

    def exchange(self, peer_public_point):
        if isinstance(peer_public_point, Point):
            peer_point = peer_public_point
        elif isinstance(peer_public_point, Point):
            peer_point = peer_public_point
        elif isinstance(peer_public_point, ECCKeyPair):
            peer_point = peer_public_point.public_point
        else:
            raise TypeError("peer_public_point must be Point")

        shared_point = self.private_key * peer_point
        return shared_point.x()

    def public_bytes(self, compressed=True):
        return self._point_to_bytes(self.public_point, compressed)

    def _point_to_bytes(self, point, compressed=True):
        if point == ellipticcurve.INFINITY:
            raise ValueError("Infinity point")

        x = point.x()
        y = point.y()

        field_size_bytes = (self.curve_obj.p().bit_length() + 7) // 8
        x_bytes = x.to_bytes(field_size_bytes, 'big')

        if compressed:
            prefix = 0x02 if y % 2 == 0 else 0x03
            return bytes([prefix]) + x_bytes
        else:
            y_bytes = y.to_bytes(field_size_bytes, 'big')
            return bytes([0x04]) + x_bytes + y_bytes

    def _bytes_to_point(self, data, curve_obj=None):
        if curve_obj is None:
            curve_obj = self.curve_obj

        p = curve_obj.p()

        if data[0] == 0x04:  
            field_size_bytes = (p.bit_length() + 7) // 8
            if len(data) != 1 + 2 * field_size_bytes:
                raise ValueError("Invalid uncompressed point length")

            x_bytes = data[1:1 + field_size_bytes]
            y_bytes = data[1 + field_size_bytes:]

            x = int.from_bytes(x_bytes, 'big')
            y = int.from_bytes(y_bytes, 'big')

            if not curve_obj.contains_point(x, y):
                raise ValueError("Point not on curve")

            return Point(curve_obj, x, y)

        elif data[0] in (0x02, 0x03):
            field_size_bytes = (p.bit_length() + 7) // 8
            if len(data) != 1 + field_size_bytes:
                raise ValueError("Invalid compressed point length")
            x = int.from_bytes(data[1:], 'big')
            y_square = (pow(x, 3, p) + curve_obj.a() * x + curve_obj.b()) % p
            y = square_root_mod_prime(y_square, p)

            if y is None:
                raise ValueError("Invalid compressed point")

            if data[0] == 0x02:  
                if y % 2 != 0:
                    y = p - y
            else:  
                if y % 2 == 0:
                    y = p - y

            return Point(curve_obj, x, y)
        else:
            raise ValueError("Unsupported format")

    @classmethod
    def from_public_bytes(cls, public_bytes, curve):
        curve_obj = curve if curve is not None else DEFAULT_CURVE
        keypair = cls(curve=curve_obj)
        keypair.public_point = keypair._bytes_to_point(public_bytes, curve_obj.curve)
        return keypair

def select_security_level():

    while True:
        choice = '1'  
        if choice == '1':
            return 128
        elif choice == '2':
            return 192
        elif choice == '3':
            return 256
        else:
            print("Valid choice")

def generate_keypair(security_level):
    curve = SECURITY_CONFIGS[security_level]["curve"]
    return ECCKeyPair(curve=curve)


def load_public_key(pub_bytes, security_level):
    curve = SECURITY_CONFIGS[security_level]["curve"]
    return ECCKeyPair.from_public_bytes(pub_bytes, curve)

def get_public_bytes(ecc_keypair, compressed=True):
    return ecc_keypair.public_bytes(compressed)


def main():

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(60)
    client.connect((HOST, PORT))
    print(f"[{CLIENT_NAME}] connected to server")

    security_level = select_security_level()
    config = SECURITY_CONFIGS[security_level]
    hash_func = config["hash_alg"]

    dh_outputs = []
    communication_times = []

 
    send_message(client, {
        "type": "register",
        "client": CLIENT_NAME,
        "security_level": security_level
    })

    print(f"--------------------{CLIENT_NAME} - ECC DH Ratchet --------------------")

 
    time1 = time.perf_counter()
    current_keypair = generate_keypair(security_level)
    current_public_bytes = get_public_bytes(current_keypair, compressed=True)
    #
    _fsb0 = (current_keypair.curve_obj.p().bit_length() + 7) // 8
    _ = hash_func(
        current_keypair.public_point.x().to_bytes(_fsb0, "big")
    ).hexdigest()

    peer_keypair = None

    print(f"[{CLIENT_NAME}] Init public key: {current_public_bytes.hex()[:24]}...")

    try:
        send_message(client, {"type": "public_key", "pubkey": current_public_bytes.hex()})

        time_init = (time.perf_counter() - time1) * 1000

        print(f"[{CLIENT_NAME}] sent initial public key")

        ratchet_count = 0

        # DH ratchet cycle
        while ratchet_count < 10:

            cmd = 'r' 
            if cmd == 'q':
                break
            elif cmd == 'r':

                ratchet_count += 1
                print(f"\n[{CLIENT_NAME}] ---- Ratchet {ratchet_count} ----")

                time_start = time.perf_counter()
                resp = receive_message(client)

                if resp["type"] != "public_key":
                    print("Error: expected public_key")
                    return

                peer_pub_bytes = bytes.fromhex(resp["pubkey"])
                peer_keypair = load_public_key(peer_pub_bytes, security_level)

                # DH1
                shared_int = current_keypair.exchange(peer_keypair.public_point)
                field_size_bytes = (current_keypair.curve_obj.p().bit_length() + 7) // 8
                shared_bytes = shared_int.to_bytes(field_size_bytes, 'big')
                dh_output_1 = hash_func(shared_bytes).hexdigest()

                time_b1 = (time.perf_counter() - time_start) * 1000 + time_init

                print(f"\n[{CLIENT_NAME}] DH_output #{ratchet_count}--1: {dh_output_1[:32]}... ({time_b1:.4f}ms)")
                dh_outputs.append(dh_output_1)

                start_time = time.perf_counter()
                new_keypair = generate_keypair(security_level)
                new_public_bytes = get_public_bytes(new_keypair, compressed=True)

                _fsb_kg = (new_keypair.curve_obj.p().bit_length() + 7) // 8
                _ = hash_func(
                    new_keypair.public_point.x().to_bytes(_fsb_kg, "big")
                ).hexdigest()

                send_message(client, { "type": "public_key", "pubkey": new_public_bytes.hex()})
                time_init = (time.perf_counter() - start_time) * 1000
                print(f"[{CLIENT_NAME}] send new public key #{ratchet_count}: {new_public_bytes.hex()[:24]}...")

                # DH2
                t3 = time.perf_counter()
                shared_int = new_keypair.exchange(peer_keypair.public_point)
                shared_bytes = shared_int.to_bytes(field_size_bytes, 'big')
                dh_output_2 = hash_func(shared_bytes).hexdigest()
                time_b2 = (time.perf_counter() - t3) * 1000

                print(f"[{CLIENT_NAME}] DH_output #{ratchet_count}--2: {dh_output_2[:32]}... ({time_b2:.4f}ms)")

                dh_outputs.append(dh_output_2)
                communication_times.append(time_b1 + time_b2)

                current_keypair = new_keypair
                current_public_bytes = new_public_bytes

            else:
                client.settimeout(1)
                try:
                    resp = receive_message(client)
                    if resp["type"] == "public_key":
                        peer_pub_bytes = bytes.fromhex(resp["pubkey"])
                        print(f"[{CLIENT_NAME}] Received new public key: {peer_pub_bytes.hex()[:24]}...")
                        peer_keypair = load_public_key(peer_pub_bytes, security_level)

                        dh_shared_int = current_ecc_keypair.exchange(peer_keypair.public_point)
                        field_size_bytes = (current_ecc_keypair.curve_obj.p().bit_length() + 7) // 8
                        dh_shared_bytes = dh_shared_int.to_bytes(field_size_bytes, 'big')
                        dh_output = hash_func(dh_shared_bytes).hexdigest()

                        dh_outputs.append(dh_output)
                        print(f"[{CLIENT_NAME}] DH_output #{ratchet_count}: {dh_output[:32]}...")
                except socket.timeout:
                    pass
                client.settimeout(60)

        send_message(client, {"type": "done"})

        df = pd.DataFrame(communication_times, columns=["ECC DH Ratchet Time (ms)"])

        print(f"\n{'=' * 50}")
        print(f"Rounds: {ratchet_count}")
        print("\n---ECC DH Ratchet Time Summary ---")
        print(df)

        print(f"DH_output numbers: {len(dh_outputs)}")
        for i, dh in enumerate(dh_outputs[:10], 1):
            print(f"  #{i}: {dh[:48]}...")
        print(f"{'=' * 50}")

    except Exception as e:
        print(f"[{CLIENT_NAME}] error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.close()
        print("Connection closed.")


if __name__ == "__main__":
    main()
