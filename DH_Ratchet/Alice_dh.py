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
    """仿射坐标下的基点 G。k*G 走仿射 Point.__mul__，与 exchange 里 k*Q（仿射公钥）同一实现；不改动 exchange。"""
    g = curve.generator
    if hasattr(g, "to_affine"):
        g = g.to_affine()
    return g

HOST = '13.208.161.119'
# HOST = '127.0.0.1'
PORT = 8000
CLIENT_NAME = "Alice"

# ECC配置 - 使用ecdsa库
DEFAULT_CURVE = curves.NIST256p

# 安全等级配置
SECURITY_CONFIGS = {
    128: {
        "curve": curves.NIST256p,
        "hash_alg": hashlib.sha256,
        "key_size": 32
    },
    192: {
        "curve": curves.NIST384p,
        "hash_alg": hashlib.sha384,
        "key_size": 48
    },
    256: {
        "curve": curves.NIST521p,
        "hash_alg": hashlib.sha512,
        "key_size": 66
    }
}


# ================= 通信层 =================

def send_message(sock, msg):
    message_str = json.dumps(msg) + "\n"
    sock.sendall(message_str.encode())


def receive_message(sock):
    data = sock.recv(4096).decode()
    if not data:
        return None
    return json.loads(data.strip())


# ================= ECC 部分（未改动） =================

class ECCKeyPair:

    def __init__(self, private_key=None, curve=None):
        self.curve = curve if curve is not None else DEFAULT_CURVE
        self.curve_obj = self.curve.curve

        if private_key is None:
            n = self.curve.order
            self.private_key = secrets.randbelow(n - 1) + 1
        else:
            self.private_key = private_key

        # 私钥 * 仿射 G：与 exchange 中私钥*仿射对方公钥同为 Point.__mul__（仅改密钥生成，不改 exchange）
        self.public_point = self.private_key * _affine_generator(self.curve)

    def exchange(self, peer_public_point):
        if isinstance(peer_public_point, bytes):
            peer_point = self._bytes_to_point(peer_public_point)
        elif isinstance(peer_public_point, Point):
            peer_point = peer_public_point
        else:
            raise TypeError("peer_public_point must be bytes or Point")

        shared_point = self.private_key * peer_point
        return shared_point.x()

    def public_bytes(self, compressed=True):
        return self._point_to_bytes(self.public_point, compressed)

    def _point_to_bytes(self, point, compressed=True):
        if point == ellipticcurve.INFINITY:
            raise ValueError("Cannot serialize point at infinity")

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
            x = int.from_bytes(data[1:1 + field_size_bytes], 'big')
            y = int.from_bytes(data[1 + field_size_bytes:], 'big')

            if not curve_obj.contains_point(x, y):
                raise ValueError("Point not on curve")

            return Point(curve_obj, x, y)

        elif data[0] in (0x02, 0x03):
            field_size_bytes = (p.bit_length() + 7) // 8
            x = int.from_bytes(data[1:], 'big')

            y_square = (pow(x, 3, p) + curve_obj.a() * x + curve_obj.b()) % p
            y = square_root_mod_prime(y_square, p)

            if y is None:
                raise ValueError("Invalid compressed point")

            # 检查y的奇偶性
            if data[0] == 0x02:  # y应为偶数
                if y % 2 != 0:
                    y = p - y
            else:  # data[0] == 0x03, y应为奇数
                if y % 2 == 0:
                    y = p - y

            return Point(curve_obj, x, y)
        else:
            raise ValueError("Invalid point format")


# ================= 主函数 =================

def select_security_level():
    """选择安全等级"""
    while True:
        choice = '1'  # 默认选择128-bit
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
    keypair = ECCKeyPair(curve=curve)
    keypair.public_point = keypair._bytes_to_point(pub_bytes, curve.curve)
    return keypair

def get_public_bytes(ecc_keypair, compressed=True):
    """获取公钥的字节表示"""
    return ecc_keypair.public_bytes(compressed)


def main():

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(60)
    client.connect((HOST, PORT))
    print(f"[{CLIENT_NAME}] connected to server")

    communication_times = []
    communication_times1 = []
    communication_times2 = []
    print(f"--------------------{CLIENT_NAME} - ECC DH Ratchet  -------------------- ")
    security_level = select_security_level()
    config = SECURITY_CONFIGS[security_level]
    hash_func = config["hash_alg"]

    peer_keypair = None
    current_keypair = None
    dh_outputs = []

    try:

        # 注册
        send_message(client, {
            "type": "register",
            "client": CLIENT_NAME,
            "security_level": security_level
        })

        # 接收初始公钥
        time_start = time.perf_counter()
        resp = receive_message(client)

        if resp["type"] != "public_key":
            print("error")
            return

        peer_pub_bytes = bytes.fromhex(resp["pubkey"])
        peer_keypair = load_public_key(peer_pub_bytes, security_level)

        time_end = time.perf_counter()
        time_init = (time_end - time_start) * 1000

        ratchet_count = 0

        # ECC DH 棘轮循环
        while ratchet_count < 301:
            cmd = 'r'
            if cmd == 'q':
                break
            elif cmd == 'r':

                ratchet_count += 1
                print(f"\n[{CLIENT_NAME}] ---------Ratchet-{ratchet_count} --------")

                time1 = time.perf_counter()

                # 生成新的密钥对
                t_p = time.perf_counter()
                current_keypair = generate_keypair(security_level)
                current_public_bytes = current_keypair.public_bytes(compressed=True)

                field_size_bytes = (current_keypair.curve_obj.p().bit_length() + 7) // 8
                _ = hash_func(
                    current_keypair.public_point.x().to_bytes(field_size_bytes, "big")
                ).hexdigest()
                t_p_end = time.perf_counter()

                print(f"[DDDDDDDDDD] Key generation time: {(t_p_end - t_p) * 1000:.4f}ms")
                print(f"[{CLIENT_NAME}] Init public key: {current_public_bytes.hex()[:24]}...")

                # 计算DH共享密钥
                t_out = time.perf_counter()
                shared_secret_int = current_keypair.exchange(peer_keypair.public_point)
                field_size_bytes = (current_keypair.curve_obj.p().bit_length() + 7) // 8
                shared_secret_bytes = shared_secret_int.to_bytes(field_size_bytes, 'big')
                dh_output_1 = hash_func(shared_secret_bytes).hexdigest()
                t_out_end = time.perf_counter()
                print(f"[DDDDDDDDDD] ECC DH computation time: {(t_out_end - t_out) * 1000:.4f}ms")

                communication_times1.append([(t_p_end - t_p) * 1000 + (t_out_end - t_out) * 1000])

                # 发送公钥
                send_message(client, {
                    "type": "public_key",
                    "pubkey": current_public_bytes.hex()
                })
                print(f"[{CLIENT_NAME}] sent public key")

                time2 = time.perf_counter()
                time_a1 = (time2 - time1) * 1000 + time_init

                print(f"\n[{CLIENT_NAME}] DH_output #{ratchet_count}--1: {dh_output_1[:32]}... ({time_a1:.4f}ms)")
                dh_outputs.append(dh_output_1)

                # 等待对方公钥
                start_time = time.perf_counter()
                print(f"[{CLIENT_NAME}] Waiting for peer's public key...")
                resp = receive_message(client)

                if resp["type"] == "public_key":
                    peer_pub_bytes = bytes.fromhex(resp["pubkey"])
                    peer_keypair = load_public_key(peer_pub_bytes, security_level)

                    time_init = (time.perf_counter() - start_time) * 1000
                    print(f"[{CLIENT_NAME}] Received new public key: {peer_pub_bytes.hex()[:24]}...")

                    # 计算第二个DH输出
                    time3 = time.perf_counter()
                    shared_secret_int = current_keypair.exchange(peer_keypair.public_point)
                    shared_secret_bytes = shared_secret_int.to_bytes(field_size_bytes, 'big')
                    dh_output = hash_func(shared_secret_bytes).hexdigest()
                    time_a2 = (time.perf_counter() - time3) * 1000

                    communication_times2.append(time_a2)

                    dh_outputs.append(dh_output)
                    communication_times.append(time_a1 + time_a2)
                    print(f"[{CLIENT_NAME}] DH_output #{ratchet_count}--2: {dh_output[:32]}... ({time_a2:.4f}ms)")

                elif resp["type"] == "done":
                    print(f"[{CLIENT_NAME}] Peer signaled done. Exiting...")
                    break

            else:
                # 被动接收对方的新公钥
                client.settimeout(1)
                try:
                    resp = receive_message(client)
                    if resp["type"] == "public_key":
                        peer_pub_bytes = bytes.fromhex(resp["pubkey"])
                        print(f"[{CLIENT_NAME}] Received new public key: {peer_pub_bytes.hex()[:24]}...")
                        peer_keypair = load_public_key(peer_pub_bytes, security_level)

                        # 用当前私钥计算 DH
                        dh_shared_int = current_ecc_keypair.exchange(peer_keypair.public_point)
                        field_size_bytes = (current_ecc_keypair.curve_obj.p().bit_length() + 7) // 8
                        dh_shared_bytes = dh_shared_int.to_bytes(field_size_bytes, 'big')
                        dh_output = hash_func(dh_shared_bytes).hexdigest()

                        dh_outputs.append(dh_output)
                        print(f"[{CLIENT_NAME}] DH_output #{ratchet_count}: {dh_output[:32]}...")
                except socket.timeout:
                    pass
                client.settimeout(60)


        # 发送完成信号
        send_message(client, {"type": "done"})

        # 显示统计
        df = pd.DataFrame(communication_times, columns=["ECC DH Ratchet Time (ms)"])
        print(f"\n{'=' * 50}")
        print(f"Rounds: {ratchet_count}")
        print("\n---ECC DH Ratchet Time Summary ---")
        # pd.set_option('display.max_rows', None)
        print(df)

        print(f"DH_output numbers: {len(dh_outputs)}")
        for i, dh in enumerate(dh_outputs[:10], 1):
            print(f"  #{i}: {dh[:48]}...")
        print(f"{'=' * 50}")

        df1 = pd.DataFrame(communication_times1, columns=["ECC DH1 (ms)"])
        print(df1)

        df2 = pd.DataFrame(communication_times2, columns=["ECC DH2 (ms)"])
        print(df2)

        # with pd.ExcelWriter(r"D:\pyProiect\code_PassRatchaet\Experiment_result\_para_PCKA.xlsx",
        #                     engine='openpyxl',
        #                     mode='a') as writer:
        #     df.to_excel(writer, sheet_name='aws-DH256-', index=False)

        with pd.ExcelWriter(r"D:\pyProiect\code_PassRatchaet\Experiment_result\AWS_DH.xlsx", engine='openpyxl',
                            mode='a') as writer:
            df.to_excel(writer, sheet_name='awsDH-300----', index=False)

        # with pd.ExcelWriter(r"D:\pyProiect\code_PassRatchaet\Experiment_result\AWS_DH.xlsx", engine='openpyxl',
        #                     mode='a') as writer:
        #     df2.to_excel(writer, sheet_name='awsDH2-1', index=False)


        # df.to_excel(r"D:\pyProiect\code_PassRatchaet\Experiment_result\Compare_.xlsx", index=False)
        # with pd.ExcelWriter(r"D:\pyProiect\code_PassRatchaet\Experiment_result\Compare_.xlsx",
        #                     engine='openpyxl',
        #                     mode='a') as writer:
        #     df.to_excel(writer, sheet_name='DH2', index=False)

        # with pd.ExcelWriter(r"D:\pyProiect\code_PassRatchaet\PCKA_4_SM\AWS-COM_ecdsa.xlsx",
        #                     engine='openpyxl',
        #                     mode='a') as writer:
        #     df.to_excel(writer, sheet_name='DH4', index=False)

    except Exception as e:
        print(f"[{CLIENT_NAME}] error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.close()
        print(f"[{CLIENT_NAME}] connection closed.")


if __name__ == "__main__":
    main()
