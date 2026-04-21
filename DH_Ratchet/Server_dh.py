import socket
import threading
import time
import json

HOST = '0.0.0.0'
PORT = 8000

clients = {}  # {name: conn}
clients_lock = threading.Lock()


# ================= Communication =================

def send_message(conn, msg):
    message_str = json.dumps(msg) + "\n"
    conn.sendall(message_str.encode())


def recv_message(conn):
    data = conn.recv(8192).decode()
    if not data:
        return None
    return json.loads(data.strip())


# ================= Forwarding logic =================

def forward_to_peer(sender_name, message):
    peer_name = "Bob" if sender_name == "Alice" else "Alice"
    with clients_lock:
        if peer_name in clients:
            try:
                send_message(clients[peer_name], message)
                return True
            except:
                return False
    return False


def handle_client(conn, addr):
    client_name = None
    try:
        conn.settimeout(300)

        msg = recv_message(conn)
        if msg is None or msg["type"] != "register":
            print(f"[Server] Valid registration")
            return

        client_name = msg["client"]
        security_level = int(msg["security_level"])

        with clients_lock:
            clients[client_name] = conn

        print(f"[Server] {client_name} registered ({addr}) ")

        # Continue to forward the message
        while True:
            try:
                msg = recv_message(conn)

                if msg is None:
                    break

                if msg["type"] == "done":
                    print(f"[Server] {client_name} Completed")
                    break

                if msg["type"] == "public_key":

                    if forward_to_peer(client_name, msg):
                        print(f"[Server] send {client_name} public key to peer")
                    else:
                        print(f"[Server] Waiting for peer to connect..")
                        for _ in range(500):
                            time.sleep(0.1)
                            if forward_to_peer(client_name, msg):
                                print(f"[Server] send {client_name} public key to peer")
                                break

            except socket.timeout:
                continue
            except Exception as e:
                print(f"[Server] {client_name} error: {e}")
                break

    except Exception as e:
        print(f"[Server] {client_name} error: {e}")
    finally:
        if client_name:
            with clients_lock:
                if client_name in clients:
                    del clients[client_name]
            print(f"[Server] {client_name} disconnected")

        try:
            conn.close()
        except:
            pass


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(10)

    print(f"[Server] listening on {HOST}:{PORT}")
    print("[Server] Waiting for Alice and Bob ...\n")

    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("\n[Server] Closing...")
    finally:
        server.close()


if __name__ == "__main__":
    main()
