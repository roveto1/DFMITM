# mallory.py (relay-only version)

import socket, threading, os, base64, re, sys, time
from utils import send_obj, recv_obj
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import math
# DH params (same as Alice/Bob)
p_hex = """
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
29024E088A67CC74020BBEA63B139B22514A08798E3404DD
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D
C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F
83655D23DCA3AD961C62F356208552BB9ED529077096966D
670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
"""

# Remove whitespace and newlines
p_hex_cleaned = "".join(p_hex.split())

# Convert to integer
p = int(p_hex_cleaned, 16)
g = 2
LISTEN_PORT = 5000
BOB_IP = "192.168.15.137"
BOB_PORT = 5000

# Gatekeeper flag
gatekeeper = False

# pending queues: each entry is {"text": str, "send_func": callable}
pending = {
    "alice": [],
    "bob": []
}
pend_lock = threading.Lock()

def parse_quoted(cmd: str):
    m = re.search(r'"(.*)"', cmd)
    return m.group(1) if m else None

# session state (relay has no AES keys)
current_session = {
    "alice_sock": None,
    "bob_sock": None,
}

session_lock = threading.Lock()

def set_session(a_sock, b_sock):
    with session_lock:
        current_session["alice_sock"] = a_sock
        current_session["bob_sock"] = b_sock

def clear_session():
    with session_lock:
        current_session["alice_sock"] = None
        current_session["bob_sock"] = None

def handle_command(line: str):
    global gatekeeper
    line = line.strip()
    if not line:
        return

    # -------------------------
    # Gatekeeper controls
    # -------------------------
    if line.lower() == "/gatekeeper on":
        gatekeeper = True
        print("[MALLORY] Gatekeeper ENABLED")
        return

    if line.lower() == "/gatekeeper off":
        gatekeeper = False
        print("[MALLORY] Gatekeeper DISABLED")
        # flush pending
        with pend_lock:
            while pending["alice"]:
                item = pending["alice"].pop(0)
                item["send_func"](item["raw"])
                print(f'[MALLORY]: *Forwarded* - [ALICE->BOB] <ciphertext>')
            while pending["bob"]:
                item = pending["bob"].pop(0)
                item["send_func"](item["raw"])
                print(f'[MALLORY]: *Forwarded* - [BOB->ALICE] <ciphertext>')
        return

    # -------------------------
    # Edit pending (ciphertext only)
    # -------------------------
    if line.startswith("/edit "):
        parts = line.split(" ", 2)
        if len(parts) < 2:
            print('[MALLORY] Usage: /edit alice')
            return
        target = parts[1].lower()
        if target not in ("alice", "bob"):
            print("[MALLORY] Choose alice or bob")
            return

        # extract text argument
        text = ""
        if len(parts) == 3:
            if parts[2].startswith('"') and parts[2].endswith('"'):
                text = parts[2][1:-1]
            else:
                print("[MALLORY] Text must be in quotes")
                return
        else:
            print('[MALLORY] Missing replacement text: /edit alice "new body"')
            return

        with pend_lock:
            queue = pending[target]
            if not queue:
                print(f"[MALLORY] No pending {target} messages to edit")
                return

            item = queue.pop(0)

            # Replace ciphertext with fake ciphertext (same length as original)
            raw_pkt = item.get("raw")
            if raw_pkt is None:
                print("[MALLORY] Cannot edit: no raw packet (bug?)")
                return

            fake_ct = base64.b64encode(os.urandom(len(text.encode()) + 16)).decode()
            fake_nonce = base64.b64encode(os.urandom(12)).decode()

            new_pkt = {
                "type": "encrypted",
                "nonce": fake_nonce,
                "ct": fake_ct
            }

            item["send_func"](new_pkt)

            print(f'[MALLORY]: *Edited (fake)* - [{target.upper()}] "{text}"')
            print("      (Alice/Bob WILL reject it, but modified packet sent.)")

            return

    if line.startswith("/msg "):
        parts = line.split(" ", 2)
        if len(parts) < 3:
            print('[MALLORY] Usage: /msg alice "text"')
            return
        target = parts[1].lower()
        if target not in ("alice", "bob"):
            print("[MALLORY] Target must be alice or bob")
            return
        text = parse_quoted(line)
        if text is None:
            print('[MALLORY] /msg requires quoted text: /msg alice "hello"')
            return

        # In relay mode we cannot encrypt valid ciphertext.
        # But we CAN send a fake ciphertext packet.
        pkt = {
            "type": "encrypted",
            "nonce": base64.b64encode(os.urandom(12)).decode(),
            "ct": base64.b64encode(os.urandom(len(text.encode()) + 16)).decode()
        }

        with session_lock:
            sock = current_session["alice_sock"] if target == "alice" else current_session["bob_sock"]

        if sock is None:
            print("[MALLORY] No active session. Cannot inject.")
            return

        send_obj(sock, pkt)

        print(f'[MALLORY]: *Injected (fake)* - [{target.upper()}] "{text}"')
        print("      (Alice/Bob WILL reject it, but packet was injected on wire.)")

        return

    # -------------------------
    # Drop a pending ciphertext packet
    # -------------------------
    if line.startswith("/drop "):
        parts = line.split()
        if len(parts) < 2:
            print("[MALLORY] Usage: /drop alice")
            return
        target = parts[1].lower()
        if target not in ("alice", "bob"):
            print("[MALLORY] Choose alice or bob")
            return
        with pend_lock:
            queue = pending[target]
            if not queue:
                print(f"[MALLORY] No pending {target} messages to drop")
                return
            item = queue.pop(0)
        print(f'[MALLORY]: *Dropped* - [{target.upper()}] <ciphertext>')
        return

    # -------------------------
    # Forward the next ciphertext in queue
    # -------------------------
    if line.startswith("/forward "):
        parts = line.split()
        if len(parts) < 2:
            print("[MALLORY] Usage: /forward alice")
            return
        target = parts[1].lower()
        if target not in ("alice", "bob"):
            print("[MALLORY] Choose alice or bob")
            return

        with pend_lock:
            queue = pending[target]
            if not queue:
                print(f"[MALLORY] No pending {target} messages to forward")
                return
            item = queue.pop(0)

        item["send_func"](item["raw"])
        print(f'[MALLORY]: *Forwarded* - [{target.upper()}] <ciphertext>')
        return

    print(f"[MALLORY] Unknown command: {line}")



def handle_client(alice_sock, addr):
    """
    Relay-only Mallory:
       - Relays Alice's initial handshake to Bob unchanged
       - Relays Bob's handshake to Alice unchanged
       - Transparently forwards encrypted packets
       - Gatekeeper can hold/drop ciphertext packets
       - Mallory cannot decrypt anything
    """
    print("[Mallory] Alice connected from", addr)

    try:
        # Receive Alice's initial dh_pub
        m = recv_obj(alice_sock)
        if not m or m.get("type") != "dh_pub":
            print("[Mallory] Invalid or missing dh_pub from Alice.")
            alice_sock.close()
            return

        a_pub_str = m.get("pub")
        alice_cert_pem = m.get("cert")
        alice_signature = m.get("signature")

        # Connect to Bob
        bob_sock = socket.create_connection((BOB_IP, BOB_PORT))
        print("[Mallory] Connected to Bob (relay mode).")

        # Forward Alice → Bob
        send_obj(bob_sock, {
            "type": "dh_pub",
            "pub": a_pub_str,
            "cert": alice_cert_pem,
            "signature": alice_signature
        })
        print("[Mallory] Forwarded Alice's dh_pub+cert to Bob.")

        # Receive Bob's response
        m2 = recv_obj(bob_sock)
        if not m2 or m2.get("type") != "dh_pub":
            print("[Mallory] Invalid dh_pub from Bob.")
            bob_sock.close()
            alice_sock.close()
            return

        # Forward Bob → Alice
        send_obj(alice_sock, m2)
        print("[Mallory] Forwarded Bob's dh_pub+cert to Alice.")

        # Activate session (relay only)
        set_session(alice_sock, bob_sock)

        # ----------- Encrypted forwarding loops -----------
        def forward(src, dst, origin):
            try:
                while True:
                    pkt = recv_obj(src)
                    if pkt is None:
                        break

                    if pkt.get("type") == "encrypted":
                        if not gatekeeper:
                            send_obj(dst, pkt)
                            print(f"[Mallory] Forwarded encrypted [{origin}]")
                        else:
                            with pend_lock:
                                pending[origin.lower()].append({
                                    "text": "<ciphertext>",
                                    "raw": pkt,
                                    "send_func": lambda pkt_out, dst_sock=dst: send_obj(dst_sock, pkt_out)
                                })
                            print(f"[MALLORY] HELD [{origin}] <ciphertext>")

                    elif pkt.get("type") == "close":
                        send_obj(dst, {"type": "close"})
                        break
                    else:
                        send_obj(dst, pkt)

            except Exception as e:
                print("[Mallory] forward ended:", e)

        t1 = threading.Thread(target=forward, args=(alice_sock, bob_sock, "ALICE"), daemon=True)
        t2 = threading.Thread(target=forward, args=(bob_sock, alice_sock, "BOB"), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()

        clear_session()
        bob_sock.close()
        alice_sock.close()
        print("[Mallory] Relay session ended.")

    except Exception as e:
        print("[Mallory] ERROR:", e)

def main():
    print("Available commands:")
    print("  /mode relay | /mode mitm")
    print("  /gatekeeper on|off")
    print('  /msg alice "text"  (requires AES session)')
    print('  /msg bob   "text"')
    print("  /forward alice|bob")
    print("  /drop alice|bob")
    print('  /edit alice|bob "text"')

    def console_loop():
        while True:
            try:
                line = input()
            except EOFError:
                break
            handle_command(line)

    threading.Thread(target=console_loop, daemon=True).start()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", LISTEN_PORT))
    s.listen(5)
    print("[Mallory] listening on port", LISTEN_PORT)

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
