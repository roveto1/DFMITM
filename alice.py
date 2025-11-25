# alice.py
import socket, sys, threading, os, base64
from utils import send_obj, recv_obj
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# https://www.ietf.org/rfc/rfc3526.txt
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
PORT = 5000

def derive_key_from_int(shared_int):
    shared_bytes = shared_int.to_bytes((shared_int.bit_length()+7)//8 or 1, 'big')
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"dh-chat")
    return hkdf.derive(shared_bytes)

#def derive_key_from_int(shared_int):
#    shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7)//8 or 1, 'big')
#    # Use first 32 bytes of the raw DH output, padded on the left if needed
#    return shared_bytes.rjust(32, b'\x00')[:32]

def dh_priv(): return int.from_bytes(os.urandom(32), 'big') % (p-2) + 2
def dh_pub(priv): return pow(g, priv, p)
def dh_shared(pub, priv): return pow(pub, priv, p)


def recv_loop(sock, aes):
    """Background thread to receive Bob's messages."""
    try:
        while True:
            msg = recv_obj(sock)
            if not msg:
                print("\n[Connection closed by Bob]")
                break

            if msg.get("type") == "encrypted":
                nonce = base64.b64decode(msg["nonce"])
                ct = base64.b64decode(msg["ct"])

                try:
                    pt = aes.decrypt(nonce, ct, None).decode()
                except Exception as e:
                    print("[Alice] decrypt error:", e)
                    break

                print(f"\n[Bob]: {pt}")
                print("> ", end="", flush=True)

            elif msg.get("type") == "close":
                print("\n[Bob ended chat]")
                break

    except Exception as e:
        print("[Alice recv thread error]", e)


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 alice.py <bob-ip>")
        return

    bob_ip = sys.argv[1]
    s = socket.create_connection((bob_ip, PORT))

    # ---- Diffie–Hellman ----
    a_priv = dh_priv()
    a_pub = dh_pub(a_priv)
    send_obj(s, {"type": "dh_pub", "pub": str(a_pub)})

    m = recv_obj(s)
    if m.get("type") != "dh_pub":
        print("Unexpected:", m)
        return

    b_pub = int(m["pub"])
    shared = dh_shared(b_pub, a_priv)
    key = derive_key_from_int(shared)
    aes = AESGCM(key)

    print("[Alice] Derived key. Start chatting:")
    print("> ", end="", flush=True)

    threading.Thread(target=recv_loop, args=(s, aes), daemon=True).start()

    # ---- Sending loop ----
    try:
        while True:
            line = input("> ")
            if not line:
                continue

            print(f"[Alice]: {line}") 

            nonce = os.urandom(12)
            ct = aes.encrypt(nonce, line.encode(), None)

            send_obj(s, {
                "type": "encrypted",
                "nonce": base64.b64encode(nonce).decode(),
                "ct": base64.b64encode(ct).decode()
            })

    except (KeyboardInterrupt, EOFError):
        send_obj(s, {"type": "close"})

    finally:
        s.close()


if __name__ == "__main__":
    main()