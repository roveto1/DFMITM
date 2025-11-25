import socket, threading, os, base64
from utils import send_obj, recv_obj
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
g = 2
PORT = 5000

def derive_key_from_int(shared_int):
    shared_bytes = shared_int.to_bytes((shared_int.bit_length()+7)//8 or 1, "big")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"dh-chat")
    return hkdf.derive(shared_bytes)

def dh_priv(): return int.from_bytes(os.urandom(32), "big") % (p-2) + 2
def dh_pub(priv): return pow(g, priv, p)
def dh_shared(pub, priv): return pow(pub, priv, p)

def recv_loop(conn, aes):
    """Receives messages from Alice."""
    try:
        while True:
            msg = recv_obj(conn)
            if not msg:
                print("[Alice disconnected]")
                break

            if msg["type"] == "encrypted":
                nonce = base64.b64decode(msg["nonce"])
                ct    = base64.b64decode(msg["ct"])

                try:
                    pt = aes.decrypt(nonce, ct, None).decode()
                except:
                    print("[Bob] decrypt error")
                    break

                print(f"\n[Alice]: {pt}")
                print("> ", end="", flush=True)

            elif msg["type"] == "close":
                print("[Alice ended chat]")
                break

    except Exception as e:
        print("[Bob recv thread error]", e)


def main():
    s = socket.socket()
    s.bind(("0.0.0.0", PORT))
    s.listen(1)
    print("[Bob] listening on port 5000")

    conn, addr = s.accept()
    print("[Bob] connection from", addr)

    # ---- DH ----
    b_priv = dh_priv()
    b_pub = dh_pub(b_priv)
    send_obj(conn, {"type": "dh_pub", "pub": str(b_pub)})

    m = recv_obj(conn)
    a_pub = int(m["pub"])

    shared = dh_shared(a_pub, b_priv)
    key = derive_key_from_int(shared)
    aes = AESGCM(key)

    print("[Bob] Key derived. Chat ready.")

    threading.Thread(target=recv_loop, args=(conn, aes), daemon=True).start()

    # ---- Sending loop ----
    try:
        while True:
            line = input("> ")
            if not line:
                continue

            print(f"[Bob]: {line}")

            nonce = os.urandom(12)
            ct = aes.encrypt(nonce, line.encode(), None)

            send_obj(conn, {
                "type": "encrypted",
                "nonce": base64.b64encode(nonce).decode(),
                "ct": base64.b64encode(ct).decode()
            })

    except (KeyboardInterrupt, EOFError):
        send_obj(conn, {"type": "close"})

    finally:
        conn.close()
        s.close()


if __name__ == "__main__":
    main()