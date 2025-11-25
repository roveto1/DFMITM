# alice.py (with certificate authentication)
import socket, sys, threading, os, base64
from utils import send_obj, recv_obj
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
g = 2
PORT = 5000

# ---------------------------
# Load certificates and keys
# ---------------------------
with open("alice.key.pem", "rb") as f:
    alice_priv = serialization.load_pem_private_key(f.read(), password=None)

with open("alice.cert.pem", "rb") as f:
    alice_cert = x509.load_pem_x509_certificate(f.read())

with open("ca.cert.pem", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

ca_public_key = ca_cert.public_key()

# ---------------------------
# DH helper functions
# ---------------------------
def derive_key_from_int(shared_int):
    shared_bytes = shared_int.to_bytes((shared_int.bit_length()+7)//8 or 1, 'big')
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"dh-chat")
    return hkdf.derive(shared_bytes)

def dh_priv(): return int.from_bytes(os.urandom(32), 'big') % (p-2) + 2
def dh_pub(priv): return pow(g, priv, p)
def dh_shared(pub, priv): return pow(pub, priv, p)

# ---------------------------
# Certificate validation
# ---------------------------
def verify_certificate(cert_pem: str):
    """Verifies that a certificate is valid and signed by the CA."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())

    # Verify issuer matches CA
    if cert.issuer != ca_cert.subject:
        raise Exception("Certificate NOT signed by CA")

    # Verify signature
    ca_public_key.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm
    )

    return cert


# ---------------------------
# Signing DH pub key
# ---------------------------
def sign(pub_int):
    data = str(pub_int).encode()
    signature = alice_priv.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def verify_signature(pub_int, signature_b64, cert):
    signature = base64.b64decode(signature_b64)
    cert.public_key().verify(
        signature,
        str(pub_int).encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )


# ---------------------------
# Receive loop unchanged
# ---------------------------
def recv_loop(sock, aes):
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


# ---------------------------
# MAIN WITH CERTIFICATE AUTH
# ---------------------------
def main():
    if len(sys.argv) != 2:
        print("Usage: python3 alice.py <bob-ip>")
        return

    bob_ip = sys.argv[1]
    s = socket.create_connection((bob_ip, PORT))

    # ---- Diffie–Hellman + Certification ----
    a_priv = dh_priv()
    a_pub = dh_pub(a_priv)

    # Sign our own DH public key
    a_signature = sign(a_pub)

    # Send Alice's certificate + signature
    send_obj(s, {
        "type": "dh_pub",
        "pub": str(a_pub),
        "cert": alice_cert.public_bytes(serialization.Encoding.PEM).decode(),
        "signature": a_signature
    })

    # ---- Receive Bob's certificate & signature ----
    m = recv_obj(s)
    if m.get("type") != "dh_pub":
        print("Unexpected:", m)
        return

    b_pub = int(m["pub"])

    # Verify Bob's certificate
    bob_cert = verify_certificate(m["cert"])

    # Verify Bob's signature over his DH pub key
    verify_signature(b_pub, m["signature"], bob_cert)

    print("[Alice] Bob authenticated successfully.")

    # Compute shared key
    shared = dh_shared(b_pub, a_priv)
    key = derive_key_from_int(shared)
    aes = AESGCM(key)

    print("[Alice] Derived secure key. Start chatting:")
    print("> ", end="", flush=True)

    threading.Thread(target=recv_loop, args=(s, aes), daemon=True).start()

    # ---- Send encrypted messages ----
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
