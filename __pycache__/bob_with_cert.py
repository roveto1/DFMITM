# bob.py (with certificate authentication)
import socket, threading, os, base64
from utils import send_obj, recv_obj
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

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

# ---------------------------
# Load Bob's keys + certificates
# ---------------------------
with open("bob.key.pem", "rb") as f:
    bob_priv = serialization.load_pem_private_key(f.read(), password=None)

with open("bob.cert.pem", "rb") as f:
    bob_cert = x509.load_pem_x509_certificate(f.read())

with open("ca.cert.pem", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

ca_public_key = ca_cert.public_key()

# ---------------------------
# Helper functions
# ---------------------------
def derive_key_from_int(shared_int):
   shared_bytes = shared_int.to_bytes((shared_int.bit_length()+7)//8 or 1, "big")
   hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"dh-chat")
   return hkdf.derive(shared_bytes)

# def derive_key_from_int(shared_int):
#     shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7)//8 or 1, 'big')
#     # Use first 32 bytes of the raw DH output, padded on the left if needed
#     return shared_bytes.rjust(32, b'\x00')[:32]

def dh_priv(): return int.from_bytes(os.urandom(32), "big") % (p-2) + 2
def dh_pub(priv): return pow(g, priv, p)
def dh_shared(pub, priv): return pow(pub, priv, p)

# ---------------------------
# Certificate validation
# ---------------------------
def verify_certificate(cert_pem: str):
    cert = x509.load_pem_x509_certificate(cert_pem.encode())

    # Check issuer (CA)
    if cert.issuer != ca_cert.subject:
        raise Exception("Certificate is NOT signed by CA")

    # Verify certificate signature
    ca_public_key.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm
    )

    return cert

# ---------------------------
# Signing DH public key
# ---------------------------
def sign(pub_int):
    data = str(pub_int).encode()
    signature = bob_priv.sign(
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
# Receive loop (unchanged)
# ---------------------------
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
                    print("> ", end="", flush=True)
                    continue

                print(f"\n[Alice]: {pt}")
                print("> ", end="", flush=True)

            elif msg["type"] == "close":
                print("[Alice ended chat]")
                break

    except Exception as e:
        print("[Bob recv thread error]", e)


# ---------------------------
# MAIN with authenticated DH
# ---------------------------
def main():
    s = socket.socket()
    s.bind(("0.0.0.0", PORT))
    s.listen(1)
    print("[Bob] listening on port 5000")

    conn, addr = s.accept()
    print("[Bob] connection from", addr)

    # ---------------------------
    # 1. RECEIVE ALICE'S DH PUB + CERTIFICATE
    # ---------------------------
    msg = recv_obj(conn)
    if msg.get("type") != "dh_pub":
        print("[Bob] Unexpected message:", msg)
        conn.close()
        return

    a_pub = int(msg["pub"])

    # ---- Verify Alice's certificate ----
    alice_cert = verify_certificate(msg["cert"])

    # ---- Verify Alice's signature over her DH public key ----
    verify_signature(a_pub, msg["signature"], alice_cert)

    print("[Bob] Alice authenticated successfully.")

    # ---------------------------
    # 2. SEND BOB'S DH PUB + CERTIFICATE
    # ---------------------------
    b_priv = dh_priv()
    b_pub = dh_pub(b_priv)

    b_signature = sign(b_pub)

    send_obj(conn, {
        "type": "dh_pub",
        "pub": str(b_pub),
        "cert": bob_cert.public_bytes(serialization.Encoding.PEM).decode(),
        "signature": b_signature
    })

    # ---------------------------
    # 3. DERIVE SHARED KEY
    # ---------------------------
    shared = dh_shared(a_pub, b_priv)
    key = derive_key_from_int(shared)
    aes = AESGCM(key)

    print("[Bob] Secure key established. Start chatting.")

    threading.Thread(target=recv_loop, args=(conn, aes), daemon=True).start()

    # ---------------------------
    # 4. Sending loop
    # ---------------------------
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
