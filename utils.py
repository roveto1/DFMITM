# utils.py
import json, struct, socket

def send_obj(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)

def recv_n(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
    return buf

def recv_obj(sock):
    hdr = recv_n(sock, 4)
    (length,) = struct.unpack(">I", hdr)
    data = recv_n(sock, length)
    return json.loads(data.decode())
    
