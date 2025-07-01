import socket
import base64
from datetime import datetime
from Crypto.Cipher import DES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

def pad(block):
    return block + b' ' * (8 - len(block) % 8)

HOST = "192.168.0.109"  # Đổi IP nếu cần
PORT = 6000

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(b"Hello!")
    if s.recv(1024) == b"Ready!":
        print("[Sender] Handshake OK")

        # 1. Tạo session key
        session_key = get_random_bytes(8)  # 8 bytes cho DES
        pubkey = RSA.import_key(open("public.pem", "rb").read())
        encrypted_key = PKCS1_v1_5.new(pubkey).encrypt(session_key)

        # 2. Tạo metadata
        metadata = f"filename=assignment.txt;timestamp={datetime.now()}"
        hash_metadata = SHA512.new(metadata.encode())
        signature = pkcs1_15.new(pubkey).sign(hash_metadata)

        # 3. Gửi session
        session_msg = (
            base64.b64encode(encrypted_key).decode() +
            "||" +
            metadata +
            "||" +
            base64.b64encode(signature).decode()
        )
        print("[Sender] DEBUG session:", session_msg)
        s.sendall(session_msg.encode() + b"<END>")
        print("[Sender] Session sent.")

        # 4. Đọc file, chia block, mã hóa
        with open("assignment.txt", "rb") as f:
            data = f.read()

        cipher = DES.new(session_key, DES.MODE_ECB)
        blocks = [pad(data[i:i+8]) for i in range(0, len(data), 8)]
        privkey = RSA.import_key(open("private.pem", "rb").read())

        for idx, block in enumerate(blocks):
            ct = cipher.encrypt(block)
            h = SHA512.new(ct)
            sig = pkcs1_15.new(privkey).sign(h)

            msg = (
                str(idx) + "||" +
                base64.b64encode(ct).decode() + "||" +
                h.hexdigest() + "||" +
                base64.b64encode(sig).decode()
            )
            s.sendall(msg.encode() + b"<END>")
            ack = s.recv(1024).decode()
            print(f"[Sender] Part {idx}: {ack}")
