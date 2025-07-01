import socket
import base64
from Crypto.Cipher import DES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

def recv_until(conn, delimiter=b"<END>"):
    buffer = b""
    while delimiter not in buffer:
        part = conn.recv(1024)
        if not part:
            break
        buffer += part
    return buffer.replace(delimiter, b"")

HOST = "0.0.0.0"
PORT = 6000

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print("[Receiver] Đang đợi kết nối...")

    conn, addr = s.accept()
    with conn:
        print(f"[Receiver] Kết nối từ {addr}")
        if conn.recv(1024) == b"Hello!":
            conn.sendall(b"Ready!")
            print("[Receiver] Handshake OK")

        print("[Receiver] Nhận session...")
        session_data = recv_until(conn)
        try:
            session_text = session_data.decode()
            print("[Receiver] DEBUG session text:", session_text)
            enc_b64, metadata, sig_b64 = session_text.split("||")
            encrypted_key = base64.b64decode(enc_b64)
            signature = base64.b64decode(sig_b64)

            privkey = RSA.import_key(open("private.pem", "rb").read())
            session_key = PKCS1_v1_5.new(privkey).decrypt(encrypted_key, None)

            h = SHA512.new(metadata.encode())
            pkcs1_15.new(privkey.publickey()).verify(h, signature)

            print("[Receiver] ✅ Session hợp lệ.")
        except Exception as e:
            print("❌ Session lỗi:", e)
            exit()

        cipher = DES.new(session_key, DES.MODE_ECB)
        parts = {}

        while True:
            try:
                data = recv_until(conn)
                if not data:
                    break
                text = data.decode()
                idx_str, ct_b64, hash_recv, sig_b64 = text.split("||")

                idx = int(idx_str)
                ct = base64.b64decode(ct_b64)
                sig = base64.b64decode(sig_b64)

                h = SHA512.new(ct)
                pkcs1_15.new(privkey.publickey()).verify(h, sig)

                if h.hexdigest() != hash_recv:
                    print(f"❌ Part {idx} sai hash.")
                    conn.sendall(b"NACK")
                    continue

                plain = cipher.decrypt(ct).rstrip(b' ')
                parts[idx] = plain
                conn.sendall(b"ACK")
                print(f"[Receiver] ✅ Nhận part {idx}")
            except Exception as e:
                print("❌ Lỗi khi nhận part:", e)
                break

        with open("reconstructed.txt", "wb") as f:
            for i in sorted(parts):
                f.write(parts[i])
        print("[Receiver] ✅ Đã ghi ra file reconstructed.txt")
