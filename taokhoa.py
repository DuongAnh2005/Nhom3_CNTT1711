# generate_keys.py
from Crypto.PublicKey import RSA

key = RSA.generate(1024)
private_key = key.export_key()
public_key = key.publickey().export_key()

with open("private.pem", "wb") as f:
    f.write(private_key)

with open("public.pem", "wb") as f:
    f.write(public_key)

print("Khóa đã được tạo.")
