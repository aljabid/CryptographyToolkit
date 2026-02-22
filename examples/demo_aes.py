from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

msg = b"Confidential message"
key = get_random_bytes(16)  # 128-bit key

# ECB mode
cipher_ecb = AES.new(key, AES.MODE_ECB)
ct_ecb = cipher_ecb.encrypt(pad(msg, AES.block_size))
pt_ecb = unpad(cipher_ecb.decrypt(ct_ecb), AES.block_size)
print("ECB roundtrip ok:", pt_ecb == msg)

# CBC mode
iv = get_random_bytes(16)
cipher_cbc = AES.new(key, AES.MODE_CBC, iv)
ct_cbc = cipher_cbc.encrypt(pad(msg, AES.block_size))
cipher_cbc_dec = AES.new(key, AES.MODE_CBC, iv)
pt_cbc = unpad(cipher_cbc_dec.decrypt(ct_cbc), AES.block_size)
print("CBC roundtrip ok:", pt_cbc == msg)
