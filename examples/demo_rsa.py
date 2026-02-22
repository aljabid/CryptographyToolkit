from src.modern.rsa import generate_keys, encrypt, decrypt

msg = b"Hello RSA"

# Generate key pair
priv, pub = generate_keys()

# Encrypt with public key
ct = encrypt(msg, pub)

# Decrypt with private key
pt = decrypt(ct, priv)

print("Message:", msg)
print("Ciphertext:", ct)
print("Decrypted:", pt)
print("Roundtrip OK:", pt == msg)
