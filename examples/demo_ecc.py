from src.modern.ecc import generate_keys, derive_shared_key, encrypt_with_shared, decrypt_with_shared

msg = b"Hello ECC"

# Alice and Bob generate keys
alice_priv, alice_pub = generate_keys()
bob_priv, bob_pub = generate_keys()

# Derive shared keys
alice_key = derive_shared_key(alice_priv, bob_pub)
bob_key = derive_shared_key(bob_priv, alice_pub)

# Encrypt with Alice's key, decrypt with Bob's key
ct = encrypt_with_shared(msg, alice_key)
pt = decrypt_with_shared(ct, bob_key)

print("Shared keys equal:", alice_key == bob_key)
print("Ciphertext:", ct)
print("Decrypted:", pt)
