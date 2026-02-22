from src.classical.playfair import encrypt, decrypt

msg = "HIDE THE GOLD IN THE TREE STUMP"
key = "PLAYFAIR EXAMPLE"

ct = encrypt(msg, key)
pt = decrypt(ct, key)

print("Message:", msg)
print("Ciphertext:", ct)
print("Decrypted:", pt)
