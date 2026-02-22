from src.classical.caesar import encrypt, decrypt, brute_force

msg = "ATTACK AT DAWN"
shift = 3

ct = encrypt(msg, shift)
pt = decrypt(ct, shift)
brute = brute_force(ct)

print("Encrypted:", ct)
print("Decrypted:", pt)
print("Brute Force Results:")
for k, v in brute.items():
    print(f"{k}: {v}")
