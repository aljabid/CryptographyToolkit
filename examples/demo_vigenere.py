from src.classical.vigenere import encrypt, decrypt, frequency_analysis

msg = "THE EAGLE HAS LANDED"
key = "LEMON"

ct = encrypt(msg, key)
pt = decrypt(ct, key)
freq = frequency_analysis(ct)

print("Message:", msg)
print("Keyword:", key)
print("Ciphertext:", ct)
print("Decrypted:", pt)
print("Frequency Analysis:")
for ch, f in freq.items():
    print(f"{ch}: {f:.2f}")
