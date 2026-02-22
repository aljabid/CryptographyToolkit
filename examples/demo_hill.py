
import numpy as np
from src.classical.hill import encrypt, decrypt

def main():
    msg = "ACT"
    # Classic invertible key matrix (determinant = 441, coprime with 26)
    K = np.array([[6, 24, 1],
                  [13, 16, 10],
                  [20, 17, 15]])

    print("Message:", msg)

    # Encrypt
    ct = encrypt(msg, K)
    print("Ciphertext:", ct)

    # Decrypt
    pt = decrypt(ct, K)
    print("Decrypted:", pt)

if __name__ == "__main__":
    main()


'''
import numpy as np
from src.classical.hill import encrypt, decrypt

msg = "ACT"
# Classic invertible key matrix
K = np.array([[6, 24, 1],
              [13, 16, 10],
              [20, 17, 15]])

ct = encrypt(msg, K)
pt = decrypt(ct, K)

print("Message:", msg)
print("Ciphertext:", ct)
print("Decrypted:", pt)
'''
# examples/demo_hill.py

