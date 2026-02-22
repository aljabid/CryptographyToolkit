"""
RSA Cipher Implementation (PyCryptodome)

This module provides functions to generate RSA key pairs and to
encrypt/decrypt data using RSA with OAEP padding.
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# -------------------------------
# Key generation
# -------------------------------

def generate_keys(bits: int = 2048):
    """
    Generate an RSA key pair.

    Parameters:
        bits (int): Key size in bits (default 2048).

    Returns:
        tuple: (private_key, public_key) as RSA key objects.
    """
    key = RSA.generate(bits)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

# -------------------------------
# Encryption / Decryption
# -------------------------------

def encrypt(plaintext: bytes, public_key) -> bytes:
    """
    Encrypt plaintext using an RSA public key with OAEP padding.

    Parameters:
        plaintext (bytes): The data to encrypt.
        public_key: The RSA public key object.

    Returns:
        bytes: The encrypted ciphertext.
    """
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plaintext)


def decrypt(ciphertext: bytes, private_key) -> bytes:
    """
    Decrypt ciphertext using an RSA private key with OAEP padding.

    Parameters:
        ciphertext (bytes): The data to decrypt.
        private_key: The RSA private key object.

    Returns:
        bytes: The decrypted plaintext.
    """
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)
