"""
AES Cipher Implementation

This module provides functions to encrypt and decrypt data using
the Advanced Encryption Standard (AES) in ECB and CBC modes.
It uses the PyCryptodome library for cryptographic operations.

AES is a symmetric block cipher standardized by NIST. It supports
key sizes of 128, 192, or 256 bits (16, 24, or 32 bytes). ECB mode
is insecure for most applications, while CBC mode with a random IV
is recommended for stronger security.
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext using AES in ECB mode.

    Parameters:
        plaintext (bytes): The data to encrypt.
        key (bytes): The AES key (16, 24, or 32 bytes).

    Returns:
        bytes: The encrypted ciphertext.

    Notes:
        - ECB mode is not semantically secure and should only be used
          for educational purposes.
        - Plaintext is padded to match AES block size.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, AES.block_size))


def decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt ciphertext using AES in ECB mode.

    Parameters:
        ciphertext (bytes): The data to decrypt.
        key (bytes): The AES key (16, 24, or 32 bytes).

    Returns:
        bytes: The decrypted plaintext.

    Notes:
        - ECB mode is insecure for real-world use.
        - Ciphertext is unpadded after decryption.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes = None) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext using AES in CBC mode.

    Parameters:
        plaintext (bytes): The data to encrypt.
        key (bytes): The AES key (16, 24, or 32 bytes).
        iv (bytes, optional): Initialization vector (16 bytes).
                              If None, a random IV is generated.

    Returns:
        tuple[bytes, bytes]: A tuple containing (ciphertext, iv).

    Notes:
        - CBC mode is more secure than ECB.
        - Always use a random IV for each encryption.
    """
    iv = iv or get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(pad(plaintext, AES.block_size)), iv


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt ciphertext using AES in CBC mode.

    Parameters:
        ciphertext (bytes): The data to decrypt.
        key (bytes): The AES key (16, 24, or 32 bytes).
        iv (bytes): The initialization vector (16 bytes).

    Returns:
        bytes: The decrypted plaintext.

    Notes:
        - CBC mode requires the same IV used during encryption.
        - Ciphertext is unpadded after decryption.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)
