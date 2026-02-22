"""
Elliptic Curve Cryptography (ECC) Implementation

This module provides functions to generate ECC key pairs, serialize
keys to PEM format, derive shared symmetric keys using ECDH and HKDF,
and perform symmetric encryption/decryption with AES.

ECC is an asymmetric cryptographic technique based on elliptic curves.
It provides strong security with smaller key sizes compared to RSA.
Here, the SECP256R1 curve is used for key generation, and HKDF with
SHA-256 is used for deriving a shared symmetric key.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# -------------------------------
# Key generation and serialization
# -------------------------------

def generate_keys():
    """
    Generate an ECC private and public key pair using the SECP256R1 curve.

    Returns:
        tuple: (private_key, public_key) objects.

    Notes:
        - SECP256R1 (also known as prime256v1) is widely used and considered secure.
        - The private key must be kept secret, while the public key can be shared.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_private(private_key):
    """
    Export an ECC private key in PEM format.

    Parameters:
        private_key: The ECC private key object.

    Returns:
        bytes: The private key encoded in PEM format.
    """
    return private_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption()
    )


def serialize_public(public_key):
    """
    Export an ECC public key in PEM format.

    Parameters:
        public_key: The ECC public key object.

    Returns:
        bytes: The public key encoded in PEM format.
    """
    return public_key.public_bytes(
        Encoding.PEM,
        PublicFormat.SubjectPublicKeyInfo
    )

# -------------------------------
# Shared key derivation
# -------------------------------

def derive_shared_key(private_key, peer_public_key):
    """
    Derive a shared symmetric key using ECDH (Elliptic Curve Diffie-Hellman)
    and HKDF (HMAC-based Key Derivation Function).

    Parameters:
        private_key: Our ECC private key.
        peer_public_key: The peer’s ECC public key.

    Returns:
        bytes: A 32-byte symmetric key derived from the shared secret.

    Notes:
        - This key can be used for symmetric encryption (e.g., AES).
        - HKDF ensures the derived key is uniformly random and secure.
    """
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecc-demo'
    ).derive(shared_secret)

# -------------------------------
# Symmetric encryption/decryption
# -------------------------------

def encrypt_with_shared(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext using AES with a shared symmetric key.

    Parameters:
        plaintext (bytes): The data to encrypt.
        key (bytes): A 32-byte symmetric key derived from ECDH.

    Returns:
        bytes: The encrypted ciphertext.

    Notes:
        - ECB mode is used here for demonstration purposes only.
        - For real-world applications, use CBC or GCM mode for stronger security.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, AES.block_size))


def decrypt_with_shared(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt ciphertext using AES with a shared symmetric key.

    Parameters:
        ciphertext (bytes): The data to decrypt.
        key (bytes): A 32-byte symmetric key derived from ECDH.

    Returns:
        bytes: The decrypted plaintext.

    Notes:
        - ECB mode is insecure for real-world use.
        - Ciphertext is unpadded after decryption.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)
