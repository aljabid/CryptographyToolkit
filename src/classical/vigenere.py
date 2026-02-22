"""
Vigenère Cipher Implementation

This module provides functions to encrypt and decrypt text using
the classical Vigenère cipher technique.

The Vigenère cipher is a polyalphabetic substitution cipher where
each letter in the plaintext is shifted by an amount determined
by a repeating keyword.
"""

import string

ALPHABET = string.ascii_uppercase

def _normalize(text: str) -> str:
    """
    Normalize input text by converting to uppercase and removing
    non-alphabetic characters.

    Parameters:
        text (str): The input string (plaintext or ciphertext).

    Returns:
        str: A cleaned string containing only uppercase alphabetic characters.
    """
    return ''.join(ch for ch in text.upper() if ch in ALPHABET)


def _extend_key(key: str, length: int) -> str:
    """
    Extend or repeat the key to match the length of the text.

    Parameters:
        key (str): The keyword used for encryption/decryption.
        length (int): The length of the text.

    Returns:
        str: The extended key of the same length as the text.
    """
    key = _normalize(key)
    return (key * (length // len(key) + 1))[:length]


def encrypt(text: str, key: str) -> str:
    """
    Encrypt text using the Vigenère cipher with a given key.

    Parameters:
        text (str): The plaintext message to encrypt.
        key (str): The keyword used for encryption.

    Returns:
        str: The encrypted ciphertext.
    """
    text = _normalize(text)
    key = _extend_key(key, len(text))
    return ''.join(
        ALPHABET[(ALPHABET.index(t) + ALPHABET.index(k)) % 26]
        for t, k in zip(text, key)
    )


def decrypt(text: str, key: str) -> str:
    """
    Decrypt text using the Vigenère cipher with a given key.

    Parameters:
        text (str): The ciphertext message to decrypt.
        key (str): The keyword used during encryption.

    Returns:
        str: The decrypted plaintext.
    """
    text = _normalize(text)
    key = _extend_key(key, len(text))
    return ''.join(
        ALPHABET[(ALPHABET.index(t) - ALPHABET.index(k)) % 26]
        for t, k in zip(text, key)
    )
