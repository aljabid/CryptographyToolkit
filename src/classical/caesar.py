"""
Caesar Cipher Implementation

This module provides functions to encrypt and decrypt text using
the classical Caesar cipher technique. It also includes a brute-force
method to try all possible shifts.

The Caesar cipher is a substitution cipher where each letter in the
plaintext is shifted by a fixed number of positions in the alphabet.
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


def encrypt(text: str, shift: int) -> str:
    """
    Encrypt text using the Caesar cipher with a given shift.

    Parameters:
        text (str): The plaintext message to encrypt.
        shift (int): The number of positions to shift each letter.

    Returns:
        str: The encrypted ciphertext.
    """
    text = _normalize(text)
    return ''.join(ALPHABET[(ALPHABET.index(ch) + shift) % 26] for ch in text)


def decrypt(text: str, shift: int) -> str:
    """
    Decrypt text using the Caesar cipher with a given shift.

    Parameters:
        text (str): The ciphertext message to decrypt.
        shift (int): The number of positions used during encryption.

    Returns:
        str: The decrypted plaintext.
    """
    text = _normalize(text)
    return ''.join(ALPHABET[(ALPHABET.index(ch) - shift) % 26] for ch in text)


def brute_force(ciphertext: str) -> dict:
    """
    Attempt to decrypt a ciphertext by trying all 26 possible shifts.

    Parameters:
        ciphertext (str): The encrypted message.

    Returns:
        dict: A dictionary mapping each shift value (0–25) to its
              corresponding decrypted plaintext.
    """
    text = _normalize(ciphertext)
    return {shift: decrypt(text, shift) for shift in range(26)}
