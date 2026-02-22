"""
Hill Cipher Implementation

This module provides functions to encrypt and decrypt text using
the classical Hill cipher technique.

The Hill cipher is a polygraphic substitution cipher based on
linear algebra. Plaintext is divided into blocks of size n, and
each block is multiplied by an n×n key matrix modulo 26.
"""

import string
import numpy as np

ALPHABET = string.ascii_uppercase

def _normalize(text: str) -> str:
    """
    Normalize input text by converting to uppercase and removing
    non-alphabetic characters.

    Parameters:
        text (str): The input string.

    Returns:
        str: A cleaned string containing only uppercase alphabetic characters.
    """
    return ''.join(ch for ch in text.upper() if ch in ALPHABET)


def _text_to_numbers(text: str) -> np.ndarray:
    """Convert text to numeric array (A=0, B=1, ..., Z=25)."""
    return np.array([ALPHABET.index(ch) for ch in text])


def _numbers_to_text(numbers: np.ndarray) -> str:
    """Convert numeric array back to text."""
    return ''.join(ALPHABET[num % 26] for num in numbers)


def encrypt(text: str, key_matrix: np.ndarray) -> str:
    """
    Encrypt text using the Hill cipher.

    Parameters:
        text (str): The plaintext message.
        key_matrix (np.ndarray): The n×n key matrix.

    Returns:
        str: The encrypted ciphertext.
    """
    text = _normalize(text)
    n = key_matrix.shape[0]

    # Pad text if not divisible by n
    while len(text) % n != 0:
        text += "X"

    numbers = _text_to_numbers(text)
    ciphertext = []

    for i in range(0, len(numbers), n):
        block = numbers[i:i+n]
        encrypted_block = key_matrix.dot(block) % 26
        ciphertext.extend(encrypted_block)

    return _numbers_to_text(np.array(ciphertext))


def decrypt(text: str, key_matrix: np.ndarray) -> str:
    """
    Decrypt text using the Hill cipher.

    Parameters:
        text (str): The ciphertext message.
        key_matrix (np.ndarray): The n×n key matrix used for encryption.

    Returns:
        str: The decrypted plaintext.
    """
    text = _normalize(text)
    n = key_matrix.shape[0]

    numbers = _text_to_numbers(text)

    # Compute modular inverse of key matrix
    det = int(round(np.linalg.det(key_matrix)))
    det_inv = pow(det % 26, -1, 26)  # modular inverse of determinant
    adjugate = np.round(det * np.linalg.inv(key_matrix)).astype(int) % 26
    inv_matrix = (det_inv * adjugate) % 26

    plaintext = []

    for i in range(0, len(numbers), n):
        block = numbers[i:i+n]
        decrypted_block = inv_matrix.dot(block) % 26
        plaintext.extend(decrypted_block)

    return _numbers_to_text(np.array(plaintext))
