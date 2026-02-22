"""
Playfair Cipher Implementation

This module provides functions to encrypt and decrypt text using
the classical Playfair cipher technique.

The Playfair cipher uses a 5x5 matrix of letters constructed from
a keyword. Plaintext is split into digraphs (pairs of letters),
and each pair is encrypted according to specific rules based on
their positions in the matrix.
"""

import string

ALPHABET = string.ascii_uppercase.replace("J", "")  # 25 letters (I/J combined)


def _normalize(text: str) -> str:
    """
    Normalize input text by converting to uppercase and removing
    non-alphabetic characters. Replace J with I.

    Parameters:
        text (str): The input string.

    Returns:
        str: A cleaned string containing only uppercase alphabetic characters.
    """
    return ''.join(ch for ch in text.upper() if ch in string.ascii_uppercase).replace("J", "I")


def _create_matrix(key: str) -> list[list[str]]:
    """
    Create a 5x5 Playfair matrix from the given key.

    Parameters:
        key (str): The keyword used to build the matrix.

    Returns:
        list[list[str]]: A 5x5 matrix of letters.
    """
    key = _normalize(key)
    seen = set()
    matrix_list = []

    for ch in key + ALPHABET:
        if ch not in seen:
            seen.add(ch)
            matrix_list.append(ch)

    # Build 5x5 matrix
    return [matrix_list[i:i+5] for i in range(0, 25, 5)]


def _find_position(matrix: list[list[str]], ch: str) -> tuple[int, int]:
    """Find row and column of a character in the matrix."""
    for r, row in enumerate(matrix):
        if ch in row:
            return r, row.index(ch)
    raise ValueError(f"Character {ch} not found in matrix")


def _process_digraphs(text: str) -> list[str]:
    """
    Split text into digraphs (pairs of letters).
    Insert X between duplicate letters in a pair.
    Pad with X if odd length.
    """
    text = _normalize(text)
    digraphs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else "X"
        if a == b:
            digraphs.append(a + "X")
            i += 1
        else:
            digraphs.append(a + b)
            i += 2
    if len(digraphs[-1]) == 1:
        digraphs[-1] += "X"
    return digraphs


def encrypt(text: str, key: str) -> str:
    """
    Encrypt text using the Playfair cipher.

    Parameters:
        text (str): The plaintext message.
        key (str): The keyword used to build the matrix.

    Returns:
        str: The encrypted ciphertext.
    """
    matrix = _create_matrix(key)
    digraphs = _process_digraphs(text)
    result = []

    for a, b in digraphs:
        r1, c1 = _find_position(matrix, a)
        r2, c2 = _find_position(matrix, b)

        if r1 == r2:  # Same row
            result.append(matrix[r1][(c1+1) % 5])
            result.append(matrix[r2][(c2+1) % 5])
        elif c1 == c2:  # Same column
            result.append(matrix[(r1+1) % 5][c1])
            result.append(matrix[(r2+1) % 5][c2])
        else:  # Rectangle
            result.append(matrix[r1][c2])
            result.append(matrix[r2][c1])

    return ''.join(result)


def decrypt(text: str, key: str) -> str:
    """
    Decrypt text using the Playfair cipher.

    Parameters:
        text (str): The ciphertext message.
        key (str): The keyword used to build the matrix.

    Returns:
        str: The decrypted plaintext.
    """
    matrix = _create_matrix(key)
    digraphs = _process_digraphs(text)
    result = []

    for a, b in digraphs:
        r1, c1 = _find_position(matrix, a)
        r2, c2 = _find_position(matrix, b)

        if r1 == r2:  # Same row
            result.append(matrix[r1][(c1-1) % 5])
            result.append(matrix[r2][(c2-1) % 5])
        elif c1 == c2:  # Same column
            result.append(matrix[(r1-1) % 5][c1])
            result.append(matrix[(r2-1) % 5][c2])
        else:  # Rectangle
            result.append(matrix[r1][c2])
            result.append(matrix[r2][c1])

    return ''.join(result)
