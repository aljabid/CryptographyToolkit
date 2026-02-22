# test/test_classical.py
import numpy as np
import pytest

from src.classical.caesar import encrypt as caesar_encrypt, decrypt as caesar_decrypt, brute_force
from src.classical.vigenere import encrypt as vigenere_encrypt, decrypt as vigenere_decrypt
from src.classical.playfair import encrypt as playfair_encrypt, decrypt as playfair_decrypt
from src.classical.hill import encrypt as hill_encrypt, decrypt as hill_decrypt

def test_caesar():
    msg = "HELLO"
    ct = caesar_encrypt(msg, 3)
    assert ct == "KHOOR"
    pt = caesar_decrypt(ct, 3)
    assert pt == "HELLO"
    bf = brute_force(ct)
    assert "HELLO" in bf.values()

def test_vigenere():
    msg = "ATTACKATDAWN"
    key = "LEMON"
    ct = vigenere_encrypt(msg, key)
    assert ct == "LXFOPVEFRNHR"
    pt = vigenere_decrypt(ct, key)
    assert pt == msg

def test_playfair():
    msg = "HIDE THE GOLD"
    key = "PLAYFAIR EXAMPLE"
    ct = playfair_encrypt(msg, key)
    pt = playfair_decrypt(ct, key)
    # decrypted text should contain original message letters (with I/J merged)
    assert "HIDE" in pt

def test_hill():
    msg = "ACT"
    K = np.array([[6, 24, 1],
                  [13, 16, 10],
                  [20, 17, 15]])
    ct = hill_encrypt(msg, K)
    assert ct == "POH"
    pt = hill_decrypt(ct, K)
    assert pt.startswith("ACT")
