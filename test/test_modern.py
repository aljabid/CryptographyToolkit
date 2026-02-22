import pytest
from Crypto.Random import get_random_bytes

from src.modern.aes import encrypt_ecb, decrypt_ecb, encrypt_cbc, decrypt_cbc
from src.modern.rsa import generate_keys, encrypt as rsa_encrypt, decrypt as rsa_decrypt
from src.modern.ecc import generate_keys as ecc_generate_keys, derive_shared_key, encrypt_with_shared, decrypt_with_shared

def test_aes_ecb():
    msg = b"SecretMessage"
    key = get_random_bytes(16)  # 128-bit AES key
    ct = encrypt_ecb(msg, key)
    pt = decrypt_ecb(ct, key)
    assert pt == msg

def test_aes_cbc():
    msg = b"ConfidentialData"
    key = get_random_bytes(16)  # 128-bit AES key
    ct, iv = encrypt_cbc(msg, key)
    pt = decrypt_cbc(ct, key, iv)
    assert pt == msg

def test_rsa():
    msg = b"HelloRSA"
    priv, pub = generate_keys()
    ct = rsa_encrypt(msg, pub)
    pt = rsa_decrypt(ct, priv)
    assert pt == msg

def test_ecc():
    msg = b"HelloECC"
    alice_priv, alice_pub = ecc_generate_keys()
    bob_priv, bob_pub = ecc_generate_keys()
    alice_key = derive_shared_key(alice_priv, bob_pub)
    bob_key = derive_shared_key(bob_priv, alice_pub)
    assert alice_key == bob_key
    ct = encrypt_with_shared(msg, alice_key)
    pt = decrypt_with_shared(ct, bob_key)
    assert pt == msg
