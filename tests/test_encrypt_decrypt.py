import pytest
from encryption import encrypt_message, decrypt_message
from key_generator import generate_keys

def test_tampered_salt_fails():
    private_key, public_key, *_ = generate_keys()
    encrypted = encrypt_message("Test", public_key)

    encrypted["salt"] = encrypted["salt"][:-1] + ("A" if encrypted["salt"][-1] != "A" else "B")

    with pytest.raises(Exception):
        decrypt_message(encrypted, private_key)