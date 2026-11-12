import base64

import pytest
from cryptography.exceptions import InvalidTag

from encryption import decrypt_message, encrypt_message
from key_generator import generate_keys


def test_tampered_salt_fails_decryption():
    private_key, public_key, *_ = generate_keys()
    encrypted = encrypt_message("Test", public_key)

    salt = bytearray(base64.b64decode(encrypted["salt"]))
    salt[0] ^= 1
    encrypted["salt"] = base64.b64encode(salt).decode("ascii")

    with pytest.raises(InvalidTag):
        decrypt_message(encrypted, private_key)


def test_missing_payload_field_raises_key_error():
    private_key, public_key, *_ = generate_keys()
    encrypted = encrypt_message("Test", public_key)
    del encrypted["salt"]

    with pytest.raises(KeyError):
        decrypt_message(encrypted, private_key)


def test_invalid_ephemeral_public_key_raises_value_error():
    private_key, public_key, *_ = generate_keys()
    encrypted = encrypt_message("Test", public_key)
    encrypted["ephemeral_public_key"] = base64.b64encode(b"invalid").decode("ascii")

    with pytest.raises(ValueError):
        decrypt_message(encrypted, private_key)


def test_invalid_nonce_length_raises_value_error():
    private_key, public_key, *_ = generate_keys()
    encrypted = encrypt_message("Test", public_key)
    encrypted["nonce"] = base64.b64encode(b"short").decode("ascii")

    with pytest.raises(ValueError):
        decrypt_message(encrypted, private_key)