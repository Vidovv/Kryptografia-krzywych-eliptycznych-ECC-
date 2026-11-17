import base64
import binascii

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec

from encryption import encrypt_bytes
from file_format import (
    encrypt_file_data,
    pack_encrypted_file,
    unpack_encrypted_file,
    decrypt_file_data,
)


@pytest.fixture
def key_pair():
    private_key = ec.generate_private_key(ec.SECP256K1())
    return private_key, private_key.public_key()


def test_pack_rejects_invalid_base64(key_pair):
    _, public_key = key_pair
    encrypted_data = encrypt_bytes(b"test", public_key)
    encrypted_data["nonce"] = "not-valid-base64!"

    with pytest.raises((ValueError, binascii.Error)):
        pack_encrypted_file(encrypted_data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("ephemeral_public_key", base64.b64encode(b"\x04" + b"\x00" * 63).decode()),
        ("salt", base64.b64encode(b"short").decode()),
        ("nonce", base64.b64encode(b"short").decode()),
        ("ciphertext", base64.b64encode(b"short").decode()),
    ],
)
def test_pack_rejects_invalid_field_lengths(key_pair, field, value):
    _, public_key = key_pair
    encrypted_data = encrypt_bytes(b"test", public_key)
    encrypted_data[field] = value

    with pytest.raises(ValueError):
        pack_encrypted_file(encrypted_data)


def test_unpack_rejects_invalid_ephemeral_key_prefix(key_pair):
    _, public_key = key_pair
    packed = bytearray(encrypt_file_data(b"test", public_key))

    # Nagłówek ma 5 bajtów, a efemeryczny klucz zaczyna się na pozycji 5.
    packed[5] = 0

    with pytest.raises(ValueError):
        unpack_encrypted_file(bytes(packed))


def test_file_format_detects_modified_ciphertext(key_pair):
    private_key, public_key = key_pair
    packed = bytearray(encrypt_file_data(b"important data", public_key))

    packed[-1] ^= 1

    with pytest.raises(InvalidTag):
        decrypt_file_data(bytes(packed), private_key)