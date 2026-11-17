import base64

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec

import file_crypto
from file_crypto import decrypt_file_bytes, encrypt_file_bytes
from file_format import (
    decrypt_file_data,
    encrypt_file_data,
    unpack_encrypted_file,
)


@pytest.fixture
def key_pair():
    private_key = ec.generate_private_key(ec.SECP256K1())
    return private_key, private_key.public_key()


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"zwykly tekst",
        bytes(range(256)),
        b"\x00\xff\x80binary data\x00",
    ],
)
def test_file_bytes_round_trip(content, key_pair):
    private_key, public_key = key_pair

    encrypted = encrypt_file_bytes(content, public_key, "sample.bin")
    filename, decrypted = decrypt_file_bytes(encrypted, private_key)

    assert filename == "sample.bin"
    assert decrypted == content


def test_file_bytes_rejects_modified_ciphertext(key_pair):
    private_key, public_key = key_pair
    encrypted = encrypt_file_bytes(b"secret", public_key, "secret.bin")

    ciphertext = bytearray(base64.b64decode(encrypted["ciphertext"]))
    ciphertext[0] ^= 1
    encrypted["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")

    with pytest.raises(InvalidTag):
        decrypt_file_bytes(encrypted, private_key)


def test_file_bytes_rejects_invalid_base64(key_pair):
    private_key, _ = key_pair
    envelope = {
        "format": "ecc-file-v1",
        "filename": "sample.bin",
        "ciphertext": "not valid base64!",
        "nonce": "AAAAAAAAAAAAAAAA",
        "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
        "ephemeral_public_key": "AAAA",
    }

    with pytest.raises(ValueError, match="Base64"):
        decrypt_file_bytes(envelope, private_key)


def test_file_bytes_rejects_unknown_format(key_pair):
    private_key, _ = key_pair
    envelope = {"format": "unknown"}

    with pytest.raises(ValueError, match="format"):
        decrypt_file_bytes(envelope, private_key)


def test_file_bytes_rejects_files_over_size_limit(key_pair, monkeypatch):
    _, public_key = key_pair
    monkeypatch.setattr(file_crypto, "MAX_FILE_SIZE", 3)

    with pytest.raises(ValueError, match="zbyt duży"):
        encrypt_file_bytes(b"four", public_key, "large.bin")


def test_file_format_round_trip(key_pair):
    private_key, public_key = key_pair
    content = b"\x00file format test\xff"

    encrypted = encrypt_file_data(content, public_key)
    decrypted = decrypt_file_data(encrypted, private_key)

    assert decrypted == content


def test_file_format_rejects_wrong_magic_header(key_pair):
    _, public_key = key_pair
    encrypted = bytearray(encrypt_file_data(b"test", public_key))
    encrypted[0] ^= 1

    with pytest.raises(ValueError, match="formatu"):
        unpack_encrypted_file(bytes(encrypted))


def test_file_format_rejects_unsupported_version(key_pair):
    _, public_key = key_pair
    encrypted = bytearray(encrypt_file_data(b"test", public_key))
    encrypted[4] = 255

    with pytest.raises(ValueError, match="wersja"):
        unpack_encrypted_file(bytes(encrypted))


def test_file_format_rejects_truncated_file():
    with pytest.raises(ValueError, match="krótki"):
        unpack_encrypted_file(b"ECCF")