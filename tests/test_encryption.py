
import base64

import pytest
from cryptography.exceptions import InvalidTag

from key_generator import generate_keys
from encryption import encrypt_message, decrypt_message



def test_encrypt_decrypt():
    private_key, public_key, *_ = generate_keys()

    message = "Witaj ECC"
    encrypted = encrypt_message(message, public_key)
    decrypted = decrypt_message(encrypted, private_key)

    assert decrypted == message



def test_unicode():
    private_key, public_key, *_ = generate_keys()

    message = "Zażółć gęślą jaźń 🔐"
    encrypted = encrypt_message(message, public_key)
    decrypted = decrypt_message(encrypted, private_key)

    assert decrypted == message


def test_empty_message():
    private_key, public_key, *_ = generate_keys()

    encrypted = encrypt_message("", public_key)
    decrypted = decrypt_message(encrypted, private_key)

    assert decrypted == ""



def test_randomness():
    private_key, public_key, *_ = generate_keys()

    first = encrypt_message("Test", public_key)
    second = encrypt_message("Test", public_key)

    assert first["ciphertext"] != second["ciphertext"]
    assert first["nonce"] != second["nonce"]
    assert first["ephemeral_public_key"] != second["ephemeral_public_key"]



def test_wrong_private_key():
    private_key, public_key, *_ = generate_keys()
    wrong_private, _, *_ = generate_keys()

    encrypted = encrypt_message("Tajna wiadomość", public_key)

    with pytest.raises(InvalidTag):
        decrypt_message(encrypted, wrong_private)



def test_modified_ciphertext():
    private_key, public_key, *_ = generate_keys()

    encrypted = encrypt_message("Test", public_key)

    data = bytearray(base64.b64decode(encrypted["ciphertext"]))
    data[0] ^= 1

    encrypted["ciphertext"] = base64.b64encode(data).decode()

    with pytest.raises(InvalidTag):
        decrypt_message(encrypted, private_key)



def test_modified_nonce():
    private_key, public_key, *_ = generate_keys()

    encrypted = encrypt_message("Test", public_key)

    nonce = bytearray(base64.b64decode(encrypted["nonce"]))
    nonce[0] ^= 1

    encrypted["nonce"] = base64.b64encode(nonce).decode()

    with pytest.raises(InvalidTag):
        decrypt_message(encrypted, private_key)

