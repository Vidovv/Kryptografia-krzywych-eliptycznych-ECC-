
import pytest

from key_generator import (
    generate_keys,
    save_keys,
    load_keys,
    verify_keys
)

from encryption import encrypt_message, decrypt_message



def test_generated_keys():
    private_key, public_key, *_ = generate_keys()

    assert verify_keys(private_key, public_key)


def test_export_import(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    private_key, public_key, *_ = generate_keys()

    password = "TestoweHaslo123!"

    save_keys(private_key, public_key, password)

    assert (tmp_path / "private_key.pem").exists()
    assert (tmp_path / "public_key.pem").exists()

    loaded_private, loaded_public = load_keys(password)

    assert verify_keys(loaded_private, loaded_public)

    assert (
        private_key.private_numbers().private_value
        == loaded_private.private_numbers().private_value
    )



def test_private_key_encrypted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    private_key, public_key, *_ = generate_keys()

    save_keys(private_key, public_key, "TestoweHaslo123!")

    content = (tmp_path / "private_key.pem").read_bytes()

    assert b"BEGIN ENCRYPTED PRIVATE KEY" in content
    assert b"BEGIN PRIVATE KEY-----" not in content



def test_wrong_password(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    private_key, public_key, *_ = generate_keys()

    save_keys(private_key, public_key, "PoprawneHaslo123!")

    with pytest.raises((ValueError, TypeError)):
        load_keys("BledneHaslo123!")



def test_empty_password(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    private_key, public_key, *_ = generate_keys()

    with pytest.raises(ValueError):
        save_keys(private_key, public_key, "")


# TEST 13: Nieistniejące pliki PEM
def test_missing_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(FileNotFoundError):
        load_keys("TestoweHaslo123!")



def test_encryption_after_import(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    private_key, public_key, *_ = generate_keys()

    password = "TestoweHaslo123!"

    save_keys(private_key, public_key, password)


    loaded_private, loaded_public = load_keys(password)

    message = "Wiadomość po ponownym imporcie ECC"

    encrypted = encrypt_message(message, loaded_public)
    decrypted = decrypt_message(encrypted, loaded_private)

    assert decrypted == message

