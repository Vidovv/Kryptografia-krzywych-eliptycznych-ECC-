import io
import zipfile

from fastapi.testclient import TestClient

from api import app
from key_generator import generate_keys, serialize_keys


client = TestClient(app)


def make_key_pems(password="test-password"):
    private_key, public_key, *_ = generate_keys()
    private_pem, public_pem = serialize_keys(
        private_key,
        public_key,
        password,
    )
    return private_pem.decode("utf-8"), public_pem.decode("utf-8")


def test_json_file_api_round_trip():
    password = "test-password"
    private_pem, public_pem = make_key_pems(password)
    content = b"\x00binary file data\xff"

    encrypt_response = client.post(
        "/api/files/encrypt",
        json={
            "public_key_pem": public_pem,
            "filename": "sample.bin",
            "file_base64": "AGJpbmFyeSBmaWxlIGRhdGH/",
        },
    )

    assert encrypt_response.status_code == 200
    encrypted = encrypt_response.json()

    decrypt_response = client.post(
        "/api/files/decrypt",
        json={
            "private_key_pem": private_pem,
            "password": password,
            "encrypted": encrypted,
        },
    )

    assert decrypt_response.status_code == 200
    result = decrypt_response.json()
    assert result["filename"] == "sample.bin"
    assert result["file_base64"] == "AGJpbmFyeSBmaWxlIGRhdGH/"


def test_json_file_api_rejects_invalid_base64():
    _, public_pem = make_key_pems()

    response = client.post(
        "/api/files/encrypt",
        json={
            "public_key_pem": public_pem,
            "filename": "sample.bin",
            "file_base64": "not valid base64!",
        },
    )

    assert response.status_code == 400


def test_upload_file_api_round_trip():
    password = "test-password"
    private_pem, public_pem = make_key_pems(password)
    content = b"\x00uploaded file\xff"

    encrypt_response = client.post(
        "/files/encrypt",
        data={"public_key_pem": public_pem},
        files={"file": ("sample.bin", content, "application/octet-stream")},
    )

    assert encrypt_response.status_code == 200

    decrypt_response = client.post(
        "/files/decrypt",
        data={
            "private_key_pem": private_pem,
            "password": password,
        },
        files={
            "file": (
                "sample.bin.ecc",
                encrypt_response.content,
                "application/octet-stream",
            )
        },
    )

    assert decrypt_response.status_code == 200
    assert decrypt_response.content == content


def test_upload_file_api_rejects_invalid_encrypted_file():
    password = "test-password"
    private_pem, _ = make_key_pems(password)

    response = client.post(
        "/files/decrypt",
        data={
            "private_key_pem": private_pem,
            "password": password,
        },
        files={"file": ("broken.ecc", b"not an ECC file", "application/octet-stream")},
    )

    assert response.status_code == 400


def test_export_keys_returns_zip_with_both_pem_files():
    private_pem, public_pem = make_key_pems()

    response = client.post(
        "/keys/export",
        json={
            "private_key": private_pem,
            "public_key": public_pem,
        },
    )

    assert response.status_code == 200

    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert set(archive.namelist()) == {"private_key.pem", "public_key.pem"}
        assert archive.read("private_key.pem").decode("utf-8") == private_pem
        assert archive.read("public_key.pem").decode("utf-8") == public_pem


def test_export_keys_rejects_unencrypted_private_key():
    _, public_pem = make_key_pems()

    response = client.post(
        "/keys/export",
        json={
            "private_key": "-----BEGIN PRIVATE KEY-----\ninvalid\n",
            "public_key": public_pem,
        },
    )

    assert response.status_code == 400


def test_import_keys_accepts_matching_key_pair():
    password = "test-password"
    private_pem, public_pem = make_key_pems(password)

    response = client.post(
        "/keys/import",
        data={"password": password},
        files={
            "private_file": ("private_key.pem", private_pem.encode("utf-8")),
            "public_file": ("public_key.pem", public_pem.encode("utf-8")),
        },
    )

    assert response.status_code == 200
    assert response.json()["private_key"] == private_pem
    assert response.json()["public_key"] == public_pem


def test_import_keys_rejects_wrong_password():
    private_pem, public_pem = make_key_pems("correct-password")

    response = client.post(
        "/keys/import",
        data={"password": "wrong-password"},
        files={
            "private_file": ("private_key.pem", private_pem.encode("utf-8")),
            "public_file": ("public_key.pem", public_pem.encode("utf-8")),
        },
    )

    assert response.status_code == 400


def test_import_keys_rejects_mismatched_pair():
    password = "test-password"
    private_pem, _ = make_key_pems(password)
    _, different_public_pem = make_key_pems(password)

    response = client.post(
        "/keys/import",
        data={"password": password},
        files={
            "private_file": ("private_key.pem", private_pem.encode("utf-8")),
            "public_file": ("public_key.pem", different_public_pem.encode("utf-8")),
        },
    )

    assert response.status_code == 400
    
def test_json_file_api_rejects_wrong_password():
    from key_generator import serialize_keys
    from cryptography.hazmat.primitives.asymmetric import ec

    password = "correct-password"
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()
    private_pem, public_pem = serialize_keys(
        private_key, public_key, password
    )

    encrypted_response = client.post(
        "/api/files/encrypt",
        json={
            "public_key_pem": public_pem.decode("utf-8"),
            "filename": "sample.bin",
            "file_base64": "dGVzdA==",
        },
    )
    assert encrypted_response.status_code == 200

    response = client.post(
        "/api/files/decrypt",
        json={
            "private_key_pem": private_pem.decode("utf-8"),
            "password": "wrong-password",
            "encrypted": encrypted_response.json(),
        },
    )

    assert response.status_code == 400


def test_upload_file_api_rejects_invalid_public_key():
    response = client.post(
        "/files/encrypt",
        data={"public_key_pem": "not a PEM key"},
        files={
            "file": ("sample.bin", b"test content", "application/octet-stream"),
        },
    )

    assert response.status_code == 400