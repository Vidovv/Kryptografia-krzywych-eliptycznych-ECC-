from fastapi.testclient import TestClient

from api import app


client = TestClient(app)


def test_generate_keys_rejects_empty_password():
    response = client.post("/keys/generate", json={"password": ""})

    assert response.status_code == 400


def test_verify_keys_rejects_wrong_password():
    generated = client.post(
        "/keys/generate",
        json={"password": "correct-password"},
    )
    assert generated.status_code == 200
    keys = generated.json()

    response = client.post(
        "/keys/verify",
        json={
            "private_key_pem": keys["private_key_pem"],
            "public_key_pem": keys["public_key_pem"],
            "password": "wrong-password",
        },
    )

    assert response.status_code == 400


def test_encrypt_rejects_invalid_public_key():
    response = client.post(
        "/encrypt",
        json={
            "public_key_pem": "not a PEM key",
            "message": "Test",
        },
    )

    assert response.status_code == 400


def test_decrypt_rejects_invalid_private_key():
    response = client.post(
        "/decrypt",
        json={
            "private_key_pem": "not a PEM key",
            "password": "password",
            "encrypted": {
                "ciphertext": "YQ==",
                "nonce": "YQ==",
                "salt": "YQ==",
                "ephemeral_public_key": "YQ==",
            },
        },
    )

    assert response.status_code == 400