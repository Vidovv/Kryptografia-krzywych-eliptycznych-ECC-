from fastapi.testclient import TestClient
from api import app
from key_generator import generate_keys

client = TestClient(app)

def test_api_generate_and_verify_keys():
    res = client.post("/keys/generate", json={"password": "secret123"})
    assert res.status_code == 200
    payload = res.json()
    assert "private_key_pem" in payload
    assert "public_key_pem" in payload

    verify_res = client.post("/keys/verify", json={
        "private_key_pem": payload["private_key_pem"],
        "public_key_pem": payload["public_key_pem"],
        "password": "secret123",
    })
    assert verify_res.status_code == 200
    assert verify_res.json()["valid"] is True