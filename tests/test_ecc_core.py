from cryptography.hazmat.primitives.asymmetric import ec
from key_generator import generate_keys, verify_keys
from ecdh import generate_shared_secret, derive_aes_key
from ecc_library import curve, G, ECCPoint

def test_generate_keys_private_value_in_range():
    private_key, public_key, d, x, y = generate_keys()
    assert 1 <= d < 115792089237316195423570985008687907852837564279074904382605163141518161494337
    assert x is not None and y is not None
    assert verify_keys(private_key, public_key)

def test_ecdh_shared_secret_matches_for_both_sides():
    alice_private, alice_public, *_ = generate_keys()
    bob_private, bob_public, *_ = generate_keys()

    alice_secret = generate_shared_secret(alice_private, bob_public)
    bob_secret = generate_shared_secret(bob_private, alice_public)

    assert alice_secret == bob_secret

def test_derive_aes_key_is_32_bytes_and_stable():
    alice_private, alice_public, *_ = generate_keys()
    bob_private, bob_public, *_ = generate_keys()

    secret_a = generate_shared_secret(alice_private, bob_public)
    secret_b = generate_shared_secret(bob_private, alice_public)

    salt = b"1234567890abcdef"

    key_a = derive_aes_key(secret_a, salt)
    key_b = derive_aes_key(secret_b, salt)

    assert len(key_a) == 32
    assert key_a == key_b