from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from key_generator import generate_keys
import os


def generate_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(
        ec.ECDH(),
        peer_public_key
    )
    return shared_secret

def derive_aes_key(shared_secret, salt):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"ECC educational project"
    )

    return hkdf.derive(shared_secret)



if __name__ == "__main__":

    alice_private, alice_public, *_ = generate_keys()
    bob_private, bob_public, *_ = generate_keys()

    alice_secret = generate_shared_secret(
        alice_private,
        bob_public
    )

    bob_secret = generate_shared_secret(
        bob_private,
        alice_public
    )
    salt = os.urandom(16)

    alice_aes_key = derive_aes_key(alice_secret, salt)
    bob_aes_key = derive_aes_key(bob_secret, salt)

    print("Klucz AES Alicji:", alice_aes_key.hex())
    print("Klucz AES Bartka:", bob_aes_key.hex())

    print("Czy klucze AES są zgodne?", alice_aes_key == bob_aes_key)
    print("Długość klucza AES:", len(alice_aes_key), "bajtów")

    print("Sekret Alicji:", alice_secret.hex())
    print("Sekret Bartka:", bob_secret.hex())

    print("Czy sekrety są zgodne?", alice_secret == bob_secret)
