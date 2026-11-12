import os
import base64
from getpass import getpass
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from ecc_library import curve, ECCPoint

from ecdh import generate_shared_secret, derive_aes_key
from key_generator import load_keys

def encrypt_bytes(data: bytes, public_key, aad=None):

    ephemeral_private = ec.generate_private_key(ec.SECP256K1())
    ephemeral_public = ephemeral_private.public_key()


    shared_secret = generate_shared_secret(
        ephemeral_private, public_key
    )


    salt = os.urandom(16)
    aes_key = derive_aes_key(shared_secret, salt)


    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)

    ciphertext = aesgcm.encrypt(nonce, data, aad)


    ephemeral_bytes = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )


    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "salt": base64.b64encode(salt).decode(),
        "ephemeral_public_key": base64.b64encode(ephemeral_bytes).decode()
    }


def decrypt_bytes(encrypted_data, private_key, aad=None):


    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    nonce = base64.b64decode(encrypted_data["nonce"])
    salt = base64.b64decode(encrypted_data["salt"])

    ephemeral_bytes = base64.b64decode(
        encrypted_data["ephemeral_public_key"]
    )


    ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(), ephemeral_bytes
    )


    shared_secret = generate_shared_secret(
        private_key, ephemeral_public
    )


    aes_key = derive_aes_key(shared_secret, salt)


    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

    return plaintext

def encrypt_message(message, public_key):
    return encrypt_bytes(
        message.encode("utf-8"),
        public_key
    )


def decrypt_message(encrypted_data, private_key):
    plaintext = decrypt_bytes(encrypted_data, private_key)
    return plaintext.decode("utf-8")
