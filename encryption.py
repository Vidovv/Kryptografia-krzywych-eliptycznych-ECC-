import os
import base64
from getpass import getpass
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

from ecdh import generate_shared_secret, derive_aes_key
from key_generator import load_keys


def encrypt_message(message, public_key):
    
    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public = ephemeral_private.public_key()

    
    shared_secret = generate_shared_secret(
        ephemeral_private, public_key
    )

    
    salt = os.urandom(16)
    aes_key = derive_aes_key(shared_secret, salt)

    
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(
        nonce, message.encode("utf-8"), None
    )

   
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


def decrypt_message(encrypted_data, private_key):

    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    nonce = base64.b64decode(encrypted_data["nonce"])
    salt = base64.b64decode(encrypted_data["salt"])
    ephemeral_bytes = base64.b64decode(
        encrypted_data["ephemeral_public_key"]
    )


    ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), ephemeral_bytes
    )


    shared_secret = generate_shared_secret(
        private_key, ephemeral_public
    )


    aes_key = derive_aes_key(shared_secret, salt)


    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext.decode("utf-8")


if __name__ == "__main__":
    password = getpass("Podaj hasło do klucza prywatnego: ")

    try:
        private_key, public_key = load_keys(password)

        message = input("Podaj wiadomość do zaszyfrowania: ")

        encrypted = encrypt_message(message, public_key)

        print("\nZaszyfrowane dane:")
        for name, value in encrypted.items():
            print(f"{name}: {value}")

        decrypted = decrypt_message(encrypted, private_key)
        print("\nOdszyfrowana wiadomość:", decrypted)

    except (ValueError, TypeError, OSError) as error:
        print(f"Błąd wczytywania lub przetwarzania danych: {error}")
