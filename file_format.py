import base64

from encryption import encrypt_bytes, decrypt_bytes

MAGIC = b"ECCF"
VERSION = 1

HEADER = MAGIC + bytes([VERSION])

def pack_encrypted_file(encrypted_data):

    ephemeral = base64.b64decode(
        encrypted_data["ephemeral_public_key"],
        validate=True
    )

    salt = base64.b64decode(
        encrypted_data["salt"],
        validate=True
    )

    nonce = base64.b64decode(
        encrypted_data["nonce"],
        validate=True
    )

    ciphertext = base64.b64decode(
        encrypted_data["ciphertext"],
        validate=True
    )

    if len(ephemeral) != 65 or ephemeral[0] != 4:
        raise ValueError("Nieprawidłowy klucz efemeryczny")

    if len(salt) != 16 or len(nonce) != 12:
        raise ValueError("Nieprawidłowe parametry szyfrowania")

    if len(ciphertext) < 16:
        raise ValueError("Nieprawidłowy szyfrogram")

    return HEADER + ephemeral + salt + nonce + ciphertext

def unpack_encrypted_file(data: bytes):

    if len(data) < 114:
        raise ValueError("Plik ECC jest zbyt krótki")

    if data[:4] != MAGIC:
        raise ValueError("Nieprawidłowy format pliku")

    if data[4] != VERSION:
        raise ValueError("Nieobsługiwana wersja pliku")

    ephemeral = data[5:70]
    salt = data[70:86]
    nonce = data[86:98]
    ciphertext = data[98:]

    if ephemeral[0] != 4:
        raise ValueError("Nieprawidłowy format klucza efemerycznego")

    return {
        "ephemeral_public_key": base64.b64encode(ephemeral).decode(),
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

def unpack_encrypted_file(data: bytes):

    if len(data) < 114:
        raise ValueError("Plik ECC jest zbyt krótki")

    if data[:4] != MAGIC:
        raise ValueError("Nieprawidłowy format pliku")

    if data[4] != VERSION:
        raise ValueError("Nieobsługiwana wersja pliku")

    ephemeral = data[5:70]
    salt = data[70:86]
    nonce = data[86:98]
    ciphertext = data[98:]

    if ephemeral[0] != 4:
        raise ValueError("Nieprawidłowy format klucza efemerycznego")

    return {
        "ephemeral_public_key": base64.b64encode(ephemeral).decode(),
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }
def encrypt_file_data(data: bytes, public_key):
    encrypted = encrypt_bytes(
        data,
        public_key,
        aad=HEADER
    )

    return pack_encrypted_file(encrypted)

def decrypt_file_data(data: bytes, private_key):
    encrypted = unpack_encrypted_file(data)

    return decrypt_bytes(
        encrypted,
        private_key,
        aad=HEADER
    )
