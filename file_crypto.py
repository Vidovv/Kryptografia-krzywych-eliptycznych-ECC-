"""Educational ECC hybrid encryption for arbitrary binary files."""
import base64
import binascii
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ecdh import generate_shared_secret, derive_aes_key

MAX_FILE_SIZE = 15 * 1024 * 1024

def b64(value):
    return base64.b64encode(value).decode('ascii')

def unb64(value):
    if not isinstance(value, str):
        raise ValueError('Nieprawidłowy format danych pliku.')
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError('Nieprawidłowe kodowanie Base64.') from None

def encrypt_file_bytes(content, public_key, filename):
    if len(content) > MAX_FILE_SIZE:
        raise ValueError('Plik jest zbyt duży (maksymalnie 15 MB).')
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256K1):
        raise ValueError('Wymagany klucz publiczny ECC secp256k1.')
    ephemeral_private = ec.generate_private_key(ec.SECP256K1())
    public_bytes = ephemeral_private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    salt = os.urandom(16)
    nonce = os.urandom(12)
    aes_key = derive_aes_key(generate_shared_secret(ephemeral_private, public_key), salt)
    ciphertext = AESGCM(aes_key).encrypt(nonce, content, None)
    return {
        'format': 'ecc-file-v1',
        'filename': filename,
        'ciphertext': b64(ciphertext),
        'nonce': b64(nonce),
        'salt': b64(salt),
        'ephemeral_public_key': b64(public_bytes),
    }

def decrypt_file_bytes(envelope, private_key):
    if envelope.get('format') != 'ecc-file-v1':
        raise ValueError('Nieobsługiwany format zaszyfrowanego pliku.')
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP256K1):
        raise ValueError('Wymagany klucz prywatny ECC secp256k1.')
    ciphertext = unb64(envelope.get('ciphertext'))
    if len(ciphertext) > MAX_FILE_SIZE + 16:
        raise ValueError('Plik jest zbyt duży (maksymalnie 15 MB).')
    nonce = unb64(envelope.get('nonce'))
    salt = unb64(envelope.get('salt'))
    ephemeral_bytes = unb64(envelope.get('ephemeral_public_key'))
    if len(nonce) != 12 or len(salt) != 16:
        raise ValueError('Niepoprawne parametry szyfrowania.')
    ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), ephemeral_bytes)
    aes_key = derive_aes_key(generate_shared_secret(private_key, ephemeral_public), salt)
    content = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
    filename = envelope.get('filename')
    if not isinstance(filename, str) or not filename:
        filename = 'odszyfrowany_plik'
    return filename, content
