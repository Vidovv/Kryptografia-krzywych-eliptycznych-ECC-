from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import secrets
from ecc_library import curve, G, n

def generate_keys():
    d = secrets.randbelow(n - 1) + 1

    Q = curve.multiply(G, d)

    x = Q.x
    y = Q.y

    private_key = ec.derive_private_key(d, ec.SECP256K1())

    public_numbers = ec.EllipticCurvePublicNumbers(
        x, y, ec.SECP256K1()
    )
    public_key = public_numbers.public_key()

    return private_key, public_key, d, x, y

def serialize_keys(private_key, public_key, password):
    if not password:
        raise ValueError("Hasło nie może być puste.")

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        )
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def deserialize_private_key(private_pem, password):
    return serialization.load_pem_private_key(
        private_pem,
        password=password.encode("utf-8")
    )



def deserialize_public_key(public_pem):
    return serialization.load_pem_public_key(public_pem)

def save_keys(private_key, public_key, password):
    private_pem, public_pem = serialize_keys(private_key, public_key, password)

    with open("private_key.pem", "wb") as file:
        file.write(private_pem)

    with open("public_key.pem", "wb") as file:
        file.write(public_pem)


def load_keys(password):
    with open("private_key.pem", "rb") as file:
        private_pem = file.read()

    with open("public_key.pem", "rb") as file:
        public_pem = file.read()

    private_key = deserialize_private_key(private_pem, password)
    public_key = deserialize_public_key(public_pem)

    return private_key, public_key

def verify_keys(private_key, public_key):
    derived_public_key = private_key.public_key()

    original_numbers = public_key.public_numbers()
    derived_numbers = derived_public_key.public_numbers()

    return original_numbers == derived_numbers


if __name__ == "__main__":
    from getpass import getpass

    password = getpass("Podaj hasło do klucza prywatnego: ")
    private_key, public_key = load_keys(password)

    d = private_key.private_numbers().private_value
    public_numbers = public_key.public_numbers()

    print(f"Klucz prywatny d: {d}")
    print(f"Klucz publiczny Q = ({public_numbers.x}, {public_numbers.y})")

    if verify_keys(private_key, public_key):
        print("Klucze są zgodne!")
    else:
        print("Klucze NIE są zgodne!")

    private_key, public_key, d, x, y = generate_keys()

    reference = private_key.public_key().public_numbers()

    print("Czy X jest zgodne?", x == reference.x)
    print("Czy Y jest zgodne?", y == reference.y)
    print("Czy klucze są zgodne?", verify_keys(private_key, public_key))

