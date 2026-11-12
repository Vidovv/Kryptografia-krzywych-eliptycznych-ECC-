from fastapi import FastAPI, HTTPException
from cryptography.exceptions import InvalidTag
from pydantic import BaseModel
from key_generator import (
    generate_keys,
    serialize_keys,
    deserialize_private_key,
    deserialize_public_key,
    verify_keys,
)
from encryption import encrypt_message, decrypt_message
import io
import zipfile
from fastapi import UploadFile, File, Form
from fastapi.responses import StreamingResponse
from cryptography.exceptions import InvalidTag
from file_format import encrypt_file_data, decrypt_file_data

app = FastAPI(title="SeminariaProjekt API")
class ExportKeysRequest(BaseModel):
    private_key: str
    public_key: str
class GenerateKeysRequest(BaseModel):
    password: str

class KeysResponse(BaseModel):
    private_key_pem: str
    public_key_pem: str

class VerifyKeysRequest(BaseModel):
    private_key_pem: str
    public_key_pem: str
    password: str

class VerifyKeysResponse(BaseModel):
    valid: bool

class EncryptRequest(BaseModel):
    public_key_pem: str
    message: str

class EncryptedData(BaseModel):
    ciphertext: str
    nonce: str
    salt: str
    ephemeral_public_key: str

class DecryptRequest(BaseModel):
    private_key_pem: str
    password: str
    encrypted: EncryptedData

class DecryptResponse(BaseModel):
    message: str

    @app.post("/files/encrypt")
    async def encrypt_file(
            file: UploadFile = File(...),
            public_key_pem: str = Form(...)
    ):
        try:

            public_key = deserialize_public_key(
                public_key_pem.encode("utf-8")
            )


            data = await file.read()


            encrypted = encrypt_file_data(data, public_key)

            filename = (file.filename or "plik") + ".ecc"


            return StreamingResponse(
                io.BytesIO(encrypted),
                media_type="application/octet-stream",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Cache-Control": "no-store"
                }
            )

        except (ValueError, TypeError):
            raise HTTPException(
                status_code=400,
                detail="Nieprawidłowy klucz publiczny lub dane."
            )


@app.post("/files/decrypt")
async def decrypt_file(
    file: UploadFile = File(...),
    private_key_pem: str = Form(...),
    password: str = Form(...)
):
    try:

        private_key = deserialize_private_key(
            private_key_pem.encode("utf-8"),
            password
        )


        data = await file.read()


        decrypted = decrypt_file_data(data, private_key)

        filename = file.filename or "plik.ecc"

        if filename.endswith(".ecc"):
            filename = filename[:-4]

        return StreamingResponse(
            io.BytesIO(decrypted),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "no-store"
            }
        )

    except (InvalidTag, ValueError, TypeError, KeyError):
        raise HTTPException(
            status_code=400,
            detail="Nie udało się odszyfrować pliku."
        )


@app.post("/keys/export")
def export_keys(request: ExportKeysRequest):

    print("Czy nagłówek jest poprawny:",
          request.private_key.strip().startswith(
              "-----BEGIN ENCRYPTED PRIVATE KEY-----"
          ))

    if not request.private_key.strip().startswith(
        "-----BEGIN ENCRYPTED PRIVATE KEY-----"
    ):
        raise HTTPException(
            status_code=400,
            detail="Klucz prywatny musi zostać zabezpieczony hasłem"
        )

    print("Walidacja nagłówka zakończona")

    buffer = io.BytesIO()

    print("Rozpoczynam tworzenie ZIP")

    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("private_key.pem", request.private_key)
        archive.writestr("public_key.pem", request.public_key)

    buffer.seek(0)

    print("ZIP został utworzony poprawnie")

    return StreamingResponse(
        buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="ecc_keys.zip"'
        }
    )
@app.post("/keys/import")
async def import_keys(
    private_file: UploadFile = File(...),
    public_file: UploadFile = File(...),
    password: str = Form(...)
):
    try:

        private_pem = await private_file.read()
        public_pem = await public_file.read()


        private_key = deserialize_private_key(
            private_pem, password
        )

        public_key = deserialize_public_key(
            public_pem
        )


        if (
            private_key.curve.name != "secp256k1"
            or public_key.curve.name != "secp256k1"
        ):
            raise ValueError("Nieprawidłowa krzywa ECC")


        if not verify_keys(private_key, public_key):
            raise ValueError("Klucze nie są zgodne")


        return {
            "message": "Klucze zaimportowane poprawnie",
            "private_key": private_pem.decode("utf-8"),
            "public_key": public_pem.decode("utf-8")
        }

    except (ValueError, TypeError, AttributeError, UnicodeError):
        raise HTTPException(
            status_code=400,
            detail="Nieprawidłowe pliki PEM, hasło lub para kluczy."
        )
@app.post("/keys/generate", response_model=KeysResponse)
def generate_keys_endpoint(data: GenerateKeysRequest):
    if not data.password:
        raise HTTPException(status_code=400, detail="Hasło nie może być puste.")

    private_key, public_key, *_ = generate_keys()
    private_pem, public_pem = serialize_keys(private_key, public_key, data.password)

    return KeysResponse(
        private_key_pem=private_pem.decode("utf-8"),
        public_key_pem=public_pem.decode("utf-8"),
    )

@app.post("/keys/verify", response_model=VerifyKeysResponse)
def verify_keys_endpoint(data: VerifyKeysRequest):
    try:
        private_key = deserialize_private_key(
            data.private_key_pem.encode("utf-8"), data.password
        )
        public_key = deserialize_public_key(data.public_key_pem.encode("utf-8"))
    except (ValueError, TypeError) as error:
        raise HTTPException(
            status_code=400, detail=f"Nie udało się zaimportować kluczy: {error}"
        )

    return VerifyKeysResponse(valid=verify_keys(private_key, public_key))

@app.post("/encrypt", response_model=EncryptedData)
def encrypt_endpoint(data: EncryptRequest):
    try:
        public_key = deserialize_public_key(data.public_key_pem.encode("utf-8"))
        encrypted = encrypt_message(data.message, public_key)
    except (ValueError, TypeError) as error:
        raise HTTPException(
            status_code=400, detail=f"Nie udało się zaszyfrować wiadomości: {error}"
        )

    return encrypted

@app.post("/decrypt", response_model=DecryptResponse)
def decrypt_endpoint(data: DecryptRequest):
    try:
        private_key = deserialize_private_key(
            data.private_key_pem.encode("utf-8"), data.password
        )
    except (ValueError, TypeError) as error:
        raise HTTPException(
            status_code=400, detail=f"Nie udało się wczytać klucza prywatnego: {error}"
        )

    try:
        message = decrypt_message(data.encrypted.model_dump(), private_key)
    except (InvalidTag, ValueError, KeyError, TypeError):
        raise HTTPException(
            status_code=400, detail="Nie udało się odszyfrować wiadomości."
        )

    return DecryptResponse(message=message)
# Interfejs do szyfrowania dowolnych plików (JSON + Base64).
# Oddzielony od istniejących endpointów tekstowych.
from pathlib import Path
from fastapi.responses import FileResponse
from file_crypto import MAX_FILE_SIZE, encrypt_file_bytes, decrypt_file_bytes, unb64, b64

class EncryptFileRequest(BaseModel):
    public_key_pem: str
    filename: str
    file_base64: str

class DecryptFileRequest(BaseModel):
    private_key_pem: str
    password: str
    encrypted: dict

@app.post('/api/files/encrypt')
def encrypt_file_endpoint(data: EncryptFileRequest):
    try:
        content = unb64(data.file_base64)
        if len(content) > MAX_FILE_SIZE:
            raise ValueError('Plik jest zbyt duży (maksymalnie 15 MB).')
        public_key = deserialize_public_key(data.public_key_pem.encode('utf-8'))
        return encrypt_file_bytes(content, public_key, data.filename)
    except (ValueError, TypeError, KeyError) as error:
        raise HTTPException(status_code=400, detail=str(error))

@app.post('/api/files/decrypt')
def decrypt_file_endpoint(data: DecryptFileRequest):
    try:
        private_key = deserialize_private_key(data.private_key_pem.encode('utf-8'), data.password)
        filename, content = decrypt_file_bytes(data.encrypted, private_key)
        return {'filename': filename, 'file_base64': b64(content)}
    except (InvalidTag, ValueError, TypeError, KeyError):
        raise HTTPException(status_code=400, detail='Nie udało się odszyfrować pliku. Sprawdź klucz, hasło i plik .ecc.')

# Strona i zasoby frontendowe dostępne z tego samego serwera.
ROOT = Path(__file__).resolve().parent
@app.get('/')
def homepage():
    return FileResponse(ROOT / 'index.html')
@app.get('/assets/style.css')
def frontend_css():
    return FileResponse(ROOT / 'style.css', media_type='text/css')

@app.get('/assets/script.js')
def frontend_js():
    return FileResponse(ROOT / 'script.js', media_type='application/javascript')
