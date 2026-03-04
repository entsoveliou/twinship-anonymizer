import base64
import json
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Key from your JS example
BASE64_KEY = 'H1VmuSeUCutQDX+M/OQOqOZvbLmmV6tS9d74iqvq9pY='
KEY = base64.b64decode(BASE64_KEY)

def encrypt_data(data_bytes: bytes, attributes: list) -> bytes:
    aesgcm = AESGCM(KEY)
    nonce = os.urandom(12)
    aad = json.dumps(sorted(attributes)).encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, data_bytes, aad)
    return nonce + ciphertext

def decrypt_data(encrypted_data: bytes, attributes: list) -> bytes:
    try:
        aesgcm = AESGCM(KEY)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aad = json.dumps(sorted(attributes)).encode('utf-8')
        return aesgcm.decrypt(nonce, ciphertext, aad)
    except Exception:
        return None