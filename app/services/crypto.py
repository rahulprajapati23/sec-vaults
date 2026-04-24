from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class EncryptedPayload:
    file_nonce: bytes
    encrypted_content: bytes
    key_nonce: bytes
    encrypted_key: bytes



def encrypt_bytes(plaintext: bytes, master_key: bytes) -> EncryptedPayload:
    file_key = os.urandom(32)
    file_nonce = os.urandom(12)
    key_nonce = os.urandom(12)

    encrypted_content = AESGCM(file_key).encrypt(file_nonce, plaintext, None)
    encrypted_key = AESGCM(master_key).encrypt(key_nonce, file_key, None)

    return EncryptedPayload(
        file_nonce=file_nonce,
        encrypted_content=encrypted_content,
        key_nonce=key_nonce,
        encrypted_key=encrypted_key,
    )



def decrypt_bytes(payload: bytes, file_nonce: bytes, encrypted_key: bytes, key_nonce: bytes, master_key: bytes) -> bytes:
    file_key = AESGCM(master_key).decrypt(key_nonce, encrypted_key, None)
    return AESGCM(file_key).decrypt(file_nonce, payload, None)



def generate_share_token() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8").rstrip("=")
