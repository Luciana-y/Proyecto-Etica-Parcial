"""
crypto_utils.py — Utilidades criptográficas (RS-02, RS-03, RS-05).

- Cifrado simétrico de PII en reposo con AES-256-GCM (confidencialidad + integridad
  autenticada). Cada operación usa un nonce aleatorio de 96 bits.
- Hashing de contraseñas con Argon2id (memory-hard) y sal única por usuario.
- Utilidad SHA-256 para el encadenamiento de la bitácora de auditoría.
"""
from __future__ import annotations

import base64
import hashlib
import os

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config

# Longitud recomendada del nonce para AES-GCM: 96 bits (12 bytes).
_NONCE_LEN = 12

# Instancia Argon2id con parámetros razonables para un entorno académico.
# (time_cost=3, memory_cost=64 MiB, parallelism=4 son valores por defecto seguros.)
_password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,
    parallelism=4,
)


# --------------------------------------------------------------------------
# Cifrado simétrico de PII en reposo (AES-256-GCM) — RS-02
# --------------------------------------------------------------------------
def encrypt_pii(plaintext: str) -> str:
    """
    Cifra un dato PII y devuelve una cadena Base64 que contiene `nonce || ciphertext`.

    El tag de autenticación GCM va incluido en el ciphertext, de modo que
    cualquier alteración del dato cifrado se detecta al descifrar.
    """
    if plaintext is None:
        plaintext = ""
    aesgcm = AESGCM(config.get_aes_key())
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = aesgcm.encrypt(nonce, str(plaintext).encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_pii(token: str) -> str:
    """
    Descifra una cadena producida por `encrypt_pii`.

    Lanza una excepción (`cryptography.exceptions.InvalidTag`) si el dato fue
    manipulado, garantizando la integridad del PII.
    """
    raw = base64.b64decode(token.encode("ascii"))
    nonce, ciphertext = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
    aesgcm = AESGCM(config.get_aes_key())
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")


# --------------------------------------------------------------------------
# Hashing de contraseñas (Argon2id) — RS-03
# --------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """Devuelve el hash Argon2id de la contraseña (incluye sal única embebida)."""
    return _password_hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Verifica una contraseña contra su hash Argon2id almacenado."""
    try:
        return _password_hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """Indica si el hash debería recalcularse (parámetros Argon2 desactualizados)."""
    try:
        return _password_hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


# --------------------------------------------------------------------------
# Hashing SHA-256 (cadena de integridad de la bitácora) — RS-05
# --------------------------------------------------------------------------
def sha256_hex(data: str) -> str:
    """Devuelve el hash SHA-256 en hexadecimal de una cadena."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()
