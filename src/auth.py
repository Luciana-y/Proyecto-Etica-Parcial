"""
auth.py — Autenticación y emisión de tokens (RS-03, RS-04).

- Verificación de credenciales contra la tabla de usuarios (contraseñas Argon2id).
- Emisión y validación de tokens JWT firmados (HS256) para autenticar cada
  petición al backend.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt

from . import config, crypto_utils, database


def authenticate_user(username: str, password: str) -> Optional[dict]:
    """
    Valida usuario y contraseña. Devuelve el registro del usuario (sin el hash)
    si las credenciales son correctas, o None en caso contrario.
    """
    user = database.get_user(username)
    if user is None:
        # Se verifica igualmente contra un hash dummy para mitigar ataques de
        # temporización (que revelarían si el usuario existe o no).
        crypto_utils.verify_password(
            "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$"
            "0000000000000000000000000000000000000000000", password)
        return None

    if not crypto_utils.verify_password(user["password_hash"], password):
        return None

    return {
        "username": user["username"],
        "role": user["role"],
        "doctor_id": user["doctor_id"],
        "full_name": user["full_name"],
    }


def create_access_token(user: dict) -> str:
    """Genera un JWT firmado con los claims del usuario y una expiración."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user["username"],
        "role": user["role"],
        "doctor_id": user["doctor_id"],
        "name": user["full_name"],
        "iat": now,
        "exp": now + timedelta(minutes=config.JWT_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, config.get_jwt_secret(), algorithm=config.JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    """
    Valida la firma y expiración de un JWT. Devuelve los claims si es válido,
    o None si está expirado o manipulado.
    """
    try:
        return jwt.decode(
            token,
            config.get_jwt_secret(),
            algorithms=[config.JWT_ALGORITHM],
        )
    except jwt.PyJWTError:
        return None
