"""
config.py — Configuración central del sistema.

Gestiona rutas, parámetros de seguridad y el material criptográfico
(clave AES-256 y secreto JWT). Las claves se generan una sola vez y se
persisten en la carpeta `secrets/` (ignorada por git). Nunca se versionan.
"""
from __future__ import annotations

import json
import os
import secrets as _secrets
from pathlib import Path

# --------------------------------------------------------------------------
# Rutas del proyecto
# --------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
CERTS_DIR = BASE_DIR / "certs"
SECRETS_DIR = BASE_DIR / "secrets"
TEMPLATES_DIR = BASE_DIR / "src" / "templates"

DB_PATH = DATA_DIR / "app.db"
KEYS_FILE = SECRETS_DIR / "keys.json"

# CSV de origen (generados en la fase de preprocesamiento)
CSV_CLEAN = DATA_DIR / "diabetic_data_clean.csv"     # features del modelo (sin IDs)
CSV_WITH_IDS = DATA_DIR / "diabetic_data_with_ids.csv"  # mismos registros + PII
CSV_STAFF = DATA_DIR / "staff_medico.csv"
CSV_COSTOS = DATA_DIR / "matriz_costos.csv"

# Artefactos del modelo de ML
MODEL_FILE = MODELS_DIR / "logistic_regression_model.joblib"
PREPROCESSOR_FILE = MODELS_DIR / "preprocessor.joblib"
NUM_COLS_FILE = MODELS_DIR / "numerical_cols.joblib"
CAT_COLS_FILE = MODELS_DIR / "categorical_cols.joblib"

# --------------------------------------------------------------------------
# Parámetros de seguridad
# --------------------------------------------------------------------------
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60

# Umbrales de estratificación de riesgo de reingreso (probabilidad del modelo).
# El modelo se entrena con balanceo (SMOTE + class_weight), por lo que sus
# probabilidades quedan centradas (~0.56 de mediana) y no en la tasa base (~9%).
# Los cortes se fijan sobre esa distribución: el cuartil superior es Alto Riesgo.
RISK_HIGH = 0.65    # >= 0.65  -> Alto Riesgo (~cuartil superior)
RISK_MEDIUM = 0.50  # 0.50-0.65 -> Riesgo Medio
# < 0.50 -> Bajo Riesgo

# Cantidad de pacientes a cargar en la BD de demostración.
SEED_LIMIT = int(os.getenv("SEED_LIMIT", "1000"))

# --------------------------------------------------------------------------
# Usuarios semilla (entorno de demostración local).
# Las contraseñas se almacenan SIEMPRE con hash Argon2id (ver auth.py);
# aquí solo viven en texto para poblar el entorno de prueba local.
# --------------------------------------------------------------------------
SEED_USERS = [
    # username,     password,        rol,          doctor_id, nombre
    ("med.cardio",  "Medico#2024",   "medico",     101, "Dra. Cardio"),
    ("med.endo",    "Medico#2024",   "medico",     102, "Dr. Endocrino"),
    ("med.emerg",   "Medico#2024",   "medico",     103, "Dra. Emergencia"),
    ("director",    "Director#2024", "director",   None, "Director Médico"),
    ("auditor",     "Auditor#2024",  "auditor",    None, "Auditor de Seguridad"),
    ("dbadmin",     "DbAdmin#2024",  "admin_bd",   None, "Administrador BD/IT"),
]


# --------------------------------------------------------------------------
# Material criptográfico (generación y carga perezosa)
# --------------------------------------------------------------------------
def _load_or_create_keys() -> dict:
    """Carga las claves desde secrets/keys.json; si no existen, las genera."""
    if KEYS_FILE.exists():
        with open(KEYS_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)

    SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    keys = {
        # Clave AES-256 (32 bytes) en hex para cifrado de PII en reposo.
        "aes_key_hex": _secrets.token_bytes(32).hex(),
        # Secreto para firmar tokens JWT.
        "jwt_secret": _secrets.token_urlsafe(48),
    }
    with open(KEYS_FILE, "w", encoding="utf-8") as fh:
        json.dump(keys, fh, indent=2)
    # Permisos restrictivos donde el SO lo soporte (no-op en Windows).
    try:
        os.chmod(KEYS_FILE, 0o600)
    except OSError:
        pass
    return keys


_KEYS = _load_or_create_keys()


def get_aes_key() -> bytes:
    """Devuelve la clave AES-256 (32 bytes) para cifrado simétrico de PII."""
    return bytes.fromhex(_KEYS["aes_key_hex"])


def get_jwt_secret() -> str:
    """Devuelve el secreto usado para firmar/verificar tokens JWT."""
    return _KEYS["jwt_secret"]
