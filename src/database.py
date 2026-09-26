"""
database.py — Capa de datos (SQLite) con cifrado de PII en reposo.

Modelo de datos:
  - users        : credenciales (hash Argon2id) y rol de cada usuario.
  - patients     : datos clínicos desidentificados + PII CIFRADA (AES-256-GCM).
  - followups    : seguimientos post-alta registrados por el médico.
  - audit_log    : bitácora inmutable encadenada por hash (ver audit.py).

Los identificadores personales (patient_nbr, encounter_id) se almacenan
únicamente cifrados. Las columnas clínicas usadas para agregados de negocio
(estancia, laboratorios, etc.) se guardan desidentificadas.
"""
from __future__ import annotations

import json
import math
import sqlite3
from typing import Optional

import pandas as pd

from . import config, crypto_utils, ml

# Columnas clínicas no identificatorias que se guardan en claro para KPIs.
_KPI_COLS = ["time_in_hospital", "num_lab_procedures", "num_medications",
             "number_emergency", "medical_specialty", "diag_1"]

# doctor_ids de los médicos con usuario en el sistema (ver config.SEED_USERS).
_DOCTORS = [101, 102, 103]


def connect() -> sqlite3.Connection:
    """Abre una conexión a la BD con claves foráneas activas."""
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Crea las tablas si no existen."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            username      TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL,
            doctor_id     INTEGER,
            full_name     TEXT
        );

        CREATE TABLE IF NOT EXISTS patients (
            id                INTEGER PRIMARY KEY,      -- handle público (no PII)
            patient_nbr_enc   TEXT NOT NULL,            -- PII cifrada (AES-256-GCM)
            encounter_id_enc  TEXT NOT NULL,            -- PII cifrada (AES-256-GCM)
            doctor_id         INTEGER NOT NULL,
            features_json     TEXT NOT NULL,            -- features clínicas para el modelo
            time_in_hospital  INTEGER,
            num_lab_procedures INTEGER,
            num_medications   INTEGER,
            number_emergency  INTEGER,
            medical_specialty TEXT,
            diag_1            TEXT,
            true_readmit      INTEGER,                  -- etiqueta real (evaluación)
            pred_prob         REAL,                     -- probabilidad estimada
            risk_band         TEXT                      -- ALTO / MEDIO / BAJO
        );

        CREATE TABLE IF NOT EXISTS followups (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL REFERENCES patients(id),
            actor      TEXT NOT NULL,
            ts         TEXT NOT NULL,
            nota       TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL,
            actor       TEXT NOT NULL,
            role        TEXT NOT NULL,
            action      TEXT NOT NULL,
            resource    TEXT,
            detail      TEXT,
            prev_hash   TEXT NOT NULL,
            record_hash TEXT NOT NULL
        );
        """
    )
    conn.commit()


def is_seeded(conn: sqlite3.Connection) -> bool:
    """Indica si la BD ya fue poblada."""
    row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
    return row[0] > 0


# --------------------------------------------------------------------------
# Semillado (carga inicial de datos de demostración)
# --------------------------------------------------------------------------
def seed(conn: sqlite3.Connection, force: bool = False) -> None:
    """Puebla usuarios y pacientes. No hace nada si ya está poblada (salvo force)."""
    if is_seeded(conn) and not force:
        return
    if force:
        conn.executescript(
            "DELETE FROM followups; DELETE FROM patients; "
            "DELETE FROM users; DELETE FROM audit_log;"
        )

    _seed_users(conn)
    _seed_patients(conn)
    conn.commit()


def _seed_users(conn: sqlite3.Connection) -> None:
    for username, password, role, doctor_id, full_name in config.SEED_USERS:
        conn.execute(
            "INSERT OR REPLACE INTO users VALUES (?, ?, ?, ?, ?)",
            (username, crypto_utils.hash_password(password), role, doctor_id, full_name),
        )


def _seed_patients(conn: sqlite3.Connection) -> None:
    clean = pd.read_csv(config.CSV_CLEAN).head(config.SEED_LIMIT).reset_index(drop=True)
    ids = pd.read_csv(config.CSV_WITH_IDS).head(config.SEED_LIMIT).reset_index(drop=True)

    features = clean.drop(columns=["readmitted"])
    # Predicción por lote (una sola pasada por el modelo).
    probs = ml.predict_dataframe(features)

    for i in range(len(clean)):
        row = features.iloc[i].to_dict()
        # NaN -> None para serializar a JSON válido.
        rec = {k: (None if (isinstance(v, float) and math.isnan(v)) else v)
               for k, v in row.items()}
        prob = float(probs[i])
        doctor_id = _DOCTORS[i % len(_DOCTORS)]

        conn.execute(
            """INSERT INTO patients
               (id, patient_nbr_enc, encounter_id_enc, doctor_id, features_json,
                time_in_hospital, num_lab_procedures, num_medications,
                number_emergency, medical_specialty, diag_1,
                true_readmit, pred_prob, risk_band)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                i + 1,
                crypto_utils.encrypt_pii(str(ids.at[i, "patient_nbr"])),
                crypto_utils.encrypt_pii(str(ids.at[i, "encounter_id"])),
                doctor_id,
                json.dumps(rec, ensure_ascii=False),
                int(clean.at[i, "time_in_hospital"]),
                int(clean.at[i, "num_lab_procedures"]),
                int(clean.at[i, "num_medications"]),
                int(clean.at[i, "number_emergency"]),
                str(clean.at[i, "medical_specialty"]),
                str(clean.at[i, "diag_1"]),
                int(clean.at[i, "readmitted"]),
                prob,
                ml.stratify(prob),
            ),
        )


# --------------------------------------------------------------------------
# Consultas
# --------------------------------------------------------------------------
def get_user(username: str) -> Optional[dict]:
    conn = connect()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_patients_for_doctor(conn: sqlite3.Connection, doctor_id: int) -> list[dict]:
    """Pacientes asignados a un médico (alcance ABAC)."""
    rows = conn.execute(
        """SELECT id, doctor_id, diag_1, risk_band, pred_prob, true_readmit
           FROM patients WHERE doctor_id = ? ORDER BY pred_prob DESC""",
        (doctor_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_patient(conn: sqlite3.Connection, patient_id: int) -> Optional[dict]:
    row = conn.execute(
        "SELECT * FROM patients WHERE id = ?", (patient_id,)
    ).fetchone()
    return dict(row) if row else None


def add_followup(conn: sqlite3.Connection, patient_id: int, actor: str,
                 nota: str) -> None:
    from datetime import datetime, timezone
    conn.execute(
        "INSERT INTO followups (patient_id, actor, ts, nota) VALUES (?,?,?,?)",
        (patient_id, actor, datetime.now(timezone.utc).isoformat(), nota),
    )


def followup_patient_ids(conn: sqlite3.Connection) -> set[int]:
    rows = conn.execute("SELECT DISTINCT patient_id FROM followups").fetchall()
    return {r[0] for r in rows}


def kpi_dataframe(conn: sqlite3.Connection) -> pd.DataFrame:
    """Devuelve un DataFrame con las columnas necesarias para calcular KPIs (sin PII)."""
    rows = conn.execute(
        """SELECT id, time_in_hospital, num_lab_procedures, num_medications,
                  number_emergency, true_readmit, pred_prob, risk_band
           FROM patients"""
    ).fetchall()
    return pd.DataFrame([dict(r) for r in rows])


def raw_patient_ciphertexts(conn: sqlite3.Connection, limit: int = 20) -> list[dict]:
    """Vista de tablas crudas para el rol admin_bd: solo ciphertexts, sin descifrar."""
    rows = conn.execute(
        """SELECT id, patient_nbr_enc, encounter_id_enc, doctor_id
           FROM patients ORDER BY id LIMIT ?""",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def audit_rows(conn: sqlite3.Connection, limit: int = 100) -> list[dict]:
    rows = conn.execute(
        """SELECT id, ts, actor, role, action, resource, detail, record_hash
           FROM audit_log ORDER BY id DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]
