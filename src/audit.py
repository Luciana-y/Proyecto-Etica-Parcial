"""
audit.py — Bitácora de auditoría inmutable (RS-05).

Cada evento se registra en una tabla append-only y se encadena con el evento
anterior mediante SHA-256:

    record_hash = SHA256( prev_hash || ts || actor || role || action || resource || detail )

De este modo, alterar o borrar cualquier registro rompe la cadena de hashes y
la manipulación se detecta con `verify_chain()`. Esto garantiza integridad y
no repudio de las acciones sobre datos sensibles.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Optional

from . import crypto_utils

# Hash raíz de la cadena (bloque génesis).
GENESIS_HASH = "0" * 64


def _canonical(ts: str, actor: str, role: str, action: str,
               resource: str, detail: str, prev_hash: str) -> str:
    """Serialización canónica y determinista del registro para el hash."""
    return "|".join([prev_hash, ts, actor, role, action, resource, detail])


def _last_hash(conn: sqlite3.Connection) -> str:
    row = conn.execute(
        "SELECT record_hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row[0] if row else GENESIS_HASH


def log_event(conn: sqlite3.Connection, actor: str, role: str, action: str,
              resource: str = "", detail: str = "") -> str:
    """
    Registra un evento en la bitácora y devuelve su hash.

    Recibe la conexión para poder participar en la misma transacción que la
    operación auditada.
    """
    ts = datetime.now(timezone.utc).isoformat()
    prev_hash = _last_hash(conn)
    canonical = _canonical(ts, actor, role, action, resource, detail, prev_hash)
    record_hash = crypto_utils.sha256_hex(canonical)
    conn.execute(
        """INSERT INTO audit_log
           (ts, actor, role, action, resource, detail, prev_hash, record_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (ts, actor, role, action, resource, detail, prev_hash, record_hash),
    )
    return record_hash


def verify_chain(conn: sqlite3.Connection) -> dict:
    """
    Recalcula la cadena de hashes de toda la bitácora.

    Devuelve {"ok": bool, "total": n, "broken_at": id|None}. Si algún registro
    fue alterado o eliminado, `ok` es False y `broken_at` indica el primer id
    donde la cadena deja de ser consistente.
    """
    rows = conn.execute(
        """SELECT id, ts, actor, role, action, resource, detail, prev_hash, record_hash
           FROM audit_log ORDER BY id ASC"""
    ).fetchall()

    prev = GENESIS_HASH
    for r in rows:
        (rid, ts, actor, role, action, resource, detail,
         stored_prev, stored_hash) = r
        # El prev_hash almacenado debe coincidir con el hash del registro previo.
        if stored_prev != prev:
            return {"ok": False, "total": len(rows), "broken_at": rid}
        expected = crypto_utils.sha256_hex(
            _canonical(ts, actor, role, action, resource, detail, stored_prev)
        )
        if expected != stored_hash:
            return {"ok": False, "total": len(rows), "broken_at": rid}
        prev = stored_hash

    return {"ok": True, "total": len(rows), "broken_at": None}
