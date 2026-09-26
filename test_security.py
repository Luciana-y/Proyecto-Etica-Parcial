"""
test_security.py — Pruebas de los mecanismos de seguridad.

Verifica de forma automática los controles del informe:
  - RS-02  Cifrado AES-256-GCM (confidencialidad + detección de manipulación)
  - RS-03  Hashing de contraseñas con Argon2id
  - RS-04  Control de acceso RBAC y validación de tokens JWT
  - RS-05  Integridad de la bitácora encadenada por hash SHA-256

Ejecutar desde la raíz del proyecto:
    python test_security.py
"""
from __future__ import annotations

import sqlite3

from cryptography.exceptions import InvalidTag

from src import audit, auth, crypto_utils, rbac

_passed = 0
_failed = 0


def check(nombre: str, condicion: bool) -> None:
    global _passed, _failed
    if condicion:
        _passed += 1
        print(f"  [OK]   {nombre}")
    else:
        _failed += 1
        print(f"  [FALLA] {nombre}")


# --------------------------------------------------------------------------
def test_aes_confidencialidad_e_integridad():
    print("RS-02  Cifrado AES-256-GCM")
    claro = "48330783"
    token = crypto_utils.encrypt_pii(claro)
    check("El ciphertext difiere del texto plano", token != claro)
    check("El descifrado recupera el valor original", crypto_utils.decrypt_pii(token) == claro)
    check("Dos cifrados del mismo dato difieren (nonce aleatorio)",
          crypto_utils.encrypt_pii(claro) != token)

    # Manipular el ciphertext debe ser detectado por el tag GCM.
    import base64
    raw = bytearray(base64.b64decode(token))
    raw[-1] ^= 0x01  # alterar un byte
    manipulado = base64.b64encode(bytes(raw)).decode()
    detectado = False
    try:
        crypto_utils.decrypt_pii(manipulado)
    except (InvalidTag, Exception):
        detectado = True
    check("Se detecta la manipulación del dato cifrado", detectado)


def test_argon2_password_hashing():
    print("RS-03  Hashing de contraseñas (Argon2id)")
    h = crypto_utils.hash_password("Medico#2024")
    check("El hash no contiene la contraseña en claro", "Medico#2024" not in h)
    check("Es un hash Argon2id", h.startswith("$argon2id$"))
    check("Verifica la contraseña correcta", crypto_utils.verify_password(h, "Medico#2024"))
    check("Rechaza una contraseña incorrecta", not crypto_utils.verify_password(h, "incorrecta"))
    check("Dos hashes del mismo password difieren (sal única)",
          crypto_utils.hash_password("Medico#2024") != h)


def test_rbac():
    print("RS-04  Control de acceso RBAC")
    check("El médico puede ver riesgo de reingreso",
          rbac.has_permission("medico", "ver_riesgo_reingreso"))
    check("El médico puede descifrar PII", rbac.can_decrypt_pii("medico"))
    check("El director NO puede descifrar PII", not rbac.can_decrypt_pii("director"))
    check("El admin_bd NO puede descifrar PII", not rbac.can_decrypt_pii("admin_bd"))
    check("El director NO puede ver la bitácora",
          not rbac.has_permission("director", "ver_logs_auditoria"))
    check("El auditor puede verificar integridad",
          rbac.has_permission("auditor", "verificar_integridad"))
    check("Un rol desconocido no tiene permisos",
          not rbac.has_permission("hacker", "ver_riesgo_reingreso"))


def test_jwt():
    print("RS-04  Tokens JWT")
    user = {"username": "auditor", "role": "auditor", "doctor_id": None,
            "full_name": "Auditor"}
    token = auth.create_access_token(user)
    claims = auth.decode_access_token(token)
    check("El token válido se decodifica", claims is not None and claims["role"] == "auditor")
    check("Un token manipulado se rechaza",
          auth.decode_access_token(token + "x") is None)


def test_audit_chain():
    print("RS-05  Integridad de la bitácora (hash chain SHA-256)")
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, role TEXT,
            action TEXT, resource TEXT, detail TEXT, prev_hash TEXT, record_hash TEXT);"""
    )
    for i in range(5):
        audit.log_event(conn, f"user{i}", "medico", "consultar_riesgo",
                        resource=f"paciente:{i}")
    conn.commit()
    check("La cadena íntegra se valida como OK", audit.verify_chain(conn)["ok"] is True)

    # Alterar un registro debe romper la cadena.
    conn.execute("UPDATE audit_log SET detail = 'ALTERADO' WHERE id = 3")
    conn.commit()
    res = audit.verify_chain(conn)
    check("Se detecta un registro alterado", res["ok"] is False and res["broken_at"] == 3)
    conn.close()


def main():
    print("=" * 60)
    print("PRUEBAS DE SEGURIDAD — Sistema Hospitalario DS3031")
    print("=" * 60)
    test_aes_confidencialidad_e_integridad()
    test_argon2_password_hashing()
    test_rbac()
    test_jwt()
    test_audit_chain()
    print("=" * 60)
    print(f"RESULTADO: {_passed} pruebas OK, {_failed} fallidas")
    print("=" * 60)
    raise SystemExit(1 if _failed else 0)


if __name__ == "__main__":
    main()
