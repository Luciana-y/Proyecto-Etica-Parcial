"""
main.py — API REST del Sistema de Seguridad de Datos Hospitalarios (RF-01..06).

FastAPI que integra autenticación JWT, control de acceso RBAC/ABAC, cifrado de
PII, motor predictivo y bitácora de auditoría. Cada acción sensible queda
registrada en la bitácora inmutable.

Ejecutar (con TLS y certificados propios, RS-01):
    uvicorn src.main:app --host 0.0.0.0 --port 8443 \
        --ssl-keyfile certs/server.key --ssl-certfile certs/server.crt
"""
from __future__ import annotations

import pandas as pd
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import audit, auth, config, crypto_utils, database, ml, rbac

app = FastAPI(title="Sistema de Riesgo de Reingreso y Gobierno de Datos Clínicos")
bearer = HTTPBearer(auto_error=False)


# --------------------------------------------------------------------------
# Ciclo de vida: inicializar y poblar la BD
# --------------------------------------------------------------------------
@app.on_event("startup")
def _startup() -> None:
    conn = database.connect()
    try:
        database.init_db(conn)
        database.seed(conn)
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Dependencias
# --------------------------------------------------------------------------
def get_db():
    conn = database.connect()
    try:
        yield conn
    finally:
        conn.close()


def current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    """Valida el token JWT del encabezado Authorization y devuelve los claims."""
    if creds is None:
        raise HTTPException(status_code=401, detail="Falta el token de autenticación.")
    claims = auth.decode_access_token(creds.credentials)
    if claims is None:
        raise HTTPException(status_code=401, detail="Token inválido o expirado.")
    return claims


def require(action: str):
    """Genera una dependencia que exige un permiso RBAC concreto."""
    def _checker(user: dict = Depends(current_user)) -> dict:
        try:
            rbac.require_permission(user["role"], action)
        except rbac.AccessDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        return user
    return _checker


# --------------------------------------------------------------------------
# Frontend (RF-01)
# --------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (config.TEMPLATES_DIR / "index.html").read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# Autenticación
# --------------------------------------------------------------------------
@app.post("/api/login")
def login(username: str = Form(...), password: str = Form(...),
          conn=Depends(get_db)):
    user = auth.authenticate_user(username, password)
    if user is None:
        audit.log_event(conn, username, "-", "login_fallido", detail="credenciales inválidas")
        conn.commit()
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos.")
    token = auth.create_access_token(user)
    audit.log_event(conn, user["username"], user["role"], "login_exitoso")
    conn.commit()
    return {"access_token": token, "token_type": "bearer",
            "role": user["role"], "name": user["full_name"]}


@app.get("/api/me")
def me(user: dict = Depends(current_user)):
    return {"username": user["sub"], "role": user["role"],
            "name": user.get("name"),
            "rol_descripcion": rbac.PERMISSIONS.get(user["role"], {}).get("descripcion")}


# --------------------------------------------------------------------------
# Rol MÉDICO (RF-04)
# --------------------------------------------------------------------------
@app.get("/api/medico/pacientes")
def medico_pacientes(user: dict = Depends(require("ver_pacientes_asignados")),
                     conn=Depends(get_db)):
    pacientes = database.list_patients_for_doctor(conn, user["doctor_id"])
    audit.log_event(conn, user["sub"], user["role"], "listar_pacientes",
                    detail=f"{len(pacientes)} pacientes asignados")
    conn.commit()
    return {"total": len(pacientes), "pacientes": pacientes}


@app.get("/api/medico/pacientes/{pid}")
def medico_paciente_detalle(pid: int,
                            user: dict = Depends(require("ver_riesgo_reingreso")),
                            conn=Depends(get_db)):
    paciente = database.get_patient(conn, pid)
    if paciente is None:
        raise HTTPException(status_code=404, detail="Paciente no encontrado.")
    # Control ABAC: el médico solo accede a pacientes de su servicio.
    if paciente["doctor_id"] != user["doctor_id"]:
        audit.log_event(conn, user["sub"], user["role"], "acceso_denegado",
                        resource=f"paciente:{pid}", detail="paciente no asignado")
        conn.commit()
        raise HTTPException(status_code=403, detail="Paciente no asignado a su servicio.")

    # Descifrado de PII en memoria (solo para el médico tratante) — RS-02.
    pii = {}
    if rbac.can_decrypt_pii(user["role"]):
        pii = {
            "patient_nbr": crypto_utils.decrypt_pii(paciente["patient_nbr_enc"]),
            "encounter_id": crypto_utils.decrypt_pii(paciente["encounter_id_enc"]),
        }

    audit.log_event(conn, user["sub"], user["role"], "consultar_riesgo",
                    resource=f"paciente:{pid}",
                    detail=f"riesgo={paciente['risk_band']}")
    conn.commit()

    return {
        "id": paciente["id"],
        "pii": pii,
        "diagnostico_principal": {
            "codigo": paciente["diag_1"],
            "descripcion": ml.describe_diagnosis(paciente["diag_1"]),
        },
        "riesgo": {
            "probabilidad": round(paciente["pred_prob"], 4),
            "estrato": paciente["risk_band"],
        },
        "estancia_dias": paciente["time_in_hospital"],
    }


@app.post("/api/medico/pacientes/{pid}/seguimiento")
def medico_registrar_seguimiento(pid: int, nota: str = Form(...),
                                 user: dict = Depends(require("registrar_seguimiento")),
                                 conn=Depends(get_db)):
    paciente = database.get_patient(conn, pid)
    if paciente is None or paciente["doctor_id"] != user["doctor_id"]:
        raise HTTPException(status_code=403, detail="Paciente no asignado a su servicio.")
    database.add_followup(conn, pid, user["sub"], nota)
    audit.log_event(conn, user["sub"], user["role"], "registrar_seguimiento",
                    resource=f"paciente:{pid}", detail="contacto post-alta")
    conn.commit()
    return {"ok": True, "mensaje": "Seguimiento registrado."}


# --------------------------------------------------------------------------
# Rol DIRECTOR — Dashboard de KPIs (RF-05, sin PII)
# --------------------------------------------------------------------------
@app.get("/api/director/kpis")
def director_kpis(user: dict = Depends(require("ver_dashboard_kpis")),
                  conn=Depends(get_db)):
    df = database.kpi_dataframe(conn)
    costos = pd.read_csv(config.CSV_COSTOS).set_index("item_type")["base_cost_usd"].to_dict()

    total = len(df)
    tasa_reingreso = float(df["true_readmit"].mean() * 100) if total else 0.0
    alos = float(df["time_in_hospital"].mean()) if total else 0.0
    alto_riesgo = int((df["risk_band"] == "ALTO").sum())

    # Costo evitado estimado: por cada paciente de ALTO riesgo, se evita el costo
    # de una estancia promedio + una atención de emergencia, ponderado por una
    # eficacia de intervención supuesta del 25%.
    costo_dia = costos.get("Día de Estancia Hospitalaria", 800.0)
    costo_emerg = costos.get("Atención de Emergencia", 350.0)
    eficacia = 0.25
    costo_evitado = alto_riesgo * (costo_dia * alos + costo_emerg) * eficacia

    # Adherencia al protocolo post-alta: % de pacientes ALTO con seguimiento.
    seguidos = database.followup_patient_ids(conn)
    ids_alto = set(df.loc[df["risk_band"] == "ALTO", "id"].tolist())
    adherencia = (len(ids_alto & seguidos) / len(ids_alto) * 100) if ids_alto else 0.0

    audit.log_event(conn, user["sub"], user["role"], "ver_dashboard_kpis",
                    detail=f"{total} registros agregados")
    conn.commit()

    return {
        "total_pacientes": total,
        "tasa_reingreso_30d_pct": round(tasa_reingreso, 2),
        "pacientes_alto_riesgo": alto_riesgo,
        "dias_estancia_promedio": round(alos, 2),
        "costo_evitado_estimado_usd": round(costo_evitado, 2),
        "adherencia_post_alta_pct": round(adherencia, 2),
    }


# --------------------------------------------------------------------------
# Rol AUDITOR — Bitácora e integridad (RF-06, RS-05)
# --------------------------------------------------------------------------
@app.get("/api/auditor/logs")
def auditor_logs(user: dict = Depends(require("ver_logs_auditoria")),
                 conn=Depends(get_db)):
    logs = database.audit_rows(conn, limit=100)
    audit.log_event(conn, user["sub"], user["role"], "consultar_bitacora",
                    detail=f"{len(logs)} eventos")
    conn.commit()
    return {"total": len(logs), "eventos": logs}


@app.get("/api/auditor/verify")
def auditor_verify(user: dict = Depends(require("verificar_integridad")),
                   conn=Depends(get_db)):
    resultado = audit.verify_chain(conn)
    audit.log_event(conn, user["sub"], user["role"], "verificar_integridad",
                    detail=f"ok={resultado['ok']}")
    conn.commit()
    return resultado


# --------------------------------------------------------------------------
# Rol ADMIN BD/IT — Solo ciphertexts (nunca descifra)
# --------------------------------------------------------------------------
@app.get("/api/admin/tablas")
def admin_tablas(user: dict = Depends(require("ver_tablas_crudas")),
                 conn=Depends(get_db)):
    filas = database.raw_patient_ciphertexts(conn, limit=20)
    audit.log_event(conn, user["sub"], user["role"], "ver_tablas_crudas",
                    detail="acceso a ciphertexts (sin descifrado)")
    conn.commit()
    return {"nota": "El administrador solo observa datos cifrados (no puede descifrar PII).",
            "filas": filas}


# --------------------------------------------------------------------------
# Manejo uniforme de errores de acceso
# --------------------------------------------------------------------------
@app.exception_handler(rbac.AccessDenied)
def _access_denied_handler(request: Request, exc: rbac.AccessDenied):
    return JSONResponse(status_code=403, content={"detail": str(exc)})
