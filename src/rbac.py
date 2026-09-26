"""
rbac.py — Control de Acceso Basado en Roles y Atributos (RS-04).

Implementa la matriz de control de acceso del informe (Cuadro 3). Cada rol
tiene un conjunto de permisos (acciones) y un alcance de lectura. La verificación
se aplica en cada endpoint del backend (principio de Mediación Completa).
"""
from __future__ import annotations

# --------------------------------------------------------------------------
# Definición de permisos por rol (RBAC).
# La componente ABAC (p. ej. "solo pacientes asignados a MI doctor_id") se
# aplica además en la capa de datos usando el claim doctor_id del token.
# --------------------------------------------------------------------------
PERMISSIONS = {
    "medico": {
        "descripcion": "Médico Tratante",
        "acciones": {
            "ver_pacientes_asignados",   # alcance ABAC: solo su especialidad
            "ver_riesgo_reingreso",
            "descifrar_pii",             # descifrado en memoria, solo sus pacientes
            "registrar_seguimiento",
        },
        "acceso_pii": True,
        "acceso_logs": False,
    },
    "director": {
        "descripcion": "Director Médico",
        "acciones": {
            "ver_dashboard_kpis",        # datos agregados, sin PII
        },
        "acceso_pii": False,             # enmascaramiento completo
        "acceso_logs": False,
    },
    "auditor": {
        "descripcion": "Auditor de Seguridad",
        "acciones": {
            "ver_logs_auditoria",
            "verificar_integridad",
        },
        "acceso_pii": False,
        "acceso_logs": True,             # lectura exclusiva de la bitácora
    },
    "admin_bd": {
        "descripcion": "Administrador BD/IT",
        "acciones": {
            "ver_tablas_crudas",         # solo observa ciphertexts
            "gestionar_backups",
        },
        "acceso_pii": False,             # nunca puede descifrar
        "acceso_logs": False,
    },
}


class AccessDenied(Exception):
    """Se lanza cuando un rol intenta una acción no autorizada."""


def has_permission(role: str, action: str) -> bool:
    """Indica si el rol tiene permitida la acción solicitada."""
    role_def = PERMISSIONS.get(role)
    if not role_def:
        return False
    return action in role_def["acciones"]


def require_permission(role: str, action: str) -> None:
    """Verifica el permiso y lanza AccessDenied si el rol no lo posee."""
    if not has_permission(role, action):
        raise AccessDenied(
            f"El rol '{role}' no está autorizado para la acción '{action}'."
        )


def can_decrypt_pii(role: str) -> bool:
    """Indica si el rol puede descifrar PII (solo el médico tratante)."""
    role_def = PERMISSIONS.get(role)
    return bool(role_def and role_def["acceso_pii"])
