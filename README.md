# Sistema de Riesgo de Reingreso y Gobierno de Datos Clínicos

Proyecto Parcial — **Ética y Seguridad de Datos (DS3031)**, UTEC.
Autoras: Valentina Alvarez Beraun · Luciana Yangali Cáceres.

Sistema que estima el **riesgo de reingreso hospitalario a 30 días** de pacientes
diabéticos (dataset *Diabetes 130-US Hospitals 1999-2008*) aplicando controles de
seguridad de datos: cifrado de PII, control de acceso por roles, auditoría inmutable
y comunicación cifrada.

---

## Arquitectura

```
[ Frontend SPA ]  ──HTTPS/TLS 1.3──►  [ API REST (FastAPI) ]  ──►  [ SQLite: PII cifrada ]
   (según rol)                          │  ├─ auth.py    JWT + Argon2id
                                        │  ├─ rbac.py    RBAC / ABAC
                                        │  ├─ crypto.py  AES-256-GCM
                                        │  ├─ audit.py   bitácora hash-chain SHA-256
                                        │  └─ ml.py      motor predictivo (LogReg)
                                        └─ certificados propios (CA interna)
```

### Mapa de requerimientos → código

| Req. | Descripción | Implementación |
|------|-------------|----------------|
| RS-01 | TLS 1.3 con certificados propios | `certs/generate_pki.sh` |
| RS-02 | Cifrado de PII en reposo (AES-256-GCM) | `src/crypto_utils.py` |
| RS-03 | Contraseñas con Argon2id + sal | `src/crypto_utils.py`, `src/auth.py` |
| RS-04 | Control de acceso RBAC/ABAC + JWT | `src/rbac.py`, `src/auth.py`, `src/main.py` |
| RS-05 | Bitácora inmutable (hash chain SHA-256) | `src/audit.py` |
| RS-06 | Respaldos y respuesta a incidentes | ver informe (sección 7) |
| RF-01..06 | Frontend por rol, API, motor ML, dashboard, auditoría | `src/main.py`, `src/templates/` |

---

## Puesta en marcha

### 1. Instalar dependencias
```bash
pip install -r requirements.txt
```

### 2. (Opcional) Regenerar el modelo de ML
Los artefactos ya están en `models/`. Para reentrenar:
```bash
python models/train_model.py     # requiere imbalanced-learn (SMOTE)
```

### 3. Generar los certificados TLS propios (RS-01)
```bash
bash certs/generate_pki.sh
```

### 4. Ejecutar el servidor (con TLS)
```bash
uvicorn src.main:app --host 0.0.0.0 --port 8443 \
    --ssl-keyfile certs/server.key --ssl-certfile certs/server.crt
```
Abrir: **https://localhost:8443/** (el navegador advertirá por la CA propia; es esperado).

> Sin TLS (solo pruebas): `uvicorn src.main:app --reload`

La base de datos se crea y se puebla automáticamente al primer arranque
(`SEED_LIMIT` pacientes, por defecto 1000).

---

## Usuarios de demostración

| Usuario | Contraseña | Rol | Alcance |
|---------|-----------|-----|---------|
| `med.cardio` | `Medico#2024` | Médico Tratante | Solo sus pacientes; descifra PII en memoria |
| `director` | `Director#2024` | Director Médico | Dashboard de KPIs agregados (sin PII) |
| `auditor` | `Auditor#2024` | Auditor | Bitácora + verificación de integridad |
| `dbadmin` | `DbAdmin#2024` | Admin BD/IT | Solo observa ciphertexts (no descifra) |

*(Credenciales de entorno local; en producción se gestionarían por usuario real.)*

---

## Pruebas de seguridad
```bash
python test_security.py
```
Verifica AES-256-GCM (confidencialidad + detección de manipulación), Argon2id,
RBAC, JWT y la integridad de la bitácora encadenada.

---

## Estructura del proyecto
```
├── src/
│   ├── config.py         # rutas, parámetros, claves (AES/JWT)
│   ├── crypto_utils.py   # AES-256-GCM, Argon2id, SHA-256
│   ├── auth.py           # autenticación + JWT
│   ├── rbac.py           # matriz de control de acceso
│   ├── audit.py          # bitácora inmutable hash-chain
│   ├── database.py       # capa de datos SQLite (PII cifrada)
│   ├── ml.py             # motor predictivo de reingreso
│   ├── main.py           # API REST (FastAPI)
│   └── templates/index.html   # frontend SPA por rol
├── models/               # modelo + preprocesador (.joblib) y train_model.py
├── data/                 # datasets (base, limpio, enriquecimiento)
├── certs/generate_pki.sh # CA propia + certificado de servidor
├── test_security.py      # pruebas de los controles de seguridad
└── requirements.txt
```
