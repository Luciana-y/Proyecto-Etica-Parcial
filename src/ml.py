"""
ml.py — Motor Predictivo de Reingreso (RF-03).

Carga el modelo de Regresión Logística y el preprocesador entrenados en
`models/train_model.py`, y expone funciones para estimar la probabilidad de
reingreso a 30 días y estratificar el riesgo (Alto / Medio / Bajo).
"""
from __future__ import annotations

from functools import lru_cache

import joblib
import numpy as np
import pandas as pd

from . import config

# Categorías ICD-9 (ya agrupadas en el preprocesamiento) a descripción legible.
# Da soporte a la "traducción de códigos ICD-9" del módulo clínico (RF-04).
ICD9_DESCRIPCION = {
    "Circulatorio": "Enfermedad del sistema circulatorio",
    "Respiratorio": "Enfermedad del sistema respiratorio",
    "Digestivo": "Enfermedad del aparato digestivo",
    "Diabetes": "Diabetes mellitus y complicaciones",
    "Lesiones": "Lesiones y envenenamientos",
    "Musculoesqueletico": "Enfermedad musculoesquelética",
    "Genitourinario": "Enfermedad del sistema genitourinario",
    "Neoplasias": "Neoplasias (tumores)",
    "Other": "Otros diagnósticos",
    "UKN": "Diagnóstico no registrado",
}


@lru_cache(maxsize=1)
def _load_artifacts():
    """Carga (una sola vez) el modelo, el preprocesador y las listas de columnas."""
    model = joblib.load(config.MODEL_FILE)
    preprocessor = joblib.load(config.PREPROCESSOR_FILE)
    num_cols = list(joblib.load(config.NUM_COLS_FILE))
    cat_cols = list(joblib.load(config.CAT_COLS_FILE))
    return model, preprocessor, num_cols, cat_cols


def feature_columns() -> list[str]:
    """Devuelve la lista de columnas de features que espera el modelo."""
    _, _, num_cols, cat_cols = _load_artifacts()
    return list(num_cols) + list(cat_cols)


def _coerce(df: pd.DataFrame) -> pd.DataFrame:
    """Asegura los tipos esperados por el preprocesador (numéricas vs. categóricas)."""
    _, _, num_cols, _ = _load_artifacts()
    for c in num_cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    return df


def predict_dataframe(df: pd.DataFrame) -> np.ndarray:
    """Devuelve el vector de probabilidades de reingreso para un DataFrame de pacientes."""
    model, preprocessor, _, _ = _load_artifacts()
    X = preprocessor.transform(_coerce(df.copy()))
    return model.predict_proba(X)[:, 1]


def predict_one(features: dict) -> float:
    """Devuelve la probabilidad de reingreso para un único paciente (dict de features)."""
    df = pd.DataFrame([features])
    return float(predict_dataframe(df)[0])


def stratify(prob: float) -> str:
    """Clasifica la probabilidad en un estrato de riesgo."""
    if prob >= config.RISK_HIGH:
        return "ALTO"
    if prob >= config.RISK_MEDIUM:
        return "MEDIO"
    return "BAJO"


def describe_diagnosis(code: str) -> str:
    """Traduce una categoría de diagnóstico ICD-9 a una descripción legible (RF-04)."""
    return ICD9_DESCRIPCION.get(str(code), str(code))
