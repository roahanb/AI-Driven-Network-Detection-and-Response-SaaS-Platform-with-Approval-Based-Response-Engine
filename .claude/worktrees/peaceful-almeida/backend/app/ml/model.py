import os
import joblib
import logging
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from typing import List, Dict, Any

from app.ml.feature_engineering import extract_features_from_logs
from app.config import settings

logger = logging.getLogger(__name__)

MODEL_PATH = settings.ML_MODEL_PATH


def train_anomaly_model(parsed_logs: List[Dict[str, Any]]) -> str:
    df = extract_features_from_logs(parsed_logs)

    if df.empty:
        raise ValueError("No logs available for training.")

    if len(df) < 10:
        raise ValueError("Insufficient data for training. Need at least 10 log entries.")

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("isolation_forest", IsolationForest(
            n_estimators=200,
            contamination=settings.ML_CONTAMINATION,
            max_features=0.8,
            bootstrap=True,
            random_state=42,
            n_jobs=-1,
        )),
    ])

    pipeline.fit(df)

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    logger.info(f"Model trained on {len(df)} samples and saved to {MODEL_PATH}")

    return MODEL_PATH


def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"ML model not found at {MODEL_PATH}. "
            "Please upload logs to train the model first."
        )
    return joblib.load(MODEL_PATH)


def model_exists() -> bool:
    return os.path.exists(MODEL_PATH)
