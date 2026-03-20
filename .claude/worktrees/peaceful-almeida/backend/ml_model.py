import os
import joblib
from sklearn.ensemble import IsolationForest
from feature_engineering import extract_features_from_logs

MODEL_PATH = "saved_models/isolation_forest.pkl"

def train_anomaly_model(parsed_logs):
    df = extract_features_from_logs(parsed_logs)

    if df.empty:
        raise ValueError("No logs available for training.")

    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42
    )

    model.fit(df)

    os.makedirs("saved_models", exist_ok=True)
    joblib.dump(model, MODEL_PATH)

    return MODEL_PATH