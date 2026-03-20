import joblib
from feature_engineering import extract_features_from_logs

MODEL_PATH = "saved_models/isolation_forest.pkl"


def load_model():
    return joblib.load(MODEL_PATH)


def generate_ai_reason(feature_row):
    reasons = []

    if feature_row["is_suspicious_alert"] == 1:
        reasons.append("suspicious alert pattern")

    if feature_row["is_malicious_domain"] == 1:
        reasons.append("malicious domain pattern")

    if feature_row["src_ip_frequency"] >= 3:
        reasons.append("repeated source IP activity")

    if feature_row["is_dns_alert"] == 1 and feature_row["has_domain"] == 1:
        reasons.append("dns related activity")

    if not reasons:
        return "behavior deviates from normal pattern"

    return ", ".join(reasons)


def predict_anomalies(parsed_logs):
    df = extract_features_from_logs(parsed_logs)

    if df.empty:
        return []

    model = load_model()
    predictions = model.predict(df)
    scores = model.decision_function(df)

    results = []

    for i in range(len(df)):
        prediction_label = "suspicious" if predictions[i] == -1 else "normal"
        anomaly_score = float(scores[i])
        ai_reason = generate_ai_reason(df.iloc[i])

        results.append(
            {
                "ai_prediction": prediction_label,
                "ai_score": anomaly_score,
                "ai_reason": ai_reason,
            }
        )

    return results