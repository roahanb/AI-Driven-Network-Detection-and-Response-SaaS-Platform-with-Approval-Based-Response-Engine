import logging
from typing import List, Dict, Any

from app.ml.feature_engineering import extract_features_from_logs
from app.ml.model import load_model, model_exists

logger = logging.getLogger(__name__)


def _compute_confidence(score: float) -> float:
    """Convert Isolation Forest decision score to 0-1 confidence."""
    import math
    # More negative score = more anomalous. Normalize to [0, 1].
    clamped = max(-1.0, min(1.0, score))
    confidence = 1 / (1 + math.exp(5 * clamped))
    return round(confidence, 4)


def _generate_ai_reason(feature_row: Dict) -> str:
    reasons = []

    if feature_row.get("is_exploit_alert"):
        reasons.append("exploit/shellcode pattern in alert")
    elif feature_row.get("is_c2_alert"):
        reasons.append("command-and-control communication pattern")
    elif feature_row.get("is_suspicious_alert"):
        reasons.append("suspicious alert type detected")

    if feature_row.get("is_malicious_domain"):
        reasons.append("known malicious domain keyword")

    if feature_row.get("domain_entropy", 0) > 3.5:
        reasons.append("high domain entropy (possible DGA)")

    if feature_row.get("src_ip_frequency", 0) >= 5:
        reasons.append(f"high-frequency source IP ({feature_row['src_ip_frequency']} occurrences)")
    elif feature_row.get("src_ip_frequency", 0) >= 3:
        reasons.append("repeated source IP activity")

    if feature_row.get("is_brute_force"):
        reasons.append("brute force pattern")

    if feature_row.get("is_exfil_alert"):
        reasons.append("potential data exfiltration pattern")

    if feature_row.get("subdomain_levels", 0) > 4:
        reasons.append("unusual subdomain depth")

    if feature_row.get("is_scan_alert"):
        reasons.append("network scanning activity")

    if feature_row.get("is_dns_alert") and feature_row.get("has_domain"):
        reasons.append("DNS-based activity with domain")

    if not reasons:
        return "Statistical anomaly: behavior deviates significantly from baseline"

    return "; ".join(reasons)


def predict_anomalies(parsed_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    df = extract_features_from_logs(parsed_logs)

    if df.empty:
        return []

    if not model_exists():
        logger.warning("ML model not found, using rule-based fallback only")
        return _rule_based_fallback(df.to_dict("records"), parsed_logs)

    try:
        pipeline = load_model()
        predictions = pipeline.predict(df)
        scores = pipeline.decision_function(df)
    except Exception as e:
        logger.error(f"ML inference failed: {e}. Falling back to rule-based.")
        return _rule_based_fallback(df.to_dict("records"), parsed_logs)

    results = []
    for i in range(len(df)):
        feature_row = df.iloc[i].to_dict()
        prediction_label = "suspicious" if predictions[i] == -1 else "normal"
        anomaly_score = float(scores[i])
        confidence = _compute_confidence(anomaly_score)
        ai_reason = _generate_ai_reason(feature_row)

        results.append({
            "ai_prediction": prediction_label,
            "ai_score": anomaly_score,
            "ai_reason": ai_reason,
            "confidence_score": confidence,
        })

    return results


def _rule_based_fallback(feature_rows: List[Dict], parsed_logs: List[Dict]) -> List[Dict]:
    results = []
    for row in feature_rows:
        is_suspicious = (
            row.get("is_suspicious_alert", 0)
            or row.get("is_malicious_domain", 0)
            or row.get("src_ip_frequency", 0) >= 3
            or row.get("domain_entropy", 0) > 3.5
        )
        results.append({
            "ai_prediction": "suspicious" if is_suspicious else "normal",
            "ai_score": -0.5 if is_suspicious else 0.3,
            "ai_reason": _generate_ai_reason(row),
            "confidence_score": 0.7 if is_suspicious else 0.3,
        })
    return results
