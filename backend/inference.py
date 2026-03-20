"""
NDR Platform — Inference Engine
Paper: "AI-Driven Network Detection and Response Platform"

Wraps the NDREnsemble to produce per-event predictions consumed by main.py.
Returns ABRE risk tiers (Section 4.3):
  Tier-1: Low risk    → automated response (block/rate-limit)
  Tier-2: Medium risk → Analyst approval required
  Tier-3: High risk   → Manager (senior Analyst) approval required
"""

import logging
from typing import Any, Dict, List

import numpy as np

from feature_engineering import extract_features_from_logs
from ml_model import ATTACK_LABELS, ATTACK_RISK_TIER, NDREnsemble, SEQ_LEN, get_ensemble

logger = logging.getLogger(__name__)

# Lazy singleton — loaded once on first prediction call
_ensemble: NDREnsemble | None = None


def _get_ensemble() -> NDREnsemble:
    global _ensemble
    if _ensemble is None:
        _ensemble = get_ensemble()
    return _ensemble


# ── Main public interface ──────────────────────────────────────────────────────

def predict_anomalies(parsed_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Run full ensemble inference on a list of parsed log events.

    Parameters
    ----------
    parsed_logs : list of event dicts (from utils.parse_logs)

    Returns
    -------
    list of result dicts, one per event, with keys:
        ai_prediction   : "suspicious" | "normal"
        ai_score        : float [0, 1]  — threat probability
        ai_reason       : str           — human-readable explanation
        attack_category : str           — one of 12 CICIDS2018 attack labels
        threat_score    : float [0, 1]
        risk_tier       : int  1 | 2 | 3  (ABRE tier)
    """
    if not parsed_logs:
        return []

    ensemble = _get_ensemble()

    # ── Feature extraction ────────────────────────────────────────────────────
    try:
        df = extract_features_from_logs(parsed_logs)
    except Exception as exc:
        logger.error(f"Feature extraction failed: {exc}")
        return _fallback_results(len(parsed_logs))

    if df.empty:
        return _fallback_results(len(parsed_logs))

    # extract_features_from_logs already applies robust z-score normalisation
    X = df.values.astype(np.float32)

    N = len(X)

    # ── Build sequences for BiLSTM ────────────────────────────────────────────
    # If fewer events than one window: pad up to SEQ_LEN, make 1 sequence.
    # Otherwise: truncate to complete windows (drop remainder), reshape.
    n_feat = X.shape[1]
    if N < SEQ_LEN:
        pad   = SEQ_LEN - N
        Xp    = np.vstack([X, np.zeros((pad, n_feat), dtype=np.float32)])
        X_seq = Xp.reshape(1, SEQ_LEN, n_feat)
        n_seq = 1
    else:
        n_seq = N // SEQ_LEN
        X_seq = X[:n_seq * SEQ_LEN].reshape(n_seq, SEQ_LEN, n_feat)

    # ── Ensemble prediction ───────────────────────────────────────────────────
    try:
        results = ensemble.predict(X, X_seq)
    except Exception as exc:
        logger.error(f"Ensemble prediction failed, using fallback: {exc}")
        results = ensemble._rule_based_fallback(X)

    # Pad/trim to match input length
    while len(results) < len(parsed_logs):
        results.append(results[-1] if results else _fallback_single())
    results = results[: len(parsed_logs)]

    # ── Apply alert-type override for clearly suspicious events ───────────────
    # When ensemble outputs "Benign" but the rule engine flagged an alert_type,
    # use the alert-type-derived category as a fallback so detections are
    # correctly labelled even when the sequence model is under-confident.
    for idx, (result, event) in enumerate(zip(results, parsed_logs)):
        if result["attack_category"] == "Benign":
            override = _alert_type_to_category(event.get("alert_type", ""))
            if override:
                from ml_model import ATTACK_RISK_TIER, _build_reason
                results[idx]["attack_category"] = override
                results[idx]["risk_tier"]       = ATTACK_RISK_TIER.get(override, 2)
                results[idx]["ai_prediction"]   = "suspicious"
                # Keep ML threat_score if it's useful, otherwise use category default
                if results[idx]["threat_score"] < 0.3:
                    results[idx]["threat_score"] = 0.65
                    results[idx]["ai_score"]     = 0.65
                results[idx]["ai_reason"] = _build_reason(
                    override, results[idx]["threat_score"],
                    X[idx] if idx < len(X) else X[-1]
                )

    return results


# ── Alert-type → CICIDS2018 category mapping ──────────────────────────────────

_ALERT_CAT_MAP: list[tuple[tuple[str, ...], str]] = [
    # High-specificity matches first
    (("ransomware", "encrypt staging"),                          "Ransomware"),
    (("heartbleed",),                                            "Heartbleed"),
    (("ddos", "distributed denial"),                             "DDoS"),
    (("dos flood", "hulk", "goldeneye", "slowloris"),            "DoS-Hulk"),
    (("port scan", "portscan", "probe", "sweep", "nmap"),        "PortScan"),
    (("ssh brute", "ssh-patator", "ssh patator"),                "SSH-Patator"),
    (("ftp brute", "ftp-patator", "ftp patator"),                "FTP-Patator"),
    (("web brute", "http brute", "login brute", "credential"),   "Web-BruteForce"),
    (("bot", "beacon", "c2", "command and control"),             "Bot"),
    (("exfil", "data exfil", "infiltrat"),                       "Infiltration"),
    # Broader fallbacks
    (("dos", "flood"),                                           "DoS-Hulk"),
    (("ssh",),                                                   "SSH-Patator"),
    (("ftp",),                                                   "FTP-Patator"),
]


def _alert_type_to_category(alert_type: str) -> str | None:
    """Map a rule-based alert_type string to a CICIDS2018 attack category."""
    a = (alert_type or "").lower()
    if not a:
        return None
    for keywords, cat in _ALERT_CAT_MAP:
        if any(k in a for k in keywords):
            return cat
    return None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fallback_single() -> Dict[str, Any]:
    return {
        "attack_category": "Benign",
        "threat_score":    0.0,
        "risk_tier":       1,
        "ai_prediction":   "normal",
        "ai_score":        0.0,
        "ai_reason":       "Insufficient data for ML inference — treated as benign",
    }


def _fallback_results(n: int) -> List[Dict[str, Any]]:
    return [_fallback_single() for _ in range(n)]


# ── Utility: risk tier description ────────────────────────────────────────────

def describe_risk_tier(tier: int) -> str:
    descriptions = {
        1: "Tier-1 — Low risk: automated response executed",
        2: "Tier-2 — Medium risk: awaiting Analyst approval",
        3: "Tier-3 — High risk: awaiting Manager approval",
    }
    return descriptions.get(tier, "Unknown tier")
