import pandas as pd
from collections import Counter

def extract_features_from_logs(parsed_logs):
    if not parsed_logs:
        return pd.DataFrame()

    src_counts = Counter(log.get("source_ip", "unknown") for log in parsed_logs)
    dst_counts = Counter(log.get("destination_ip", "unknown") for log in parsed_logs)
    domain_counts = Counter(log.get("domain", "unknown") for log in parsed_logs)
    alert_counts = Counter(log.get("alert_type", "unknown") for log in parsed_logs)

    feature_rows = []

    for log in parsed_logs:
        source_ip = log.get("source_ip", "unknown")
        destination_ip = log.get("destination_ip", "unknown")
        domain = log.get("domain", "unknown")
        alert_type = log.get("alert_type", "unknown")

        row = {
            "src_ip_frequency": src_counts[source_ip],
            "dst_ip_frequency": dst_counts[destination_ip],
            "domain_frequency": domain_counts[domain],
            "alert_type_frequency": alert_counts[alert_type],
            "has_domain": 0 if domain in ["", "unknown", None] else 1,
            "is_dns_alert": 1 if "dns" in str(alert_type).lower() else 0,
            "is_suspicious_alert": 1 if "suspicious" in str(alert_type).lower() else 0,
            "is_malicious_domain": 1 if "malicious" in str(domain).lower() else 0,
            "domain_length": len(str(domain)) if domain not in [None, "unknown"] else 0,
            "alert_type_length": len(str(alert_type)) if alert_type not in [None, "unknown"] else 0,
        }

        feature_rows.append(row)

    return pd.DataFrame(feature_rows)