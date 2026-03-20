import pandas as pd
from collections import Counter
from typing import List, Dict, Any
import ipaddress
import re


KNOWN_MALICIOUS_KEYWORDS = [
    "malware", "phish", "exploit", "botnet", "evil", "bad", "malicious",
    "ransomware", "trojan", "spyware", "keylogger", "backdoor", "rootkit",
    "c2", "command-and-control", "darkweb", "tor2web",
]

SUSPICIOUS_ALERT_KEYWORDS = [
    "scan", "exploit", "attack", "malware", "brute", "injection", "flood",
    "dos", "ddos", "recon", "probe", "lateral", "exfil", "pivot", "c2",
    "shellcode", "overflow", "sqli", "xss", "rce", "lfi", "rfi",
]

SUSPICIOUS_PORTS = {22, 23, 3389, 4444, 5900, 6667, 1080, 8080, 8443}
WELL_KNOWN_PORTS = {80, 443, 53, 25, 587, 110, 143}


def _is_private_ip(ip: str) -> int:
    try:
        return int(ipaddress.ip_address(ip).is_private)
    except Exception:
        return 0


def _domain_entropy(domain: str) -> float:
    """Calculate Shannon entropy of domain name (high entropy = suspicious DGA)."""
    if not domain or domain in ("unknown", ""):
        return 0.0
    import math
    clean = domain.lower().split(".")[0]
    if not clean:
        return 0.0
    freq = Counter(clean)
    length = len(clean)
    entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
    return round(entropy, 4)


def _count_subdomain_levels(domain: str) -> int:
    if not domain or domain in ("unknown", ""):
        return 0
    return len(domain.split(".")) - 1


def extract_features_from_logs(parsed_logs: List[Dict[str, Any]]) -> pd.DataFrame:
    if not parsed_logs:
        return pd.DataFrame()

    src_counts = Counter(log.get("source_ip", "unknown") for log in parsed_logs)
    dst_counts = Counter(log.get("destination_ip", "unknown") for log in parsed_logs)
    domain_counts = Counter(log.get("domain", "unknown") for log in parsed_logs)
    alert_counts = Counter(log.get("alert_type", "unknown") for log in parsed_logs)

    feature_rows = []

    for log in parsed_logs:
        source_ip = log.get("source_ip", "unknown") or "unknown"
        destination_ip = log.get("destination_ip", "unknown") or "unknown"
        domain = log.get("domain", "") or ""
        alert_type = str(log.get("alert_type", "") or "")

        alert_lower = alert_type.lower()
        domain_lower = domain.lower()

        row = {
            # Frequency features
            "src_ip_frequency": src_counts[source_ip],
            "dst_ip_frequency": dst_counts[destination_ip],
            "domain_frequency": domain_counts[domain or "unknown"],
            "alert_type_frequency": alert_counts[alert_type or "unknown"],

            # IP features
            "src_is_private": _is_private_ip(source_ip),
            "dst_is_private": _is_private_ip(destination_ip),
            "src_dst_same_subnet": int(source_ip.rsplit(".", 1)[0] == destination_ip.rsplit(".", 1)[0]),

            # Domain features
            "has_domain": int(bool(domain) and domain not in ("", "unknown")),
            "is_malicious_domain": int(any(k in domain_lower for k in KNOWN_MALICIOUS_KEYWORDS)),
            "domain_length": len(domain) if domain not in (None, "unknown", "") else 0,
            "domain_entropy": _domain_entropy(domain),
            "subdomain_levels": _count_subdomain_levels(domain),
            "is_ip_as_domain": int(bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", domain))),

            # Alert type features
            "is_dns_alert": int("dns" in alert_lower),
            "is_suspicious_alert": int(any(k in alert_lower for k in SUSPICIOUS_ALERT_KEYWORDS)),
            "alert_type_length": len(alert_type) if alert_type not in (None, "unknown", "") else 0,
            "is_scan_alert": int("scan" in alert_lower),
            "is_exploit_alert": int("exploit" in alert_lower or "shellcode" in alert_lower),
            "is_c2_alert": int("c2" in alert_lower or "command" in alert_lower or "control" in alert_lower),
            "is_exfil_alert": int("exfil" in alert_lower or "data" in alert_lower),
            "is_brute_force": int("brute" in alert_lower or "force" in alert_lower),
        }

        feature_rows.append(row)

    return pd.DataFrame(feature_rows)
