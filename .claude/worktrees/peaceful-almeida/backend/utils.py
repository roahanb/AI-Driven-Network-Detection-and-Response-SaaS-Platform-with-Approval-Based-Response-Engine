from collections import Counter
import json


def parse_logs(text: str):
    lines = text.strip().split("\n")
    parsed = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        try:
            obj = json.loads(line)

            timestamp = obj.get("timestamp", "")
            source_ip = obj.get("src_ip", "") or obj.get("source_ip", "")
            destination_ip = obj.get("dest_ip", "") or obj.get("destination_ip", "")
            domain = obj.get("domain", "") or obj.get("query", "") or obj.get("hostname", "")
            alert_type = obj.get("alert_type", "") or obj.get("event_type", "") or obj.get("alert", "")

            if isinstance(alert_type, dict):
                alert_type = alert_type.get("signature", "unknown")

            if source_ip and destination_ip:
                parsed.append(
                    {
                        "timestamp": timestamp,
                        "source_ip": source_ip,
                        "destination_ip": destination_ip,
                        "domain": domain,
                        "alert_type": str(alert_type),
                    }
                )
                continue

        except json.JSONDecodeError:
            pass

        parts = [p.strip() for p in line.split(",")]

        if len(parts) < 5:
            continue

        parsed.append(
            {
                "timestamp": parts[0],
                "source_ip": parts[1],
                "destination_ip": parts[2],
                "domain": parts[3],
                "alert_type": parts[4],
            }
        )

    return parsed


def detect_suspicious_events(events: list) -> list:
    suspicious = []
    ip_counts = Counter(e["source_ip"] for e in events)

    for event in events:
        alert = event.get("alert_type", "").lower()
        domain = event.get("domain", "").lower()
        src_ip = event.get("source_ip", "")
        dst_ip = event.get("destination_ip", "")
        timestamp = event.get("timestamp", "")
        alert_type = event.get("alert_type", "")
        domain_value = event.get("domain", "")

        reasons = []

        if any(k in alert for k in ["scan", "exploit", "attack", "malware", "brute", "injection", "flood", "dos"]):
            reasons.append(f"Suspicious alert type: {alert_type}")

        if ip_counts[src_ip] >= 3:
            reasons.append(f"Repeated source IP activity from {src_ip}")

        if any(k in domain for k in ["malware", "phish", "exploit", "botnet", "evil", "bad", "malicious"]):
            reasons.append(f"Suspicious domain: {domain_value}")

        if reasons:
            if "malicious" in domain or "malware" in domain or "botnet" in domain:
                risk_level = "High"
                recommended_action = "Block IP and isolate affected host"
            elif "scan" in alert or "brute" in alert or ip_counts[src_ip] >= 3:
                risk_level = "Medium"
                recommended_action = "Investigate source host and monitor traffic"
            else:
                risk_level = "Low"
                recommended_action = "Review event and continue monitoring"

            summary = (
                f"Suspicious network activity detected from {src_ip} to {dst_ip}. "
                f"Domain involved: {domain_value}. "
                f"Alert type: {alert_type}. "
                f"Reasons: {'; '.join(reasons)}. "
                f"Recommended action: {recommended_action}."
            )

            suspicious.append(
                {
                    "timestamp": timestamp,
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "domain": domain_value,
                    "alert_type": alert_type,
                    "summary": summary,
                    "risk_level": risk_level,
                    "recommended_action": recommended_action,
                    "status": "Pending",
                }
            )

    return suspicious