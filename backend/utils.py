from collections import Counter


def parse_logs(text: str):
    lines = text.strip().split("\n")
    parsed = []

    for line in lines:
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


def detect_suspicious_events(events):
    incidents = []
    ip_counter = Counter()

    for event in events:
        ip_counter[event["source_ip"]] += 1

    for event in events:
        domain_value = (event.get("domain") or "").lower()
        alert_value = (event.get("alert_type") or "").lower()

        repeated_ip = ip_counter[event["source_ip"]] >= 3
        malicious_domain = "malicious" in domain_value
        suspicious_alert = "suspicious" in alert_value or "dns" in alert_value

        if repeated_ip or malicious_domain or suspicious_alert:
            if malicious_domain:
                risk = "High"
                action = "Block IP"
            elif repeated_ip:
                risk = "Medium"
                action = "Monitor activity"
            else:
                risk = "Low"
                action = "Review DNS traffic"

            summary = (
                f"Suspicious network activity detected from {event['source_ip']} "
                f"to {event['destination_ip']}. Domain involved: {event['domain']}. "
                f"Alert type: {event['alert_type']}. Recommended action: {action}."
            )

            incidents.append(
                {
                    "source_ip": event["source_ip"],
                    "destination_ip": event["destination_ip"],
                    "domain": event["domain"],
                    "timestamp": event["timestamp"],
                    "alert_type": event["alert_type"],
                    "summary": summary,
                    "risk_level": risk,
                    "recommended_action": action,
                    "status": "Pending",
                }
            )

    return incidents