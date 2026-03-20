"""
Multi-format log parser supporting:
- Suricata EVE JSON
- Zeek TSV and JSON logs (conn, dns, http, ssl, notice, files)
- Generic JSON Lines, CSV, and plain text
"""

import json
import csv
import io
from collections import Counter
from typing import List, Dict, Any, Optional

# ──────────────────────────────────────────────────────────────────────────────
# SURICATA EVE JSON PARSER
# ──────────────────────────────────────────────────────────────────────────────

def _parse_suricata_eve(obj: dict) -> Optional[Dict[str, Any]]:
    """Parse a Suricata EVE JSON event."""
    event_type = obj.get("event_type", "")
    src_ip = obj.get("src_ip") or obj.get("source_ip") or ""
    dst_ip = obj.get("dest_ip") or obj.get("dst_ip") or obj.get("destination_ip") or ""

    if not src_ip or not dst_ip:
        return None

    alert = obj.get("alert", {}) or {}
    http = obj.get("http", {}) or {}
    dns = obj.get("dns", {}) or {}
    tls = obj.get("tls", {}) or {}
    flow = obj.get("flow", {}) or {}

    # Alert signature
    signature = (
        alert.get("signature")
        or alert.get("category")
        or event_type
        or "suricata-event"
    )

    # Domain from HTTP host, DNS query, or TLS SNI
    domain = (
        http.get("hostname")
        or dns.get("rrname")
        or tls.get("sni")
        or obj.get("domain")
        or ""
    )

    # Severity mapping: Suricata 1=High, 2=Med, 3=Low
    severity_map = {1: "High", 2: "Medium", 3: "Low"}
    suricata_severity = alert.get("severity", 3)
    risk_level = severity_map.get(suricata_severity, "Low")

    return {
        "source": "suricata",
        "timestamp": obj.get("timestamp") or obj.get("time") or "",
        "source_ip": str(src_ip),
        "destination_ip": str(dst_ip),
        "source_port": obj.get("src_port"),
        "destination_port": obj.get("dest_port"),
        "domain": str(domain),
        "alert_type": str(signature),
        "protocol": obj.get("proto", ""),
        "event_type": event_type,
        "risk_level": risk_level,
        "signature_id": alert.get("signature_id"),
        "category": alert.get("category", ""),
        "action": alert.get("action", ""),
        "raw": json.dumps(obj),
    }


# ──────────────────────────────────────────────────────────────────────────────
# ZEEK LOG PARSER
# ──────────────────────────────────────────────────────────────────────────────

ZEEK_SUSPICIOUS_CONN_STATES = {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"}
ZEEK_SUSPICIOUS_NOTES = [
    "Scan::Port_Scan", "Scan::Address_Scan", "SSL::Invalid_Server_Cert",
    "HTTP::SQL_Injection_Attacker", "Exploit::", "Trojan::", "C2::",
]


def _parse_zeek_tsv_line(line: str, fields: List[str], log_type: str) -> Optional[Dict[str, Any]]:
    """Parse a single Zeek TSV log line."""
    if line.startswith("#") or not line.strip():
        return None

    parts = line.strip().split("\t")
    if len(parts) < 4:
        return None

    row: Dict[str, Any] = {}
    for i, f in enumerate(fields):
        if i < len(parts):
            v = parts[i]
            row[f] = None if v in ("-", "(empty)") else v

    src_ip = row.get("id.orig_h") or row.get("src")
    dst_ip = row.get("id.resp_h") or row.get("dst")

    if not src_ip or not dst_ip:
        return None

    domain = (
        row.get("host") or row.get("query") or
        row.get("server_name") or row.get("filename") or ""
    )

    # Build alert_type from log type + interesting fields
    if log_type == "conn":
        service = row.get("service") or "unknown"
        proto = row.get("proto") or ""
        state = row.get("conn_state") or ""
        alert_type = f"zeek-conn:{proto}:{service}:{state}"
        risk_level = "Medium" if state in ZEEK_SUSPICIOUS_CONN_STATES else "Low"
    elif log_type == "dns":
        qtype = row.get("qtype_name") or "A"
        query = row.get("query") or ""
        alert_type = f"zeek-dns:{qtype}:{query}"
        risk_level = "Low"
    elif log_type == "http":
        method = row.get("method") or "GET"
        status = row.get("status_code") or ""
        alert_type = f"zeek-http:{method}:{status}"
        risk_level = "Low"
    elif log_type == "notice":
        note = row.get("note") or "notice"
        alert_type = f"zeek-notice:{note}"
        is_suspicious = any(n in note for n in ZEEK_SUSPICIOUS_NOTES)
        risk_level = "High" if is_suspicious else "Medium"
    elif log_type == "ssl":
        ver = row.get("version") or ""
        validation = row.get("validation_status") or "ok"
        alert_type = f"zeek-ssl:{ver}:{validation}"
        risk_level = "Medium" if "fail" in str(validation).lower() else "Low"
    else:
        alert_type = f"zeek-{log_type}"
        risk_level = "Low"

    return {
        "source": f"zeek-{log_type}",
        "timestamp": row.get("ts") or "",
        "source_ip": str(src_ip),
        "destination_ip": str(dst_ip),
        "source_port": row.get("id.orig_p"),
        "destination_port": row.get("id.resp_p"),
        "domain": str(domain),
        "alert_type": alert_type,
        "protocol": row.get("proto") or "",
        "risk_level": risk_level,
        "raw": line.strip(),
    }


def _detect_zeek_log_type(lines: List[str]) -> Optional[str]:
    """Detect Zeek log type from #path header."""
    for line in lines[:10]:
        if line.startswith("#path"):
            path = line.split("\t")[-1].strip()
            for log_type in ["conn", "dns", "http", "ssl", "notice", "files"]:
                if path == log_type or path.endswith(f".{log_type}"):
                    return log_type
    # Fallback: detect from #fields header
    for line in lines[:10]:
        if line.startswith("#fields"):
            fields_line = line.replace("#fields", "").strip()
            cols = fields_line.split("\t")
            if "conn_state" in cols:
                return "conn"
            if "query" in cols and "qtype_name" in cols:
                return "dns"
            if "method" in cols and "host" in cols:
                return "http"
            if "note" in cols:
                return "notice"
    return None


def _parse_zeek_tsv(text: str) -> List[Dict[str, Any]]:
    """Parse a full Zeek TSV log file."""
    lines = text.strip().split("\n")
    log_type = _detect_zeek_log_type(lines)
    if not log_type:
        return []

    # Extract fields from header
    fields = []
    for line in lines:
        if line.startswith("#fields"):
            fields = line.replace("#fields", "").strip().split("\t")
            break

    if not fields:
        return []

    results = []
    for line in lines:
        if line.startswith("#"):
            continue
        parsed = _parse_zeek_tsv_line(line, fields, log_type)
        if parsed:
            results.append(parsed)

    return results


def _parse_zeek_json_line(obj: dict) -> Optional[Dict[str, Any]]:
    """Parse a single Zeek JSON-format log entry."""
    log_type = obj.get("_path") or obj.get("log_type") or "conn"

    src_ip = obj.get("id.orig_h") or obj.get("orig_h") or obj.get("src_ip") or ""
    dst_ip = obj.get("id.resp_h") or obj.get("resp_h") or obj.get("dst_ip") or ""
    if not src_ip or not dst_ip:
        return None

    domain = (
        obj.get("query") or obj.get("host") or
        obj.get("server_name") or obj.get("domain") or ""
    )

    return {
        "source": f"zeek-{log_type}",
        "timestamp": obj.get("ts") or "",
        "source_ip": str(src_ip),
        "destination_ip": str(dst_ip),
        "domain": str(domain),
        "alert_type": f"zeek-{log_type}:{obj.get('proto','')}:{obj.get('service','') or obj.get('note','')}",
        "protocol": obj.get("proto") or "",
        "risk_level": "Low",
        "raw": json.dumps(obj),
    }


# ──────────────────────────────────────────────────────────────────────────────
# GENERIC PARSERS
# ──────────────────────────────────────────────────────────────────────────────

def _normalize_generic_json(obj: dict) -> Optional[Dict[str, Any]]:
    """Normalize a generic JSON event."""
    src_ip = (obj.get("src_ip") or obj.get("source_ip") or
              obj.get("src") or obj.get("orig_h") or "")
    dst_ip = (obj.get("dest_ip") or obj.get("destination_ip") or
              obj.get("dst_ip") or obj.get("dst") or obj.get("resp_h") or "")

    if not src_ip or not dst_ip:
        return None

    domain = (obj.get("domain") or obj.get("query") or
              obj.get("hostname") or obj.get("host") or
              obj.get("server_name") or "")
    timestamp = (obj.get("timestamp") or obj.get("time") or
                 obj.get("ts") or obj.get("@timestamp") or "")
    alert_type = (obj.get("alert_type") or obj.get("event_type") or
                  obj.get("alert") or obj.get("signature") or
                  obj.get("type") or obj.get("note") or "")
    if isinstance(alert_type, dict):
        alert_type = alert_type.get("signature") or alert_type.get("category") or ""

    return {
        "source": "generic-json",
        "timestamp": str(timestamp),
        "source_ip": str(src_ip),
        "destination_ip": str(dst_ip),
        "domain": str(domain),
        "alert_type": str(alert_type),
        "protocol": obj.get("proto") or obj.get("protocol") or "",
        "risk_level": None,
        "raw": json.dumps(obj),
    }


def _try_json_lines(lines: List[str]) -> List[Dict]:
    """Try parsing as JSON lines (Suricata EVE or Zeek JSON)."""
    results = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Detect Suricata EVE JSON
        if obj.get("event_type") and ("src_ip" in obj or "dest_ip" in obj):
            parsed = _parse_suricata_eve(obj)

        # Detect Zeek JSON
        elif ("id.orig_h" in obj or "orig_h" in obj or "_path" in obj):
            parsed = _parse_zeek_json_line(obj)

        # Generic JSON
        else:
            parsed = _normalize_generic_json(obj)

        if parsed:
            results.append(parsed)

    return results if len(results) > len(lines) * 0.2 else []


def _try_csv(text: str) -> List[Dict]:
    """Try parsing as CSV."""
    try:
        reader = csv.DictReader(io.StringIO(text))
        results = []
        for row in reader:
            src = (row.get("source_ip") or row.get("src_ip") or
                   row.get("src") or row.get("orig_h") or "")
            dst = (row.get("destination_ip") or row.get("dest_ip") or
                   row.get("dst_ip") or row.get("dst") or row.get("resp_h") or "")
            if not src or not dst:
                continue
            results.append({
                "source": "csv",
                "timestamp": row.get("timestamp") or row.get("time") or row.get("ts") or "",
                "source_ip": src,
                "destination_ip": dst,
                "domain": row.get("domain") or row.get("hostname") or row.get("query") or "",
                "alert_type": row.get("alert_type") or row.get("alert") or row.get("event") or "",
                "protocol": row.get("proto") or row.get("protocol") or "",
                "risk_level": None,
                "raw": str(row),
            })
        return results
    except Exception:
        return []


def _try_plain(lines: List[str]) -> List[Dict]:
    """Try parsing as plain comma-separated text."""
    results = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 5:
            continue
        results.append({
            "source": "plain-text",
            "timestamp": parts[0],
            "source_ip": parts[1],
            "destination_ip": parts[2],
            "domain": parts[3],
            "alert_type": parts[4],
            "protocol": parts[5] if len(parts) > 5 else "",
            "risk_level": None,
            "raw": line,
        })
    return results


# ──────────────────────────────────────────────────────────────────────────────
# MAIN PARSER
# ──────────────────────────────────────────────────────────────────────────────

def parse_logs(text: str) -> List[Dict[str, Any]]:
    """
    Auto-detect and parse log format:
    1. Zeek TSV (starts with #separator or #path)
    2. Suricata EVE JSON / Zeek JSON Lines
    3. CSV
    4. Plain comma-separated text
    """
    text = text.strip()
    if not text:
        return []

    lines = text.split("\n")

    # ── Zeek TSV detection ──
    if any(l.startswith("#separator") or l.startswith("#path") or l.startswith("#fields")
           for l in lines[:5]):
        results = _parse_zeek_tsv(text)
        if results:
            return results

    # ── JSON Lines (Suricata EVE or Zeek JSON) ──
    json_results = _try_json_lines(lines)
    if json_results:
        return json_results

    # ── CSV ──
    csv_results = _try_csv(text)
    if csv_results:
        return csv_results

    # ── Plain text fallback ──
    return _try_plain(lines)


# ──────────────────────────────────────────────────────────────────────────────
# SUSPICIOUS EVENT DETECTION (Original Logic)
# ──────────────────────────────────────────────────────────────────────────────

def detect_suspicious_events(events: list) -> list:
    """Detect suspicious events based on rules and patterns."""
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

        # Try to get risk_level from parsed event, fallback to None
        risk_level_hint = event.get("risk_level")

        reasons = []

        if any(k in alert for k in [
            "scan", "exploit", "attack", "malware", "brute", "injection",
            "flood", "dos", "ddos", "ransomware", "exfil", "beacon",
            "c2", "heartbleed", "infiltrat", "patator", "bot",
        ]):
            reasons.append(f"Suspicious alert type: {alert_type}")

        if ip_counts[src_ip] >= 3:
            reasons.append(f"Repeated source IP activity from {src_ip}")

        if any(k in domain for k in ["malware", "phish", "exploit", "botnet", "evil", "bad", "malicious"]):
            reasons.append(f"Suspicious domain: {domain_value}")

        if reasons:
            # Determine risk level
            if any(k in alert for k in ["ransomware", "heartbleed", "exploit", "c2", "exfil"]) or \
               any(k in domain for k in ["malicious", "malware", "botnet", "trojan", "ransomware"]):
                risk_level = "High"
                recommended_action = "Block IP and isolate affected host"
            elif "scan" in alert or "brute" in alert or "beacon" in alert or \
                 "ddos" in alert or "flood" in alert or ip_counts[src_ip] >= 3:
                risk_level = "Medium"
                recommended_action = "Investigate source host and monitor traffic"
            else:
                risk_level = "Low"
                recommended_action = "Review event and continue monitoring"

            # Override with risk_hint from parser if available
            if risk_level_hint:
                risk_level = risk_level_hint

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
