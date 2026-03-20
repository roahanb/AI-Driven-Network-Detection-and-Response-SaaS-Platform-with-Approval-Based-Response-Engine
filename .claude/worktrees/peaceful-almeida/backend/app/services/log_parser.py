"""
Multi-format log parser supporting:
- Suricata EVE JSON
- Zeek (conn.log, dns.log, http.log, alert.log) — TSV and JSON
- Generic JSON Lines
- CSV
- Plain text (comma-separated)
"""

import json
import csv
import io
import re
from typing import List, Dict, Any, Optional
from collections import Counter


# ── Suricata ────────────────────────────────────────────────────────────────

def _parse_suricata_eve(obj: dict) -> Optional[Dict[str, Any]]:
    """Parse a Suricata EVE JSON event."""
    event_type = obj.get("event_type", "")
    src_ip = obj.get("src_ip") or obj.get("source_ip") or ""
    dst_ip = obj.get("dest_ip") or obj.get("dst_ip") or obj.get("destination_ip") or ""

    if not src_ip or not dst_ip:
        return None

    alert = obj.get("alert", {}) or {}
    http  = obj.get("http",  {}) or {}
    dns   = obj.get("dns",   {}) or {}
    tls   = obj.get("tls",   {}) or {}
    flow  = obj.get("flow",  {}) or {}

    # Alert signature — richer than generic alert_type
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
    risk_hint = severity_map.get(suricata_severity, "Low")

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
        "suricata_severity": suricata_severity,
        "risk_hint": risk_hint,
        "signature_id": alert.get("signature_id"),
        "gid": alert.get("gid"),
        "rev": alert.get("rev"),
        "category": alert.get("category", ""),
        "action": alert.get("action", ""),
        "bytes_to_server": flow.get("bytes_toserver"),
        "bytes_to_client": flow.get("bytes_toclient"),
        "http_url": http.get("url", ""),
        "http_method": http.get("http_method", ""),
        "http_user_agent": http.get("http_user_agent", ""),
        "dns_type": dns.get("type", ""),
        "tls_version": tls.get("version", ""),
        "raw": json.dumps(obj),
    }


# ── Zeek ─────────────────────────────────────────────────────────────────────

ZEEK_LOG_FIELDS = {
    "conn": ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
             "proto", "service", "duration", "orig_bytes", "resp_bytes",
             "conn_state", "missed_bytes", "history"],
    "dns":  ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
             "proto", "query", "qclass_name", "qtype_name", "rcode_name",
             "rejected", "answers"],
    "http": ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
             "method", "host", "uri", "user_agent", "status_code",
             "resp_mime_types"],
    "ssl":  ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
             "version", "cipher", "server_name", "validation_status"],
    "files": ["ts", "fuid", "tx_hosts", "rx_hosts", "source",
              "mime_type", "filename", "total_bytes", "md5", "sha256"],
    "notice": ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
               "note", "msg", "sub", "src", "dst", "actions"],
}

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
        risk_hint = "Medium" if state in ZEEK_SUSPICIOUS_CONN_STATES else "Low"
    elif log_type == "dns":
        qtype = row.get("qtype_name") or "A"
        query = row.get("query") or ""
        alert_type = f"zeek-dns:{qtype}:{query}"
        risk_hint = "Low"
    elif log_type == "http":
        method = row.get("method") or "GET"
        status = row.get("status_code") or ""
        alert_type = f"zeek-http:{method}:{status}"
        risk_hint = "Low"
    elif log_type == "notice":
        note = row.get("note") or "notice"
        alert_type = f"zeek-notice:{note}"
        is_suspicious = any(n in note for n in ZEEK_SUSPICIOUS_NOTES)
        risk_hint = "High" if is_suspicious else "Medium"
    elif log_type == "ssl":
        ver = row.get("version") or ""
        validation = row.get("validation_status") or "ok"
        alert_type = f"zeek-ssl:{ver}:{validation}"
        risk_hint = "Medium" if "fail" in str(validation).lower() else "Low"
    else:
        alert_type = f"zeek-{log_type}"
        risk_hint = "Low"

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
        "risk_hint": risk_hint,
        "bytes_to_server": row.get("orig_bytes"),
        "bytes_to_client": row.get("resp_bytes"),
        "http_url": row.get("uri") or "",
        "http_method": row.get("method") or "",
        "http_user_agent": row.get("user_agent") or "",
        "dns_type": row.get("qtype_name") or "",
        "raw": line.strip(),
    }


def _detect_zeek_log_type(lines: List[str]) -> Optional[str]:
    """Detect Zeek log type from #path header."""
    for line in lines[:10]:
        if line.startswith("#path"):
            path = line.split("\t")[-1].strip()
            if path in ZEEK_LOG_FIELDS:
                return path
    # Fallback: detect from #fields header
    for line in lines[:10]:
        if line.startswith("#fields"):
            fields_line = line.replace("#fields", "").strip()
            cols = fields_line.split("\t")
            if "id.orig_h" in cols and "conn_state" in cols:
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
    fields = ZEEK_LOG_FIELDS.get(log_type, [])
    for line in lines:
        if line.startswith("#fields"):
            fields = line.replace("#fields", "").strip().split("\t")
            break

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
        "risk_hint": "Low",
        "bytes_to_server": obj.get("orig_bytes"),
        "bytes_to_client": obj.get("resp_bytes"),
        "http_url": obj.get("uri") or "",
        "http_method": obj.get("method") or "",
        "dns_type": obj.get("qtype_name") or "",
        "raw": json.dumps(obj),
    }


# ── Generic parsers ──────────────────────────────────────────────────────────

def _normalize_generic_json(obj: dict) -> Optional[Dict[str, Any]]:
    """Normalize a generic JSON event (non-Suricata, non-Zeek)."""
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
        "risk_hint": None,
        "raw": json.dumps(obj),
    }


# ── Main parser ──────────────────────────────────────────────────────────────

def parse_logs(text: str) -> List[Dict[str, Any]]:
    """
    Auto-detect and parse log format:
    1. Zeek TSV (starts with #separator)
    2. Suricata EVE JSON / Zeek JSON Lines
    3. CSV
    4. Plain comma-separated
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


def _try_json_lines(lines: List[str]) -> List[Dict]:
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
                "risk_hint": None,
                "raw": str(row),
            })
        return results
    except Exception:
        return []


def _try_plain(lines: List[str]) -> List[Dict]:
    results = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 4:
            results.append({
                "source": "plain",
                "timestamp": parts[0],
                "source_ip": parts[1],
                "destination_ip": parts[2],
                "domain": parts[3] if len(parts) > 3 else "",
                "alert_type": parts[4] if len(parts) > 4 else "",
                "protocol": "",
                "risk_hint": None,
                "raw": line,
            })
    return results


# ── Rule-based threat detection ──────────────────────────────────────────────

SUSPICIOUS_ALERT_KEYWORDS = [
    "scan", "exploit", "attack", "malware", "brute", "injection", "flood",
    "dos", "ddos", "recon", "probe", "lateral", "exfil", "pivot", "c2",
    "shellcode", "overflow", "sqli", "xss", "rce", "lfi", "rfi",
    "ransomware", "trojan", "backdoor", "phish", "spyware", "keylogger",
    "botnet", "beacon", "rat", "meterpreter", "mimikatz", "cobalt",
    "ET POLICY", "ET MALWARE", "ET TROJAN", "ET EXPLOIT", "ET SCAN",
]

MALICIOUS_DOMAIN_KEYWORDS = [
    "malware", "phish", "exploit", "botnet", "evil", "malicious",
    "ransomware", "trojan", "spyware", "c2", "darkweb", "tor2web",
]


def detect_suspicious_events(events: List[Dict]) -> List[Dict]:
    """Rule-based + source-aware threat detection."""
    suspicious = []
    ip_counts = Counter(e.get("source_ip", "") for e in events)

    for event in events:
        alert = str(event.get("alert_type", "")).lower()
        domain = str(event.get("domain", "")).lower()
        src_ip = event.get("source_ip", "")
        dst_ip = event.get("destination_ip", "")
        timestamp = event.get("timestamp", "")
        alert_type = event.get("alert_type", "")
        domain_value = event.get("domain", "")
        source = event.get("source", "generic")
        risk_hint = event.get("risk_hint")

        reasons = []

        # Suricata signatures are pre-classified — trust them
        if source == "suricata":
            suricata_sev = event.get("suricata_severity", 3)
            category = str(event.get("category", "")).lower()
            if suricata_sev <= 2 or any(k in alert for k in SUSPICIOUS_ALERT_KEYWORDS):
                reasons.append(f"Suricata alert: {alert_type}")
            if any(k in category for k in ["malware", "trojan", "exploit", "attack", "policy"]):
                reasons.append(f"Category: {event.get('category')}")

        # Zeek notice log entries are pre-classified
        elif "zeek-notice" in source:
            reasons.append(f"Zeek notice: {alert_type}")

        else:
            # Generic rule-based
            if any(k in alert for k in SUSPICIOUS_ALERT_KEYWORDS):
                reasons.append(f"Suspicious alert: {alert_type}")
            if any(k in domain for k in MALICIOUS_DOMAIN_KEYWORDS):
                reasons.append(f"Malicious domain: {domain_value}")

        if ip_counts[src_ip] >= 3:
            reasons.append(f"Repeated source IP ({ip_counts[src_ip]}x): {src_ip}")

        if not reasons:
            continue

        # Risk level: use Suricata/Zeek hints if available, else infer
        if risk_hint:
            risk_level = risk_hint
        elif any(k in domain for k in ["malware", "ransomware", "botnet", "c2", "trojan"]):
            risk_level = "Critical"
        elif any(k in alert for k in ["exploit", "shellcode", "rce", "overflow", "ransomware", "cobalt"]):
            risk_level = "High"
        elif "scan" in alert or "brute" in alert or ip_counts[src_ip] >= 5:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        recommended = {
            "Critical": "Immediately block IP, isolate host, initiate IR process",
            "High": "Block IP, isolate host, collect forensic evidence",
            "Medium": "Investigate source host, enforce rate limiting",
            "Low": "Review event and continue monitoring",
        }.get(risk_level, "Review event")

        summary = (
            f"[{source.upper()}] Suspicious activity from {src_ip} → {dst_ip}. "
            f"Alert: {alert_type}. Domain: {domain_value or 'N/A'}. "
            f"Reasons: {'; '.join(reasons)}. Action: {recommended}."
        )

        suspicious.append({
            "timestamp": timestamp,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "domain": domain_value,
            "alert_type": alert_type,
            "summary": summary,
            "risk_level": risk_level,
            "recommended_action": recommended,
            "status": "Pending",
            "raw_log": event.get("raw", ""),
            "log_source_type": source,
        })

    return suspicious
