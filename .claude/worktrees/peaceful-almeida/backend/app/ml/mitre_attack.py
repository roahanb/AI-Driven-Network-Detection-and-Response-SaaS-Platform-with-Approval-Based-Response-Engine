"""
MITRE ATT&CK TTP mapping for network security incidents.
Maps alert signatures, domains, and behavioral patterns to ATT&CK tactics/techniques.
Reference: https://attack.mitre.org/
"""

from typing import Optional
import re

# ── MITRE ATT&CK Mapping Table ─────────────────────────────────────────────
# Each entry: alert keywords → tactic + technique
MITRE_RULES = [
    # TA0043 — Reconnaissance
    {
        "patterns": ["scan", "port scan", "nmap", "masscan", "portscan", "probe", "sweep", "recon"],
        "tactic": "Reconnaissance",
        "tactic_id": "TA0043",
        "technique": "Network Service Discovery",
        "technique_id": "T1046",
    },
    {
        "patterns": ["os detect", "fingerprint", "os-scan", "version detect"],
        "tactic": "Reconnaissance",
        "tactic_id": "TA0043",
        "technique": "Active Scanning: Fingerprinting",
        "technique_id": "T1595.001",
    },

    # TA0001 — Initial Access
    {
        "patterns": ["phish", "spear", "credential harvest", "login page", "fake login"],
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique": "Phishing",
        "technique_id": "T1566",
    },
    {
        "patterns": ["exploit", "shellcode", "overflow", "heap spray", "use-after-free",
                     "rce", "remote code", "zero-day", "0day", "cve-"],
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
    },
    {
        "patterns": ["sqli", "sql injection", "union select", "xss", "cross-site",
                     "lfi", "rfi", "path traversal", "directory traversal", "webshell"],
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
    },

    # TA0006 — Credential Access
    {
        "patterns": ["brute", "brute force", "password spray", "credential stuffing",
                     "hydra", "medusa", "login attempt", "auth fail", "authentication failure"],
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique": "Brute Force",
        "technique_id": "T1110",
    },
    {
        "patterns": ["kerberos", "pass-the-hash", "pass-the-ticket", "golden ticket",
                     "mimikatz", "lsass", "credential dump"],
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique": "OS Credential Dumping",
        "technique_id": "T1003",
    },

    # TA0002 — Execution
    {
        "patterns": ["powershell", "cmd.exe", "wscript", "cscript", "mshta",
                     "wmi", "macro", "vba", "office macro"],
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "technique": "Command and Scripting Interpreter",
        "technique_id": "T1059",
    },
    {
        "patterns": ["ransomware", "encrypt", "wannacry", "notpetya", "locky",
                     "ryuk", "revil", "darkside"],
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique": "Data Encrypted for Impact",
        "technique_id": "T1486",
    },

    # TA0011 — Command and Control
    {
        "patterns": ["c2", "c&c", "command and control", "beacon", "cobalt strike",
                     "metasploit", "meterpreter", "empire", "rat", "remote access trojan",
                     "reverse shell", "backdoor"],
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "technique": "Application Layer Protocol",
        "technique_id": "T1071",
    },
    {
        "patterns": ["dns tunnel", "dns exfil", "iodine", "dnscat", "dns covert",
                     "dns c2", "dns query exfil"],
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "technique": "Protocol Tunneling: DNS",
        "technique_id": "T1572",
    },
    {
        "patterns": ["tor", "onion", "darkweb", "i2p", "proxy chain", "vpn tunnel",
                     "anonymize", "anonymizer"],
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "technique": "Proxy: Multi-hop Proxy",
        "technique_id": "T1090.003",
    },
    {
        "patterns": ["dga", "domain generation", "fast flux", "domain flux"],
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "technique": "Dynamic Resolution: Domain Generation Algorithms",
        "technique_id": "T1568.002",
    },

    # TA0010 — Exfiltration
    {
        "patterns": ["exfil", "data exfil", "data theft", "data leak", "upload",
                     "large transfer", "outbound transfer", "ftp upload"],
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "technique": "Exfiltration Over C2 Channel",
        "technique_id": "T1041",
    },

    # TA0008 — Lateral Movement
    {
        "patterns": ["lateral", "smb", "psexec", "wmi lateral", "rdp", "ssh lateral",
                     "pass the hash", "pivoting", "pivot"],
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "technique": "Lateral Tool Transfer",
        "technique_id": "T1570",
    },

    # TA0005 — Defense Evasion
    {
        "patterns": ["obfuscat", "encode", "base64", "encrypt payload", "pack",
                     "polymorphic", "metamorphic", "antivirus bypass", "av bypass",
                     "edr bypass"],
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "technique": "Obfuscated Files or Information",
        "technique_id": "T1027",
    },

    # TA0040 — Impact
    {
        "patterns": ["ddos", "dos", "flood", "syn flood", "udp flood", "http flood",
                     "amplification", "reflection", "botnet"],
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique": "Network Denial of Service",
        "technique_id": "T1498",
    },

    # TA0007 — Discovery
    {
        "patterns": ["network discovery", "host discovery", "ping sweep", "arp scan",
                     "smb enum", "ldap enum", "ad enum"],
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique": "Network Service Discovery",
        "technique_id": "T1046",
    },

    # TA0003 — Persistence
    {
        "patterns": ["persistence", "registry run", "startup", "cron job", "scheduled task",
                     "service install", "rootkit"],
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "technique": "Boot or Logon Autostart Execution",
        "technique_id": "T1547",
    },

    # Malware families (cross-tactic)
    {
        "patterns": ["trojan", "spyware", "keylogger", "infostealer", "banker",
                     "emotet", "trickbot", "qbot", "dridex", "zeus", "agent tesla"],
        "tactic": "Collection",
        "tactic_id": "TA0009",
        "technique": "Data from Local System",
        "technique_id": "T1005",
    },
]


def map_to_mitre(
    alert_type: str = "",
    domain: str = "",
    ai_reason: str = "",
    summary: str = "",
    domain_entropy: float = 0.0,
) -> dict:
    """
    Map an incident to a MITRE ATT&CK TTP based on alert type, domain, and AI reasoning.
    Returns dict with tactic, tactic_id, technique, technique_id — or empty if no match.
    """
    # Combine all text for matching
    text = " ".join([
        str(alert_type).lower(),
        str(domain).lower(),
        str(ai_reason).lower(),
        str(summary).lower(),
    ])

    # Score each rule
    best_match = None
    best_score = 0

    for rule in MITRE_RULES:
        score = sum(1 for p in rule["patterns"] if p in text)
        if score > best_score:
            best_score = score
            best_match = rule

    # High entropy domain → likely DGA → C2
    if domain_entropy > 3.8 and best_match is None:
        best_match = {
            "tactic": "Command and Control",
            "tactic_id": "TA0011",
            "technique": "Dynamic Resolution: Domain Generation Algorithms",
            "technique_id": "T1568.002",
        }

    if best_match and best_score > 0:
        return {
            "mitre_tactic": best_match["tactic"],
            "mitre_tactic_id": best_match["tactic_id"],
            "mitre_technique": best_match["technique"],
            "mitre_technique_id": best_match["technique_id"],
        }

    return {
        "mitre_tactic": None,
        "mitre_tactic_id": None,
        "mitre_technique": None,
        "mitre_technique_id": None,
    }
