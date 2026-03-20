"""
MITRE ATT&CK Framework Mapping

Maps detected security events to MITRE ATT&CK tactics and techniques.
Based on rule-based pattern matching of alert types, domains, and AI reasoning.
"""

from typing import Dict, Optional, Tuple
import re
import math


# ──────────────────────────────────────────────────────────────────────────────
# MITRE TACTICS & TECHNIQUES
# ──────────────────────────────────────────────────────────────────────────────

MITRE_MAPPING = {
    # Reconnaissance (TA0043)
    "TA0043": {
        "name": "Reconnaissance",
        "techniques": {
            "T1046": "Network Service Discovery",
            "T1592": "Gather Victim Host Information",
            "T1589": "Gather Victim Identity Information",
        }
    },
    # Initial Access (TA0001)
    "TA0001": {
        "name": "Initial Access",
        "techniques": {
            "T1566": "Phishing",
            "T1190": "Exploit Public-Facing Application",
            "T1195": "Supply Chain Compromise",
        }
    },
    # Execution (TA0002)
    "TA0002": {
        "name": "Execution",
        "techniques": {
            "T1204": "User Execution",
            "T1648": "Serverless Execution",
        }
    },
    # Persistence (TA0003)
    "TA0003": {
        "name": "Persistence",
        "techniques": {
            "T1547": "Boot or Logon Autostart Execution",
            "T1037": "Boot or Logon Initialization Scripts",
        }
    },
    # Privilege Escalation (TA0004)
    "TA0004": {
        "name": "Privilege Escalation",
        "techniques": {
            "T1548": "Abuse Elevation Control Mechanism",
            "T1547": "Boot or Logon Autostart Execution",
        }
    },
    # Defense Evasion (TA0005)
    "TA0005": {
        "name": "Defense Evasion",
        "techniques": {
            "T1197": "BITS Jobs",
            "T1612": "Build Image on Host",
        }
    },
    # Credential Access (TA0006)
    "TA0006": {
        "name": "Credential Access",
        "techniques": {
            "T1110": "Brute Force",
            "T1555": "Credentials from Password Stores",
            "T1187": "Forced Authentication",
        }
    },
    # Discovery (TA0007)
    "TA0007": {
        "name": "Discovery",
        "techniques": {
            "T1087": "Account Discovery",
            "T1518": "Software Discovery",
        }
    },
    # Lateral Movement (TA0008)
    "TA0008": {
        "name": "Lateral Movement",
        "techniques": {
            "T1570": "Lateral Tool Transfer",
            "T1570": "Lateral Tool Transfer",
        }
    },
    # Collection (TA0009)
    "TA0009": {
        "name": "Collection",
        "techniques": {
            "T1557": "Adversary-in-the-Middle",
            "T1123": "Audio Capture",
        }
    },
    # Exfiltration (TA0010)
    "TA0010": {
        "name": "Exfiltration",
        "techniques": {
            "T1020": "Automated Exfiltration",
            "T1048": "Exfiltration Over Alternative Protocol",
        }
    },
    # Command and Control (TA0011)
    "TA0011": {
        "name": "Command and Control",
        "techniques": {
            "T1071": "Application Layer Protocol",
            "T1092": "Communication Through Removable Media",
            "T1568": "Dynamic Resolution",
        }
    },
    # Impact (TA0040)
    "TA0040": {
        "name": "Impact",
        "techniques": {
            "T1531": "Account Access Removal",
            "T1485": "Data Destruction",
            "T1486": "Data Encrypted for Impact",
        }
    },
}


# ──────────────────────────────────────────────────────────────────────────────
# PATTERN-BASED MAPPING RULES
# ──────────────────────────────────────────────────────────────────────────────

PATTERN_RULES = [
    # Reconnaissance (TA0043 / T1046 - Network Service Discovery)
    {
        "tactic_id": "TA0043",
        "technique_id": "T1046",
        "patterns": [
            r"scan", r"nmap", r"port.*scan", r"network.*scan",
            r"udp.*scan", r"tcp.*scan", r"syn.*scan",
        ],
    },
    # Initial Access (TA0001 / T1566 - Phishing)
    {
        "tactic_id": "TA0001",
        "technique_id": "T1566",
        "patterns": [
            r"phish", r"email.*spam", r"credential.*theft",
            r"social.*engineering", r"malicious.*link",
        ],
    },
    # Initial Access (TA0001 / T1190 - Exploit Public-Facing App)
    {
        "tactic_id": "TA0001",
        "technique_id": "T1190",
        "patterns": [
            r"exploit", r"shellcode", r"overflow", r"vulnerability",
            r"injection", r"sql.*injection", r"xss", r"rce",
        ],
    },
    # Credential Access (TA0006 / T1110 - Brute Force)
    {
        "tactic_id": "TA0006",
        "technique_id": "T1110",
        "patterns": [
            r"brute.*force", r"password.*attack", r"credential.*attack",
            r"login.*attempt", r"auth.*fail", r"failed.*login",
        ],
    },
    # Command and Control (TA0011 / T1071 - Application Layer Protocol)
    {
        "tactic_id": "TA0011",
        "technique_id": "T1071",
        "patterns": [
            r"c2.*beacon", r"command.*control", r"reverse.*shell",
            r"backdoor", r"agent.*callback", r"beacon",
        ],
    },
    # Command and Control (TA0011 / T1568 - Dynamic Resolution)
    {
        "tactic_id": "TA0011",
        "technique_id": "T1568.002",  # DGA variant
        "patterns": [
            r"dga", r"dynamic.*domain", r"domain.*generation",
            r"fast.*flux", r"domain.*flux",
        ],
    },
    # Exfiltration (TA0010 / T1041 - Exfil Over C2)
    {
        "tactic_id": "TA0010",
        "technique_id": "T1041",
        "patterns": [
            r"exfil", r"data.*theft", r"data.*extract", r"data.*transfer",
            r"large.*transfer", r"unusual.*traffic.*size",
        ],
    },
    # Impact (TA0040 / T1486 - Data Encrypted for Impact / Ransomware)
    {
        "tactic_id": "TA0040",
        "technique_id": "T1486",
        "patterns": [
            r"ransomware", r"encrypt.*file", r"crypto.*locker",
            r"wannacry", r"petya", r"notpetya", r"darkside",
        ],
    },
]

MALICIOUS_DOMAINS_MAPPING = {
    "tactic_id": "TA0001",
    "technique_id": "T1566",
    "keywords": [
        "malware", "trojan", "botnet", "ransomware", "phish",
        "malicious", "evil", "c2", "command", "control",
    ]
}


# ──────────────────────────────────────────────────────────────────────────────
# DOMAIN ENTROPY CALCULATION (for DGA Detection)
# ──────────────────────────────────────────────────────────────────────────────

def calculate_domain_entropy(domain: str) -> float:
    """
    Calculate Shannon entropy of domain name.
    High entropy (>3.8) suggests DGA (Domain Generation Algorithm).
    """
    if not domain or len(domain) < 3:
        return 0.0

    # Extract domain name without TLD
    parts = domain.split(".")
    name = parts[0] if parts else domain

    # Calculate frequency of each character
    freq = {}
    for char in name.lower():
        freq[char] = freq.get(char, 0) + 1

    # Calculate Shannon entropy
    entropy = 0.0
    for count in freq.values():
        p = count / len(name)
        entropy -= p * (p and math.log2(p) or 0)

    return entropy


# ──────────────────────────────────────────────────────────────────────────────
# MAIN MAPPING FUNCTION
# ──────────────────────────────────────────────────────────────────────────────

def map_to_mitre(
    alert_type: str,
    domain: str,
    ai_reason: str,
    summary: str = "",
) -> Optional[Tuple[str, str, str, str]]:
    """
    Map security event to MITRE ATT&CK framework.

    Returns:
        Tuple of (tactic_id, tactic_name, technique_id, technique_name)
        or None if no match found
    """
    combined_text = (
        f"{alert_type} {domain} {ai_reason} {summary}".lower()
    )

    # Rule-based pattern matching
    for rule in PATTERN_RULES:
        for pattern in rule["patterns"]:
            if re.search(pattern, combined_text):
                tactic_id = rule["tactic_id"]
                technique_id = rule["technique_id"]
                tactic_name = MITRE_MAPPING[tactic_id]["name"]
                technique_name = MITRE_MAPPING[tactic_id]["techniques"].get(
                    technique_id, technique_id
                )
                return (tactic_id, tactic_name, technique_id, technique_name)

    # Check for DGA patterns (high domain entropy)
    if domain and len(domain) > 5:
        entropy = calculate_domain_entropy(domain)
        if entropy > 3.8:  # High entropy threshold
            tactic_id = "TA0011"
            technique_id = "T1568.002"
            tactic_name = MITRE_MAPPING[tactic_id]["name"]
            technique_name = "Dynamic Resolution: Domain Generation Algorithm"
            return (tactic_id, tactic_name, technique_id, technique_name)

    # Check for malicious domain keywords
    domain_lower = domain.lower()
    for keyword in MALICIOUS_DOMAINS_MAPPING["keywords"]:
        if keyword in domain_lower:
            tactic_id = MALICIOUS_DOMAINS_MAPPING["tactic_id"]
            technique_id = MALICIOUS_DOMAINS_MAPPING["technique_id"]
            tactic_name = MITRE_MAPPING[tactic_id]["name"]
            technique_name = MITRE_MAPPING[tactic_id]["techniques"].get(
                technique_id, technique_id
            )
            return (tactic_id, tactic_name, technique_id, technique_name)

    return None
