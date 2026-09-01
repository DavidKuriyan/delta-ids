"""Canonical Delta-NIDS rules compiler.

Builds rules/delta.rules containing all 4000+ detection rules organized into
structured categories with clear section headers and metadata preservation.
"""
from __future__ import annotations

import os
import re
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SNORT_COMMUNITY_PATH = Path(r"D:\Cyber security Projects\snort3-community-rules\snort3-community-rules\snort3-community.rules")
DELTA_RULES_PATH = ROOT / "rules" / "delta.rules"
DELTA_JSON_PATH = ROOT / "rules" / "rules.json"

CATEGORIES = OrderedDict([
    ("ICMP", []),
    ("DNS", []),
    ("HTTP", []),
    ("TLS", []),
    ("SSH", []),
    ("SCANNING", []),
    ("MALWARE / C2", []),
    ("WEB ATTACKS", []),
    ("EXPLOITATION", []),
    ("TCP", []),
    ("UDP", []),
    ("POLICY / ANOMALY", []),
])


def classify_rule(rule_text: str) -> str:
    text_upper = rule_text.upper()
    proto_match = re.match(r"^alert\s+([a-zA-Z0-9]+)", rule_text, re.IGNORECASE)
    proto = proto_match.group(1).upper() if proto_match else ""

    if proto == "ICMP":
        return "ICMP"
    if "DNS" in text_upper or "PORT 53" in text_upper or " 53 " in text_upper or "DOMAIN-NAME" in text_upper or "$DNS_PORTS" in text_upper:
        return "DNS"
    if any(k in text_upper for k in ["WEB-ATTACK", "SQL INJECTION", "SQLI", "CROSS-SITE", "XSS", "PATH TRAVERSAL", "DIRECTORY TRAVERSAL", "COMMAND INJECTION", "RCE", "WEB-APPLICATION-ATTACK"]):
        return "WEB ATTACKS"
    if any(k in text_upper for k in ["HTTP", "WEBAPP", "BROWSER-", "WEB-CLIENT", "FILE-IDENTIFY", "$HTTP_PORTS", " 80 ", " 8080 ", "SERVER-WEBAPP"]):
        return "HTTP"
    if any(k in text_upper for k in ["TLS", "SSL", "HTTPS", "CERTIFICATE", " 443 ", "$HTTPS_PORTS"]):
        return "TLS"
    if "SSH" in text_upper or " 22 " in text_upper or "$SSH_PORTS" in text_upper:
        return "SSH"
    if any(k in text_upper for k in ["SCAN", "SWEEP", "RECONNAISSANCE", "ATTEMPTED-RECON", "NMAP"]):
        return "SCANNING"
    if any(k in text_upper for k in ["MALWARE", "TROJAN", "BACKDOOR", "C2", "COMMAND AND CONTROL", "BOTNET", "RANSOMWARE", "SPYWARE", "TROJAN-ACTIVITY"]):
        return "MALWARE / C2"
    if any(k in text_upper for k in ["EXPLOIT", "OVERFLOW", "BUFFER-OVERFLOW", "DENIAL-OF-SERVICE", "DOS", "SHELLCODE", "ATTEMPTED-ADMIN", "ATTEMPTED-USER", "ATTEMPTED-DOS"]):
        return "EXPLOITATION"
    if proto == "TCP":
        return "TCP"
    if proto == "UDP":
        return "UDP"
    return "POLICY / ANOMALY"


def build_rules():
    categories = OrderedDict((k, list(v)) for k, v in CATEGORIES.items())
    seen_sids = set()
    total_rules = 0

    base_custom_rules = [
        'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( msg:"HTTP path traversal target /etc/passwd"; flow:to_server,established; content:"/etc/passwd"; classtype:web-application-attack; priority:1; severity:HIGH; sid:1000001; rev:1; )',
        'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( msg:"HTTP administrative path access GET /admin"; flow:to_server,established; content:"GET /admin"; nocase; classtype:web-application-activity; priority:2; severity:MEDIUM; sid:1000002; rev:1; )',
        'alert tcp $EXTERNAL_NET any -> $HOME_NET $SSH_PORTS ( msg:"SSH protocol banner observed"; flow:to_server,established; content:"SSH-"; classtype:protocol-command-decode; priority:3; severity:LOW; sid:1000003; rev:1; )',
    ]

    for rule in base_custom_rules:
        sid_match = re.search(r"sid:(\d+);", rule)
        if sid_match:
            seen_sids.add(int(sid_match.group(1)))
        cat = classify_rule(rule)
        categories[cat].append(rule)
        total_rules += 1

    if SNORT_COMMUNITY_PATH.exists():
        with open(SNORT_COMMUNITY_PATH, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                clean = line.strip()
                if not clean.startswith("alert "):
                    continue
                sid_match = re.search(r"sid:(\d+);", clean)
                if sid_match:
                    sid = int(sid_match.group(1))
                    if sid in seen_sids:
                        continue
                    seen_sids.add(sid)
                cat = classify_rule(clean)
                categories[cat].append(clean)
                total_rules += 1

    DELTA_RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(DELTA_RULES_PATH, "w", encoding="utf-8") as out:
        out.write("# ==============================================================================\n")
        out.write("# DELTA-NIDS CANONICAL DETECTION RULES REPOSITORY\n")
        out.write(f"# Total Integrated Rules: {total_rules}\n")
        out.write("# Target Platform: Windows / Production Passive NIDS\n")
        out.write("# ==============================================================================\n\n")

        for cat_name, cat_rules in categories.items():
            out.write("# " + "=" * 78 + "\n")
            out.write(f"# {cat_name} ({len(cat_rules)} rules)\n")
            out.write("# " + "=" * 78 + "\n\n")
            for r in cat_rules:
                out.write(r + "\n")
            out.write("\n")

    print(f"Successfully generated {DELTA_RULES_PATH} with {total_rules} rules across {len(categories)} categories.")
    for cat, rlist in categories.items():
        print(f"  - {cat}: {len(rlist)} rules")


if __name__ == "__main__":
    build_rules()
