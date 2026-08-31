from __future__ import annotations

import json
import os
import re
import time
from typing import Iterable

DEDUP_WINDOW_SECONDS = 30.0

# Alert deduplication is for repeated identical detections, not packet identity.
# Include packet sequence/length when available so distinct packets are not
# silently collapsed by source/destination/SID alone.

MAX_ALERTS_PER_PACKET = 20
SUPPORTED_FIELDS = {"sid", "rev", "revision", "action", "protocol", "src_port", "dst_port", "message", "severity", "priority", "gid", "content", "pcre", "regex", "evidence", "explanation", "direction", "service", "buffer", "nocase", "classification", "offset", "depth", "distance", "within", "threshold", "suppression_key"}
# `heuristic_payload` is a legacy summary produced by parse_rules.py, not a
# faithful representation of a content/URI condition. Treating it as a
# raw substring creates false positives in arbitrary binary/encrypted payloads.
LEGACY_HEURISTIC_FIELD = "heuristic_payload"


class DetectionEngine:
    def __init__(self, rules_path: str):
        self.rules = self.load_rules(rules_path)
        self._compiled_rules = self._compile_rules(self.rules)
        self.unsupported_rules = sum(1 for item in self._compiled_rules if item["unsupported"])
        self._alert_cache: dict[tuple, float] = {}

    @staticmethod
    def load_rules(path: str) -> list[dict]:
        if not os.path.exists(path):
            raise FileNotFoundError(f"rules file not found: {path}")
        with open(path, encoding="utf-8") as stream:
            rules = json.load(stream)
        if not isinstance(rules, list):
            raise ValueError("rules file must contain a JSON array")
        return rules

    @staticmethod
    def _compile_rules(rules: Iterable[dict]) -> list[dict]:
        compiled = []
        for rule in rules:
            # heuristic_payload is a legacy compatibility field, but it is still a
            # content condition: an empty/missing condition must never match merely
            # because the protocol or port matched.
            content = rule.get("content")
            # Legacy heuristic summaries are intentionally not evaluated. They
            # remain visible in rule-load diagnostics, but cannot authorize an
            # alert because they do not preserve the original rule options.
            if isinstance(content, str):
                content_bytes = content.encode("utf-8", errors="ignore").lower()
            else:
                content_bytes = bytes(content or b"").lower()
            regex = rule.get("pcre") or rule.get("regex")
            unsupported = set(rule).difference(SUPPORTED_FIELDS)
            if LEGACY_HEURISTIC_FIELD in rule:
                unsupported.add(LEGACY_HEURISTIC_FIELD)
            compiled.append({
                "rule": rule,
                "unsupported": unsupported,
                "protocol": str(rule.get("protocol", "IP")).upper(),
                "content": content_bytes,
                "regex": re.compile(regex.encode() if isinstance(regex, str) else regex, re.I) if regex else None,
                "src_port": rule.get("src_port"),
                "dst_port": rule.get("dst_port"),
            })
        return compiled

    @staticmethod
    def _port_matches(condition, value) -> bool:
        if condition in (None, "", "any"):
            return True
        if value is None:
            return False
        if isinstance(condition, int):
            return value == condition
        text = str(condition).strip()
        if text.isdigit():
            return value == int(text)
        if ":" in text:
            low, high = text.split(":", 1)
            return (not low or value >= int(low)) and (not high or value <= int(high))
        return value in {int(part) for part in text.split(",") if part.strip().isdigit()}

    def analyze_packet(self, packet: dict) -> list[dict]:
        protocol = str(packet.get("protocol", "")).upper()
        payload = bytes(packet.get("payload", b"")).lower()
        now = time.monotonic()
        alerts = []
        for item in self._compiled_rules:
            if len(alerts) >= MAX_ALERTS_PER_PACKET:
                break
            if item["unsupported"]:
                continue
            if item["protocol"] not in ("IP", protocol):
                continue
            if item["rule"].get("direction") == "client_to_server" and packet.get("direction") not in (None, "client_to_server"):
                continue
            if item["rule"].get("direction") == "server_to_client" and packet.get("direction") != "server_to_client":
                continue
            if not self._port_matches(item["src_port"], packet.get("src_port")):
                continue
            if not self._port_matches(item["dst_port"], packet.get("dst_port")):
                continue
            rule = item["rule"]
            content = item["content"]
            if content and content not in payload:
                continue
            if item["regex"] and not item["regex"].search(payload):
                continue
            sid = rule.get("sid")
            key = (
                packet.get("src_ip"), packet.get("dst_ip"), sid,
                packet.get("src_port"), packet.get("dst_port"),
                packet.get("tcp_sequence"), packet.get("length"),
                bytes(packet.get("payload", b"")),
            )
            if now - self._alert_cache.get(key, 0.0) < DEDUP_WINDOW_SECONDS:
                continue
            self._alert_cache[key] = now
            alerts.append({
                "src_ip": packet.get("src_ip"), "dst_ip": packet.get("dst_ip"),
                "src_port": packet.get("src_port"), "dst_port": packet.get("dst_port"),
                "protocol": protocol, "gid": int(rule.get("gid", 1) or 1), "sid": sid,
                "revision": int(rule.get("rev", rule.get("revision", 1)) or 1),
                "priority": int(rule.get("priority", 3) or 3),
                "severity": rule.get("severity", "Low"),
                "message": rule.get("message", f"Rule {sid} matched"),
                "action": rule.get("action", "ALERT"), "is_ml_anomaly": False,
                "evidence": (f"protocol={protocol}; payload_match="
                             f"{content.decode('utf-8', errors='replace') if content else 'regex'}"),
                "explanation": f"rule {sid} matched packet payload on protocol {protocol}",
            })
        if len(self._alert_cache) > 10000:
            cutoff = now - DEDUP_WINDOW_SECONDS * 2
            self._alert_cache = {key: value for key, value in self._alert_cache.items() if value > cutoff}
        return alerts
