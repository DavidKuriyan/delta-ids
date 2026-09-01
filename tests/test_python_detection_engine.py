import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.alert_manager import AlertManager
from core.delta_core import DeltaCore
from core.detection_engine import DetectionEngine
from dashboard.app import app


class RecordingAlerts:
    session = None

    def __init__(self):
        self.alerts = []
        self.traffic = []

    def log_traffic(self, packet):
        self.traffic.append(packet)
        return None

    def log_alert(self, alert):
        self.alerts.append(alert)


class UdpScanRegressionTests(unittest.TestCase):
    def packet(self, port, dst="198.51.100.2", timestamp=None):
        packet = {"src_ip": "192.0.2.1", "dst_ip": dst, "protocol": "UDP",
                  "src_port": 53000, "dst_port": port, "payload": b"dns", "length": 40}
        if timestamp is not None:
            packet["_monotonic"] = timestamp
        return packet

    def test_dns_and_duplicates_do_not_trigger_scan(self):
        recorder = RecordingAlerts()
        core = DeltaCore(recorder, DetectionEngine.__new__(DetectionEngine), port_threshold=3)
        core.detection_engine.analyze_packet = lambda packet: []
        for _ in range(20):
            core.process_packet(self.packet(53))
        self.assertEqual(recorder.alerts, [])

    def test_distinct_ports_same_destination_trigger_scan(self):
        recorder = RecordingAlerts()
        core = DeltaCore(recorder, DetectionEngine.__new__(DetectionEngine), port_threshold=3)
        core.detection_engine.analyze_packet = lambda packet: []
        for port in (53, 123, 161):
            core.process_packet(self.packet(port))
        self.assertEqual(len(recorder.alerts), 1)
        self.assertEqual(recorder.alerts[0]["sid"], 90003)
        self.assertIn("ports=[53, 123, 161]", recorder.alerts[0]["evidence"])

    def test_different_destinations_do_not_aggregate(self):
        recorder = RecordingAlerts()
        core = DeltaCore(recorder, DetectionEngine.__new__(DetectionEngine), port_threshold=3)
        core.detection_engine.analyze_packet = lambda packet: []
        for port, destination in ((53, "198.51.100.2"), (123, "198.51.100.3"), (161, "198.51.100.4")):
            core.process_packet(self.packet(port, destination))
        self.assertEqual(recorder.alerts, [])


class StealthScanRegressionTests(unittest.TestCase):
    def test_flag_based_scan_classes_are_isolated_and_evidence_backed(self):
        for flags, scan_class in (("F", "fin"), ("", "null"), ("FPU", "xmas"), ("FA", "maimon")):
            recorder = RecordingAlerts()
            engine = DetectionEngine.__new__(DetectionEngine)
            engine.analyze_packet = lambda packet: []
            core = DeltaCore(recorder, engine, port_threshold=3)
            for port in (21, 22, 23):
                core.process_packet({"src_ip": "192.0.2.10", "dst_ip": "198.51.100.10",
                                     "protocol": "TCP", "src_port": 40000, "dst_port": port,
                                     "tcp_flags": flags, "length": 60, "payload": b""})
            self.assertEqual(len(recorder.alerts), 1)
            self.assertIn(f"probe_class={scan_class}", recorder.alerts[0]["evidence"])

    def test_ack_scan_requires_reverse_rst_evidence(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, port_threshold=3)
        for port in (21, 22, 23):
            core.process_packet({"src_ip": "192.0.2.10", "dst_ip": "198.51.100.10",
                                 "protocol": "TCP", "src_port": 40000, "dst_port": port,
                                 "tcp_flags": "A", "length": 60, "payload": b""})
        self.assertEqual(recorder.alerts, [])
        for port in (21, 22, 23):
            core.process_packet({"src_ip": "198.51.100.10", "dst_ip": "192.0.2.10",
                                 "protocol": "TCP", "src_port": port, "dst_port": 40000,
                                 "tcp_flags": "R", "length": 40, "payload": b""})
        self.assertEqual(len(recorder.alerts), 1)
        self.assertIn("probe_class=ack", recorder.alerts[0]["evidence"])

    def test_later_scan_window_emits_new_event(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, port_threshold=2, scan_window=5)
        for timestamp, port in ((0, 80), (1, 443), (10, 22), (11, 23)):
            core.process_packet({"src_ip": "192.0.2.10", "dst_ip": "198.51.100.10",
                                 "protocol": "TCP", "src_port": 40000, "dst_port": port,
                                 "tcp_flags": "S", "length": 60, "payload": b"", "_monotonic": timestamp})
        self.assertEqual(len(recorder.alerts), 2)
        self.assertNotEqual(recorder.alerts[0]["event_id"], recorder.alerts[1]["event_id"])


class DetectionEngineSafetyTests(unittest.TestCase):
    def test_alerts_from_same_source_are_not_permanently_suppressed(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = AlertManager(str(Path(directory) / "alerts.sqlite"), terminal=False, persist=True)
            base = {"src_ip": "192.0.2.10", "dst_ip": "198.51.100.10", "protocol": "TCP",
                    "src_port": 40000, "dst_port": 80, "sid": 90003, "severity": "High",
                    "message": "behavioral scan", "event_id": "scan-1", "evidence": "ports=[80,443]"}
            manager.log_alert(base)
            manager.log_alert({**base, "event_id": "scan-2", "evidence": "ports=[22,23]"})
            manager.log_alert({**base, "sid": 1000002, "message": "HTTP attack",
                               "event_id": "http-1", "evidence": "payload_match=GET /admin"})
            from database.models import Alert
            self.assertEqual(manager.session.query(Alert).count(), 3)
            self.assertEqual(len(manager.get_recent_alerts()), 3)
            manager.close()

    def test_configured_rules_match_representative_payload(self):
        engine = DetectionEngine("rules/rules.json")
        packet = {
            "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.1",
            "protocol": "TCP",
            "src_port": 40000,
            "dst_port": 80,
            "payload": b"GET /admin HTTP/1.1",
        }
        alerts = engine.analyze_packet(packet)
        self.assertEqual([alert["sid"] for alert in alerts], [1000002])
        self.assertEqual(engine.unsupported_rules, 0)

    def test_runtime_rules_refresh_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "rules.sqlite")
            engine = DetectionEngine("rules/rules.json", runtime_db_path=db_path)
            from database.models import Rule, init_db
            session = init_db(db_path)
            rule = {"sid": 777001, "rev": 1, "action": "ALERT", "protocol": "ICMP",
                    "message": "runtime ICMP", "rule_text": "runtime", "enabled": True}
            session.add(Rule(sid=777001, revision=1, gid=1, priority=2, protocol="ICMP",
                             message="runtime ICMP", enabled=True, source_file="runtime",
                             rule_text="runtime", rule_json=json.dumps(rule), updated_at=1))
            session.commit()
            session.close()
            packet = {"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1", "protocol": "ICMP",
                      "icmp_type": 8, "length": 64, "payload": b""}
            self.assertEqual(engine.analyze_packet(packet)[0]["sid"], 777001)
            session = init_db(db_path)
            row = session.query(Rule).filter_by(sid=777001, revision=1).one()
            row.enabled = False
            row.rule_json = json.dumps({**rule, "enabled": False})
            session.commit()
            session.close()
            engine.refresh_if_changed(force=True)
            self.assertEqual(engine.analyze_packet(packet), [])

    def test_ipv6_protocol_only_rule_matches(self):
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.rules = [{"sid": 900002, "rev": 1, "protocol": "ICMPV6", "message": "icmpv6"}]
        engine._compiled_rules = engine._compile_rules(engine.rules)
        engine.unsupported_rules = 0
        engine._alert_cache = {}
        packet = {"src_ip": "2001:db8::1", "dst_ip": "2001:db8::2", "protocol": "ICMPv6", "icmp_type": 128, "length": 64, "payload": b""}
        alerts = engine.analyze_packet(packet)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["sid"], 900002)

    def test_explicit_content_rule_matches(self):
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.rules = [{
            "sid": 900001,
            "rev": 1,
            "protocol": "TCP",
            "content": "GET /lab-test",
            "message": "lab test",
        }]
        engine._compiled_rules = engine._compile_rules(engine.rules)
        engine.unsupported_rules = 0
        engine._alert_cache = {}
        packet = {
            "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.1",
            "protocol": "TCP",
            "src_port": 40000,
            "dst_port": 80,
            "payload": b"GET /lab-test HTTP/1.1",
        }
        alerts = engine.analyze_packet(packet)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["sid"], 900001)


class DashboardRuleApiTests(unittest.TestCase):
    def test_rule_crud_search_and_authoritative_state(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "rules.sqlite")
            client = app.test_client()
            with patch("dashboard.app.DB_PATH", db_path):
                response = client.post("/api/rules", json={"rule": "alert icmp any any -> any any (msg:\"ICMP packet found\"; sid:1000999; rev:1;)"})
                self.assertEqual(response.status_code, 201)
                self.assertTrue(response.get_json()["enabled"])

                for query in ("icmp", "ICMP", "iCmP"):
                    response = client.get("/api/rules", query_string={"search": query})
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.get_json()["total"], 1)

                response = client.patch("/api/rules/1000999/1", json={"enabled": False})
                self.assertEqual(response.status_code, 200)
                self.assertFalse(response.get_json()["enabled"])
                response = client.get("/api/rules", query_string={"search": "icmp"})
                self.assertFalse(response.get_json()["items"][0]["enabled"])

                response = client.delete("/api/rules/1000999/1")
                self.assertEqual(response.status_code, 200)
                response = client.get("/api/rules", query_string={"search": "icmp"})
                self.assertEqual(response.get_json()["total"], 0)

                response = client.post("/api/rules", json={"rule": "alert tcp any any -> any any (msg:\"never executable\"; sid:1001000; rev:1;)"})
                self.assertEqual(response.status_code, 400)
                self.assertIn("requires content", response.get_json()["error"])

                response = client.get("/api/rules/1000999/1")
                self.assertEqual(response.status_code, 404)

    def test_port_variable_rule_end_to_end(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "rules.sqlite")
            client = app.test_client()
            with patch("dashboard.app.DB_PATH", db_path):
                # $HTTP_PORTS rule makes it through validation with a canonical
                # port set and becomes active in the compiled detection engine.
                response = client.post("/api/rules", json={"rule": (
                    "alert tcp 192.168.68.110 any -> any $HTTP_PORTS "
                    '(msg:"Nmap detected from windows"; content:"User-Agent|3a| Nmap"; sid:100023; rev:123;)')
                })
                self.assertEqual(response.status_code, 201)
                payload = response.get_json()
                self.assertEqual(payload["dst_port"], "80,8000,8008,8080,8888")
                self.assertEqual(payload["src_ip"], "192.168.68.110")
                # The persisted rule must compile and match through the real
                # detection engine exactly as a file-loaded rule does.
                from database.models import Rule, init_db
                session = init_db(db_path)
                rule_json = session.query(Rule).filter_by(sid=100023, revision=123).one().rule_json
                session.close()
                engine = DetectionEngine.__new__(DetectionEngine)
                engine.rules = [json.loads(rule_json)]
                engine._compiled_rules = engine._compile_rules(engine.rules)
                engine.unsupported_rules = 0
                engine._alert_cache = {}
                engine._lock = __import__("threading").RLock()
                packet = {"src_ip": "192.168.68.110", "dst_ip": "198.51.100.9", "protocol": "TCP",
                          "src_port": 50000, "dst_port": 8080, "payload": b"User-Agent: Nmap"}
                alerts = engine.analyze_packet(packet)
                self.assertEqual([a["sid"] for a in alerts], [100023])

    def test_bracketed_port_list_rule_via_dashboard(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "rules.sqlite")
            client = app.test_client()
            with patch("dashboard.app.DB_PATH", db_path):
                response = client.post("/api/rules", json={"rule": (
                    "alert tcp any any -> any [80,443] "
                    '(msg:"web ports"; content:"GET /"; sid:1002005; rev:1;)')
                })
                self.assertEqual(response.status_code, 201)
                self.assertEqual(response.get_json()["dst_port"], "80,443")

    def test_unknown_port_variable_validation_error(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "rules.sqlite")
            client = app.test_client()
            with patch("dashboard.app.DB_PATH", db_path):
                response = client.post("/api/rules/validate", json={"rule": (
                    "alert tcp any any -> any $XYZ_PORTS (msg:\"x\"; sid:1; rev:1;)")
                })
                self.assertEqual(response.status_code, 400)
                self.assertFalse(response.get_json()["valid"])
                error = response.get_json()["error"]
                self.assertIn("Unknown port variable '$XYZ_PORTS'", error)
                self.assertIn("Available variables:", error)
                self.assertIn("HTTP_PORTS", error)

    def test_invalid_port_expression_validation_error(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "rules.sqlite")
            client = app.test_client()
            with patch("dashboard.app.DB_PATH", db_path):
                response = client.post("/api/rules/validate", json={"rule": (
                    "alert tcp any any -> any banana (msg:\"x\"; sid:1; rev:1;)")
                })
                self.assertEqual(response.status_code, 400)
                error = response.get_json()["error"]
                self.assertIn("Rule validation failed", error)
                self.assertIn("Destination Port", error)
                for form in ("80", "80,443", "[80,443]", "1:1024", "$HTTP_PORTS"):
                    self.assertIn(form, error)

    def test_sort_port_variables_endpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "rules.sqlite")
            client = app.test_client()
            with patch("dashboard.app.DB_PATH", db_path):
                response = client.get("/api/port-variables")
                self.assertEqual(response.status_code, 200)
                variables = response.get_json()["variables"]
                self.assertIn("HTTP_PORTS", variables)
                self.assertEqual(variables["HTTP_PORTS"], [80, 8080, 8000, 8008, 8888])
                self.assertIn("HTTPS_PORTS", variables)

    def test_fields_based_rule_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "rules.sqlite")
            client = app.test_client()
            with patch("dashboard.app.DB_PATH", db_path):
                response = client.post("/api/rules", json={"rule": {"fields": {
                    "action": "alert", "protocol": "tcp", "src_ip": "any", "src_port": "any",
                    "direction": "->", "dst_ip": "any", "dst_port": "$HTTP_PORTS",
                    "message": "editor rule", "content": "GET /", "sid": 1002006, "rev": 1,
                }}})
                self.assertEqual(response.status_code, 201)
                payload = response.get_json()
                self.assertEqual(payload["dst_port"], "80,8000,8008,8080,8888")
                # The variable is resolved before compilation; the generated
                # rule text contains the canonical port set, not a raw token.
                self.assertIn("80,8000,8008,8080,8888", payload["rule_text"])
                self.assertIn("sid:1002006", payload["rule_text"])

    def test_rule_details_endpoint_returns_loaded_rule_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "rules.sqlite")
            client = app.test_client()
            with patch("dashboard.app.DB_PATH", db_path):
                response = client.post("/api/rules", json={"rule": (
                    "alert tcp any any -> any 80 (msg:\"HTTP admin probe\"; "
                    "content:\"GET /admin\"; nocase; sid:1002001; rev:2; priority:2; "
                    "classtype:web-application;)")
                })
                self.assertEqual(response.status_code, 201)
                response = client.get("/api/rules/1002001/2")
                self.assertEqual(response.status_code, 200)
                payload = response.get_json()
                self.assertEqual(payload["sid"], 1002001)
                self.assertEqual(payload["revision"], 2)
                self.assertEqual(payload["action"], "ALERT")
                self.assertEqual(payload["protocol"], "TCP")
                self.assertEqual(payload["dst_port"], 80)
                self.assertEqual(payload["content"], "GET /admin")
                self.assertEqual(payload["nocase"], True)
                self.assertEqual(payload["enabled"], True)
                self.assertTrue(payload["updated_at"] > 0)
                self.assertEqual(payload["source_file"], "runtime")
                self.assertNotIn("mac", payload)


if __name__ == "__main__":
    unittest.main()
