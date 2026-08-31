import unittest

from core.delta_core import DeltaCore
from core.detection_engine import DetectionEngine


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



class DetectionEngineSafetyTests(unittest.TestCase):
    def test_metadata_only_rules_do_not_match_payload(self):
        engine = DetectionEngine("rules/rules.json")
        packet = {
            "src_ip": "151.101.209.91",
            "dst_ip": "10.35.194.204",
            "protocol": "TCP",
            "src_port": 443,
            "dst_port": 50000,
            "payload": bytes.fromhex("17 03 03 01 bd af 9e 35 bf 0d 24 29 49 b2 ee fb"),
        }
        self.assertEqual(engine.analyze_packet(packet), [])
        self.assertEqual(engine.unsupported_rules, len(engine.rules))

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


if __name__ == "__main__":
    unittest.main()
