import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, Raw

from core.alert_manager import AlertManager
from core.delta_core import DeltaCore
from core.packet_capture import PacketCapture, _raw_ip_to_info, packet_to_info
from core.detection_engine import DetectionEngine
from main import build_parser
from run_project import parser as project_parser


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


class PacketNormalizationTests(unittest.TestCase):
    def test_ipv6_packets_are_ignored_by_ipv4_only_pipeline(self):
        from scapy.all import IPv6ExtHdrHopByHop, ICMPv6DestUnreach
        # IPv6 TCP, UDP, ICMPv6, and extension headers must be dropped immediately
        tcp6 = packet_to_info(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") /
                              IPv6ExtHdrHopByHop() / TCP(sport=40000, dport=443, flags="S"))
        self.assertIsNone(tcp6)

        udp6 = packet_to_info(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") /
                              UDP(sport=53000, dport=53) / Raw(b"dns6"))
        self.assertIsNone(udp6)

        icmp6 = packet_to_info(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") /
                               ICMPv6EchoRequest(id=7, seq=3) / Raw(b"ping6"))
        self.assertIsNone(icmp6)

        unreach6 = packet_to_info(Ether() / IPv6(src="2001:db8::2", dst="2001:db8::1") /
                                   ICMPv6DestUnreach(code=4) /
                                   (IPv6(src="2001:db8::1", dst="2001:db8::2") /
                                    UDP(sport=53000, dport=161)))
        self.assertIsNone(unreach6)

    def test_raw_parser_rejects_truncated_and_decodes_icmp(self):
        self.assertIsNone(_raw_ip_to_info(b"\x45" + b"\x00" * 10))
        raw_icmp = bytes.fromhex(
            "4500001c0000000040010000c0000201c6336401"
            "0800000000010001" + "70696e67"
        )
        parsed = _raw_ip_to_info(raw_icmp)
        self.assertEqual(parsed["protocol"], "ICMP")
        self.assertEqual(parsed["icmp_type"], 8)
        self.assertEqual(parsed["payload"], b"ping")
        self.assertEqual(parsed["details"]["icmp_sequence"], 1)

    def test_raw_parser_decodes_tcp_and_udp(self):
        # Raw TCP IPv4 packet: 20 bytes IP + 20 bytes TCP (SYN+ACK = 0x12) + payload "hello"
        raw_tcp = bytes.fromhex(
            "4500002d0001000040060000c0000201c6336401"
            "04d2005000000001000000025012010000000000"
            "68656c6c6f"
        )
        tcp_parsed = _raw_ip_to_info(raw_tcp)
        self.assertIsNotNone(tcp_parsed)
        self.assertEqual(tcp_parsed["protocol"], "TCP")
        self.assertEqual(tcp_parsed["src_port"], 1234)
        self.assertEqual(tcp_parsed["dst_port"], 80)
        self.assertEqual(tcp_parsed["tcp_flags"], "SA")
        self.assertEqual(tcp_parsed["payload"], b"hello")

        # Raw UDP IPv4 packet: 20 bytes IP + 8 bytes UDP + payload "dns"
        raw_udp = bytes.fromhex(
            "4500001f0002000040110000c0000201c6336401"
            "cf080035000b0000"
            "646e73"
        )
        udp_parsed = _raw_ip_to_info(raw_udp)
        self.assertIsNotNone(udp_parsed)
        self.assertEqual(udp_parsed["protocol"], "UDP")
        self.assertEqual(udp_parsed["src_port"], 53000)
        self.assertEqual(udp_parsed["dst_port"], 53)
        self.assertEqual(udp_parsed["payload"], b"dns")



class CaptureTests(unittest.TestCase):
    def test_replay_dispatches_packets_and_continues_after_callback_error(self):
        packets = [Ether() / IP(src="192.0.2.1", dst="198.51.100.1") / UDP(sport=1, dport=2),
                   Ether() / IP(src="192.0.2.2", dst="198.51.100.2") / UDP(sport=3, dport=4)]
        received = []
        def callback(info):
            received.append(info)
            if len(received) == 1:
                raise RuntimeError("synthetic")
        capture = PacketCapture(callback, pcap_path="fixture.pcap")
        with patch("core.packet_capture.rdpcap", return_value=packets):
            capture.run()
        self.assertEqual(capture.packets_seen, 2)
        self.assertEqual(capture.packets_failed, 1)
        self.assertEqual(len(received), 2)


class CoreAndRulesTests(unittest.TestCase):
    def test_icmp_request_and_sweep(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, ping_threshold=3)
        for index in range(3):
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": f"198.51.100.{index + 1}",
                                 "protocol": "ICMP", "icmp_type": 8, "length": 64,
                                 "payload": b""})
        self.assertEqual([a["sid"] for a in recorder.alerts], [90001, 90001, 90001, 90002])

    def test_configured_rules_are_native_valid(self):
        result = __import__("subprocess").run(
            ["./build/delta-nids", "--validate-rules", "rules/rules.json"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rule_port_range_and_regex(self):
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.rules = [{"gid": 2, "sid": 77, "rev": 3, "protocol": "TCP",
                         "src_port": "40000:40010", "dst_port": "80,443",
                         "regex": "GET /[a-z]+", "message": "web"}]
        engine._compiled_rules = engine._compile_rules(engine.rules)
        engine.unsupported_rules = 0
        engine._alert_cache = {}
        packet = {"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1", "protocol": "TCP",
                  "src_port": 40005, "dst_port": 80, "payload": b"GET /index"}
        alerts = engine.analyze_packet(packet)
        self.assertEqual(len(alerts), 1)
        self.assertEqual((alerts[0]["gid"], alerts[0]["sid"], alerts[0]["revision"]), (2, 77, 3))

    def test_icmp_echo_to_same_target_aggregates_per_window(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, ping_threshold=3)
        for sequence in range(1, 6):
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1",
                                 "protocol": "ICMP", "icmp_type": 8, "icmp_id": 7,
                                 "icmp_sequence": sequence, "length": 64, "payload": b""})
        # Repeated pings to one target aggregate into a single bounded
        # INFO-level visibility event instead of flooding one alert per ping.
        self.assertEqual([a["sid"] for a in recorder.alerts], [90001])
        self.assertEqual(recorder.alerts[0]["severity"], "INFO")

    def test_dns_query_rate_anomaly(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, dns_threshold=3)
        for offset in range(4):
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.53",
                                 "protocol": "UDP", "src_port": 53000, "dst_port": 53,
                                 "length": 40, "payload": bytes([offset])})
        self.assertEqual([a["sid"] for a in recorder.alerts], [90004])
        # Emitted as soon as the threshold is reached (streaming): the 3rd
        # query satisfies dns_threshold=3.
        self.assertIn("query_count=3", recorder.alerts[0]["evidence"])

    def test_dns_replies_are_not_query_anomalies(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, dns_threshold=2)
        for offset in range(4):
            core.process_packet({"src_ip": "198.51.100.53", "dst_ip": "192.0.2.1",
                                 "protocol": "UDP", "src_port": 53, "dst_port": 45000,
                                 "length": 40, "payload": bytes([offset])})
        self.assertEqual(recorder.alerts, [])

    def test_repeated_connection_failures(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, brute_force_threshold=3)
        for sequence in range(4):
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1",
                                 "protocol": "TCP", "src_port": 42000 + sequence,
                                 "dst_port": 22, "tcp_flags": "R",
                                 "tcp_sequence": sequence, "length": 40, "payload": b""})
        self.assertEqual([a["sid"] for a in recorder.alerts], [90005])
        # Emitted as soon as the threshold is reached (streaming): the 3rd
        # failure satisfies brute_force_threshold=3.
        self.assertIn("connection_failures=3", recorder.alerts[0]["evidence"])

    def test_fin_scan_is_not_connection_failure_flood(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, port_threshold=3, brute_force_threshold=2)
        for port in (21, 22, 23):
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1",
                                 "protocol": "TCP", "src_port": 40000,
                                 "dst_port": port, "tcp_flags": "F",
                                 "length": 60, "payload": b""})
        sids = [alert["sid"] for alert in recorder.alerts]
        self.assertEqual(sids, [90003])

    def test_full_port_scale_evidence_is_bounded(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, port_threshold=150)
        for port in range(1, 201):
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1",
                                 "protocol": "TCP", "src_port": 10000 + port,
                                 "dst_port": port, "tcp_flags": "S",
                                 "length": 60, "payload": b""})
        self.assertEqual([a["sid"] for a in recorder.alerts], [90003])
        evidence = recorder.alerts[0]["evidence"]
        self.assertIn("distinct_destination_ports=150", evidence)
        self.assertIn("(+54 more)", evidence)
        self.assertLess(len(evidence), 2000, "evidence must stay bounded at scanner scale")

    def test_single_port_probes_across_hosts_are_host_sweep_not_scan(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, ping_threshold=3)
        for host in range(2, 7):
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": f"198.51.100.{host}",
                                 "protocol": "TCP", "src_port": 40000,
                                 "dst_port": 443, "tcp_flags": "S",
                                 "length": 60, "payload": b""})
        # Zmap-class horizontal sweep: one port, many hosts -> host sweep, and
        # no per-host multi-port scan is fabricated.
        self.assertEqual([a["sid"] for a in recorder.alerts], [90002])

    def test_host_sweep_evidence_is_bounded(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, ping_threshold=70)
        for host in range(2, 82):
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": f"198.51.100.{host}",
                                 "protocol": "ICMP", "icmp_type": 8,
                                 "length": 64, "payload": b""})
        sweep = [alert for alert in recorder.alerts if alert["sid"] == 90002]
        self.assertEqual(len(sweep), 1)
        evidence = sweep[0]["evidence"]
        self.assertIn("distinct_targets=70", evidence)
        self.assertIn("(+6 more)", evidence)
        self.assertLess(len(evidence), 4000)

    def test_invalid_syn_fin_combination_is_anomaly_not_scan(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine)
        for port in (21, 22, 23):
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1",
                                 "protocol": "TCP", "src_port": 40000,
                                 "dst_port": port, "tcp_flags": "SF",
                                 "tcp_sequence": port, "length": 60, "payload": b""})
        self.assertEqual([a["sid"] for a in recorder.alerts], [90006, 90006, 90006])

    def test_simulated_live_attacker_scan(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, port_threshold=5, scan_window=15.0)
        attacker_ip = "198.51.100.250"
        target_ip = "192.168.1.100"
        # Attacker sends SYN packets across 5 different target ports
        for port in [21, 22, 80, 443, 8080]:
            core.process_packet({
                "src_ip": attacker_ip,
                "dst_ip": target_ip,
                "protocol": "TCP",
                "src_port": 50000,
                "dst_port": port,
                "tcp_flags": "S",
                "length": 60,
                "payload": b""
            })
        self.assertEqual(len(recorder.alerts), 1)
        self.assertEqual(recorder.alerts[0]["sid"], 90003)
        self.assertIn("port scan", recorder.alerts[0]["message"].lower())

    def test_acknowledged_established_traffic_does_not_trigger_scan(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, port_threshold=3)
        for port in [21, 22, 23, 80, 443]:
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1", "protocol": "TCP",
                                 "src_port": 40000, "dst_port": port, "tcp_flags": "A", "length": 60})
        self.assertEqual(recorder.alerts, [])

    def test_scan_state_isolated_by_source_destination_and_protocol(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, port_threshold=3)
        for port in [22, 80]:
            core.process_packet({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1", "protocol": "TCP", "src_port": 50000, "dst_port": port, "tcp_flags": "S", "length": 60})
        core.process_packet({"src_ip": "192.0.2.2", "dst_ip": "198.51.100.1", "protocol": "TCP", "src_port": 50001, "dst_port": 443, "tcp_flags": "S", "length": 60})
        self.assertEqual(recorder.alerts, [])

    def test_sustained_high_volume_throughput(self):
        recorder = RecordingAlerts()
        engine = DetectionEngine.__new__(DetectionEngine)
        engine.analyze_packet = lambda packet: []
        core = DeltaCore(recorder, engine, scan_window=5.0)
        # Feed 2,000 packets rapidly
        for i in range(2000):
            core.process_packet({
                "src_ip": "10.0.0.5",
                "dst_ip": "10.0.0.1",
                "protocol": "TCP",
                "src_port": 40000 + (i % 10),
                "dst_port": 80,
                "length": 1500,
                "payload": b"data"
            })
        self.assertEqual(core.packets_sniffed, 2000)
        self.assertGreater(core.total_data, 0)



class PersistenceAndConfigTests(unittest.TestCase):
    def test_python_alert_and_traffic_persist(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = AlertManager(str(Path(directory) / "nids.sqlite"), terminal=False, persist=True)
            packet = {"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1", "protocol": "TCP",
                      "src_port": 40000, "dst_port": 80, "length": 60, "details": {"ttl": 64}}
            traffic_id = manager.log_traffic(packet)
            manager.log_alert({**packet, "sid": 42, "gid": 1, "revision": 2, "message": "test"})
            self.assertEqual(traffic_id, 1)
            self.assertEqual(manager.session.query(__import__("database.models", fromlist=["TrafficLog"]).TrafficLog).count(), 1)
            self.assertEqual(manager.session.query(__import__("database.models", fromlist=["Alert"]).Alert).count(), 1)
            manager.close()

    def test_cli_validation(self):
        args = build_parser().parse_args(["--pcap", "x.pcap", "--persist", "--quiet"])
        self.assertEqual((args.pcap, args.persist, args.quiet), ("x.pcap", True, True))
        project = project_parser().parse_args(["--api-port", "8080", "--dashboard-port", "8081"])
        self.assertEqual((project.api_port, project.dashboard_port), (8080, 8081))

    def test_restart_reset_preserves_rules_and_clears_runtime_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "nids.sqlite")
            manager = AlertManager(path, terminal=False, persist=True)
            manager.persist_rules([{"sid": 99, "revision": 1, "message": "keep"}], "rules.json")
            manager.log_traffic({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1", "protocol": "ICMP", "length": 64})
            manager.log_alert({"src_ip": "192.0.2.1", "dst_ip": "198.51.100.1", "protocol": "ICMP", "sid": 1, "message": "old"})
            manager.reset_session_data()
            models = __import__("database.models", fromlist=["TrafficLog", "Alert", "Incident", "Rule", "Statistic"])
            self.assertEqual(manager.session.query(models.TrafficLog).count(), 0)
            self.assertEqual(manager.session.query(models.Alert).count(), 0)
            self.assertEqual(manager.session.query(models.Incident).count(), 0)
            self.assertEqual(manager.session.query(models.Statistic).count(), 0)
            self.assertEqual(manager.session.query(models.Rule).count(), 1)
            self.assertEqual(manager.get_recent_traffic(), [])
            self.assertEqual(manager.get_recent_alerts(), [])
            manager.close()

    def test_database_permissions_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "nids.sqlite"
            manager = AlertManager(str(path), terminal=False, persist=True)
            self.assertTrue(path.exists())
            manager.close()

    def test_invalid_rule_json_is_rejected(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as stream:
            stream.write(json.dumps({"sid": 1}))
            path = stream.name
        try:
            with self.assertRaises(ValueError):
                DetectionEngine(path)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
