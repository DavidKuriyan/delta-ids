from __future__ import annotations

import ipaddress
import threading
import time
from collections import defaultdict, deque
from typing import Any




class DeltaCore:
    """Coordinates packet normalization, signature detection, and scan detection."""

    def __init__(self, alert_manager, detection_engine, scan_window: float = 30.0,
                 port_threshold: int = 8, ping_threshold: int = 3):
        self.alert_manager = alert_manager
        self.detection_engine = detection_engine
        self.scan_window = scan_window
        self.port_threshold = port_threshold
        self.ping_threshold = ping_threshold
        self.total_data = 0
        self.unique_ips = set()
        self.flows = set()
        self.packets_sniffed = 0
        # Scan state is keyed by source, destination, and protocol. Each entry
        # stores packet timestamps with its ports so the sliding window expires
        # individual observations rather than resetting the whole set abruptly.
        self._ports = defaultdict(lambda: {"observations": deque(), "emitted": False})
        self._pings = defaultdict(lambda: {"observations": deque(), "emitted": False})
        self._last_ping = {}
        self._lock = threading.Lock()
        self._max_scan_states = 4096

    @staticmethod
    def _is_same_subnet(ip1: str, ip2: str) -> bool:
        """Return True when both addresses are RFC 1918 private IPs in the
        same /24 subnet (e.g. 192.168.68.0/24).  Local subnet pings are
        normal network housekeeping and should not generate alerts."""
        try:
            a = ipaddress.ip_address(ip1)
            b = ipaddress.ip_address(ip2)
            if not (a.is_private and b.is_private):
                return False
            return str(a).rsplit(".", 1)[0] == str(b).rsplit(".", 1)[0]
        except ValueError:
            return False

    def _alert(self, packet, sid, severity, message):
        self.alert_manager.log_alert({**packet, "sid": sid, "severity": severity,
                                      "message": message, "is_ml_anomaly": False})

    def _scan_detection(self, packet):
        src, dst = packet.get("src_ip"), packet.get("dst_ip")
        now = float(packet.get("_monotonic", time.monotonic()))
        if not src or not dst:
            return
        # Detect both echo-request (type 8) and echo-reply (type 0) so that
        # pings from an external host (e.g. Kali → Windows) are caught regardless
        # of which direction Npcap happens to capture first.
        icmp_type = packet.get("icmp_type")
        if packet.get("protocol") == "ICMP" and icmp_type in (0, 8):
            # Only raise a standalone alert for echo REQUESTS (type 8) — these
            # mean "someone is actively pinging this machine" which is the genuine
            # security event. Echo replies (type 0) are our own machine responding;
            # alerting on them would be a false positive.
            # Both types are still tracked below for ping-sweep counting.
            if icmp_type == 8:
                if now - self._last_ping.get((src, dst), 0) >= 1:
                    self._last_ping[(src, dst)] = now
                    # Suppress the per-ping alert when both IPs are on the same
                    # local subnet — pings between neighbours (e.g. gateway ↔
                    # host) are normal network housekeeping, not probes.
                    if not self._is_same_subnet(src, dst):
                        self._alert(packet, 90001, "Medium", f"ICMP echo request from {src} to {dst}")
            state = self._pings[src]
            observations = state["observations"]
            observations.append((now, dst))
            cutoff = now - self.scan_window
            while observations and observations[0][0] < cutoff:
                observations.popleft()
            targets = {destination for _, destination in observations}
            if len(targets) < self.ping_threshold:
                state["emitted"] = False
            elif not state["emitted"]:
                state["emitted"] = True
                self._alert(packet, 90002, "High", f"ICMP ping sweep from {src} ({len(targets)} targets)")
        if packet.get("protocol") in ("TCP", "UDP") and packet.get("dst_port") is not None:
            protocol = str(packet["protocol"]).upper()
            # A scan is an active probe pattern, not ordinary established traffic.
            # Restrict TCP candidates to SYN-bearing packets and exclude replies;
            # this prevents one long-lived connection from accumulating as a scan.
            flags = str(packet.get("tcp_flags") or "").upper()
            if protocol == "TCP" and ("S" not in flags or "A" in flags or "R" in flags):
                return
            # UDP replies must not be treated as probes.
            if protocol == "UDP" and packet.get("src_port") in (53, 67, 68, 123):
                return
            state = self._ports[(src, dst, protocol)]
            observations = state["observations"]
            observation = (now, int(packet["dst_port"]))
            # A packet replayed or delivered twice must not inflate scan state.
            if not any(existing_port == observation[1] for _, existing_port in observations):
                observations.append(observation)
            cutoff = now - self.scan_window
            while observations and observations[0][0] < cutoff:
                observations.popleft()
            ports_seen = {port for _, port in observations}
            if len(ports_seen) < self.port_threshold:
                state["emitted"] = False
            if len(self._ports) > self._max_scan_states:
                oldest_key = min(self._ports, key=lambda key: self._ports[key]["observations"][0][0] if self._ports[key]["observations"] else now)
                if oldest_key != (src, dst, protocol):
                    self._ports.pop(oldest_key, None)
            if len(ports_seen) >= self.port_threshold and not state["emitted"]:
                state["emitted"] = True
                ports = ", ".join(str(port) for port in sorted(ports_seen))
                evidence = (f"source={src}; destination={dst}; protocol={protocol}; "
                            f"window_seconds={self.scan_window:g}; distinct_destination_ports="
                            f"{len(ports_seen)}; ports=[{ports}]")
                self._alert({**packet, "evidence": evidence,
                             "explanation": "behavioral port-scan threshold reached"},
                            90003, "High", f"{protocol} port scan from {src} to {dst} ({len(ports_seen)} ports)")

    def process_packet(self, packet):
        with self._lock:
            self.packets_sniffed += 1
            self.total_data += int(packet.get("length", 0) or 0)
            self.unique_ips.update(filter(None, (packet.get("src_ip"), packet.get("dst_ip"))))
            if packet.get("src_ip") and packet.get("dst_ip"):
                self.flows.add((packet.get("src_ip"), packet.get("src_port"), packet.get("dst_ip"), packet.get("dst_port"), packet.get("protocol")))
        traffic_id = self.alert_manager.log_traffic(packet)
        if traffic_id:
            packet["traffic_id"] = traffic_id
        if self.alert_manager.session:
            self.alert_manager._persist_statistic("packets_processed", self.packets_sniffed)
            self.alert_manager._persist_statistic("bytes_processed", self.total_data)
        self._scan_detection(packet)
        for alert in self.detection_engine.analyze_packet(packet):
            alert.setdefault("traffic_id", packet.get("traffic_id"))
            self.alert_manager.log_alert(alert)
