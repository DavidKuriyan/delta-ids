from __future__ import annotations

import ipaddress
import threading
import time
from collections import defaultdict, deque
from typing import Any


def _bounded_list(values, limit: int = 96) -> str:
    """Render a sorted list compactly, truncating huge scanner-scale evidence.

    Masscan/RustScan-class probes can cover the full 65,535-port space and
    Zmap-class host sweeps can cover large subnets. Alert evidence must stay
    bounded regardless of how many distinct ports or targets the scanner
    emits, while the complete distinct count is always preserved.
    """
    values = list(values)
    try:
        ordered = sorted(values)  # ports sort numerically, addresses as strings
    except TypeError:
        ordered = sorted(str(value) for value in values)
    if len(ordered) <= limit:
        return ", ".join(str(value) for value in ordered)
    return ", ".join(str(value) for value in ordered[:limit]) + f", ... (+{len(ordered) - limit} more)"


class DeltaCore:
    """Coordinates packet normalization, signature detection, and behavioral detection.

    Behavioral state is deliberately keyed by the complete observation scope. A
    scanner cannot contaminate another source, target, protocol, or scan class.
    The implementation reports observable behavior (not the originating tool).

    Evidence contract: every alert generated here is derived from observed
    packet fields (source, destination, protocol, ports, flags, ICMP metadata,
    timestamps). No synthetic or simulated events are ever generated.
    """

    TCP_FLAG_BITS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20}

    def __init__(self, alert_manager, detection_engine, scan_window: float = 30.0,
                 port_threshold: int = 8, ping_threshold: int = 5,
                 remote_sweep_threshold: int = 200,
                 remote_sweep_enabled: bool = False,
                 dns_threshold: int = 50, brute_force_threshold: int = 30):
        self.alert_manager = alert_manager
        self.detection_engine = detection_engine
        self.scan_window = float(scan_window)
        self.port_threshold = max(2, int(port_threshold))
        self.ping_threshold = max(2, int(ping_threshold))
        self.remote_sweep_threshold = max(2, int(remote_sweep_threshold))
        self.remote_sweep_enabled = bool(remote_sweep_enabled)
        self.dns_threshold = max(2, int(dns_threshold))
        self.brute_force_threshold = max(2, int(brute_force_threshold))
        self.total_data = 0
        self.unique_ips = set()
        self.flows = set()
        self.packets_sniffed = 0

        # (source, destination, protocol, probe class) -> observations.
        self._ports: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        # Host-discovery observations keyed by
        # (source, protocol, probe signature, target scope).
        self._hosts: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        # Source -> DNS query-rate observations (outbound queries, not replies).
        self._dns: dict[str, dict[str, Any]] = {}
        # (source, destination, destination port) -> connection failure observations.
        self._brute: dict[tuple[str, str, int], dict[str, Any]] = {}
        # (source, destination, protocol) -> last window epoch that emitted an
        # ICMP echo visibility event. Ordinary echo requests are a bounded,
        # low-severity visibility event, not an attack by themselves.
        self._icmp_events: dict[tuple[str, str, str], tuple[float, int]] = {}
        # Compatibility name retained for callers that inspect bounded ping
        # state; it references the same host-discovery map.
        self._pings = self._hosts
        self._last_ping: dict[tuple[str, str], float] = {}
        self._event_sequence = 0
        self._lock = threading.RLock()
        self._max_scan_states = 4096
        self._max_host_states = 4096
        self._max_dns_states = 1024
        self._max_brute_states = 1024
        self._max_icmp_event_states = 4096

    @staticmethod
    def _is_same_subnet(ip1: str, ip2: str) -> bool:
        try:
            a = ipaddress.ip_address(ip1)
            b = ipaddress.ip_address(ip2)
            return a.version == b.version and a.is_private and b.is_private and \
                str(a).rsplit(".", 1)[0] == str(b).rsplit(".", 1)[0]
        except ValueError:
            return False

    @staticmethod
    def _tcp_flags(value: Any) -> int:
        if isinstance(value, int):
            return value
        return sum(bit for name, bit in DeltaCore.TCP_FLAG_BITS.items()
                   if name in str(value or "").upper())

    @staticmethod
    def _flag_class(flags: int) -> str | None:
        """Return a behavioral class for an active TCP probe.

        ACK-only probes are inherently ambiguous from a passive vantage point,
        so they require the same multi-port threshold as other probes and are
        reported as "possible" behavior rather than a definitive scan.

        SYN+FIN returns None here because it is an invalid combination that is
        reported separately as a protocol anomaly.
        """
        if flags & 0x02 and flags & 0x01:
            # SYN+FIN is an invalid combination, not a normal SYN probe.
            return None
        if flags & 0x02 and not (flags & (0x10 | 0x04)):
            return "syn"
        if flags == 0x10:
            return "ack"
        if flags == (0x01 | 0x10):
            # Maimon-style probes use FIN+ACK.
            return "maimon"
        if flags == 0x01:
            return "fin"
        if flags == 0:
            return "null"
        if flags == (0x01 | 0x08 | 0x20):
            return "xmas"
        return None

    def _next_event_id(self, prefix: str) -> str:
        self._event_sequence += 1
        return f"{prefix}-{self._event_sequence}"

    def _alert(self, packet: dict, sid: int, severity: str, message: str,
               evidence: str | None = None, explanation: str | None = None,
               event_id: str | None = None, **extra: Any) -> None:
        alert = {**packet, "sid": sid, "severity": severity, "message": message,
                 "is_ml_anomaly": False}
        if evidence is not None:
            alert["evidence"] = evidence
        if explanation is not None:
            alert["explanation"] = explanation
        if event_id is not None:
            alert["event_id"] = event_id
        alert.update(extra)
        self.alert_manager.log_alert(alert)

    def _prune_ports(self, now: float) -> None:
        cutoff = now - self.scan_window
        for key, state in list(self._ports.items()):
            observations = state["observations"]
            while observations and observations[0][0] < cutoff:
                observations.popleft()
            if not observations:
                self._ports.pop(key, None)
                continue
            ports = {port for _, port in observations}
            if len(ports) < self.port_threshold:
                # Allow a later scan with the same source/target/class to emit a
                # new event after its previous window has genuinely ended.
                state["emitted"] = False
        if len(self._ports) > self._max_scan_states:
            oldest = sorted(self._ports, key=lambda key: self._ports[key]["observations"][-1][0])
            for key in oldest[:len(self._ports) - self._max_scan_states]:
                self._ports.pop(key, None)

    def _threshold_for(self, protocol: str, scope: str) -> int:
        """Distinct-target threshold for a host-discovery correlation bucket.

        Locally-scoped probes (private hosts on the local segment / private
        ranges) use the standard host-sweep threshold. Globally-routable
        (Internet) destinations are ordinary client egress and are only
        correlated when remote sweep detection is explicitly enabled, with a
        far higher threshold.
        """
        if scope == "public":
            return self.remote_sweep_threshold if self.remote_sweep_enabled else 0
        return self.ping_threshold

    def _prune_hosts(self, now: float) -> None:
        cutoff = now - self.scan_window
        for key, state in list(self._hosts.items()):
            observations = state["observations"]
            while observations and observations[0][0] < cutoff:
                observations.popleft()
            if not observations:
                self._hosts.pop(key, None)
                continue
            protocol, scope = key[1], key[3]
            threshold = self._threshold_for(protocol, scope)
            if threshold == 0 or len({target for _, target in observations}) < threshold:
                state["emitted"] = False
        if len(self._hosts) > self._max_host_states:
            oldest = sorted(self._hosts, key=lambda key: self._hosts[key]["observations"][-1][0])
            for key in oldest[:len(self._hosts) - self._max_host_states]:
                self._hosts.pop(key, None)

    def _prune_dns(self, now: float) -> None:
        cutoff = now - self.scan_window
        for key, state in list(self._dns.items()):
            observations = state["observations"]
            while observations and observations[0][0] < cutoff:
                observations.popleft()
            if not observations:
                self._dns.pop(key, None)
                continue
            if len(observations) < self.dns_threshold:
                state["emitted"] = False
        if len(self._dns) > self._max_dns_states:
            oldest = sorted(self._dns, key=lambda key: self._dns[key]["observations"][-1][0])
            for key in oldest[:len(self._dns) - self._max_dns_states]:
                self._dns.pop(key, None)

    def _prune_brute(self, now: float) -> None:
        cutoff = now - self.scan_window
        for key, state in list(self._brute.items()):
            observations = state["observations"]
            while observations and observations[0][0] < cutoff:
                observations.popleft()
            if not observations:
                self._brute.pop(key, None)
                continue
            if len(observations) < self.brute_force_threshold:
                state["emitted"] = False
        if len(self._brute) > self._max_brute_states:
            oldest = sorted(self._brute, key=lambda key: self._brute[key]["observations"][-1][0])
            for key in oldest[:len(self._brute) - self._max_brute_states]:
                self._brute.pop(key, None)

    def _prune_icmp_events(self, now: float) -> None:
        cutoff = now - self.scan_window
        for key, (seen_at, _window) in list(self._icmp_events.items()):
            if seen_at < cutoff:
                self._icmp_events.pop(key, None)
        if len(self._icmp_events) > self._max_icmp_event_states:
            oldest = sorted(self._icmp_events, key=lambda key: self._icmp_events[key][0])
            for key in oldest[:len(self._icmp_events) - self._max_icmp_event_states]:
                self._icmp_events.pop(key, None)

    @staticmethod
    def _target_scope(source: str, destination: str) -> str:
        """Classify a probed target: local, private, or public (Internet).

        Host discovery is a local-network reconnaissance behaviour. Targets on
        the same segment as the source, or inside private/documentation space,
        are the evidence of host discovery. Globally-routable destinations are
        ordinary client egress (web browsing, API calls, CDN traffic) and are
        not counted as local host discovery unless remote sweep detection is
        explicitly enabled with a high volume threshold.
        """
        try:
            import ipaddress
            address = ipaddress.ip_address(destination)
            if DeltaCore._is_same_subnet(source, destination) and not address.is_global:
                return "local"
            if address.is_global:
                return "public"
            return "private"
        except ValueError:
            return "public"

    def _host_discovery(self, packet: dict, now: float) -> None:
        protocol = str(packet.get("protocol") or "").upper()
        source = packet.get("src_ip")
        destination = packet.get("dst_ip")
        if not source or not destination:
            return

        if protocol in ("ICMP", "ICMPV6") and packet.get("icmp_type") in (8, 128):
            # Ordinary ICMP echo requests are not attacks by themselves. Report
            # each (source, destination, protocol) pair at most once per scan
            # window as a bounded INFO-level visibility event. Capture-level
            # duplicates are already removed upstream; repeated real pings
            # aggregate into one event whose occurrence count grows, so normal
            # ping traffic cannot flood the alert stream.
            window_epoch = int(now // self.scan_window)
            key = (str(source), str(destination), str(protocol))
            previous = self._icmp_events.get(key)
            if previous is None or previous[1] != window_epoch:
                self._icmp_events[key] = (now, window_epoch)
                self._prune_icmp_events(now)
                self._alert(packet, 90001, "INFO",
                            f"{protocol} echo request from {source} to {destination}",
                            evidence=(f"protocol={protocol}; icmp_type={packet.get('icmp_type')}; "
                                      f"source={source}; destination={destination}; "
                                      f"window_seconds={self.scan_window:g}; window_epoch={window_epoch}"),
                            explanation="captured ICMP echo request visibility event; not by itself an attack",
                            event_id=f"icmp-request-{source}-{destination}-{window_epoch}",
                            detection_type="icmp_visibility", confidence=20)
            signature = "echo"
            active = True
        elif protocol == "TCP":
            flags = self._tcp_flags(packet.get("tcp_flags"))
            # Only unacknowledged SYN probes are multi-host discovery evidence;
            # established conversation traffic is ordinary client communication.
            active = bool(flags & 0x02 and not (flags & (0x10 | 0x04)))
            # A horizontal host sweep probes the same service port across many
            # hosts. Grouping by destination port prevents unrelated
            # conversations (e.g. a client reaching several different services)
            # from aggregating into a fake sweep.
            signature = str(packet.get("dst_port") or "0")
        else:
            # ARP requests no longer participate in host-discovery sweeps:
            # normal gateway neighbor resolution is L2 housekeeping, not a
            # scan, so ARP is intentionally never correlated here.
            return
        if not active:
            return

        scope = self._target_scope(source, destination)
        if scope == "public" and not self.remote_sweep_enabled:
            # Normal Internet egress (browsing, CDNs, API traffic) must never
            # be mistaken for local-network host discovery.
            return
        threshold = self._threshold_for(protocol, scope)
        if threshold == 0:
            return

        key = (str(source), str(protocol), signature, scope)
        state = self._hosts.setdefault(key, {"observations": deque(), "emitted": False})
        # Distinct targets only: retransmissions and capture-level duplicates
        # of a probe to the same host must not inflate the threshold.
        targets = {target for _, target in state["observations"]}
        if str(destination) not in targets:
            state["observations"].append((now, str(destination)))
            targets.add(str(destination))
        self._prune_hosts(now)
        targets = {target for _, target in state["observations"]}
        if len(targets) >= threshold and not state["emitted"]:
            state["emitted"] = True
            event_id = self._next_event_id("host-sweep")
            window_span = 0.0
            if state["observations"]:
                window_span = state["observations"][-1][0] - state["observations"][0][0]
            evidence = (f"detection_type=host_discovery; source={source}; protocol={protocol}; "
                        f"scope={scope}; probe_signature={signature}; "
                        f"window_seconds={self.scan_window:g}; window_span_seconds={window_span:g}; "
                        f"distinct_targets={len(targets)}; probes={len(state['observations'])}; "
                        f"targets=[{_bounded_list(targets, limit=64)}]")
            self._alert(packet, 90002, "High",
                        f"{protocol} host discovery sweep from {source} ({len(targets)} targets)",
                        evidence=evidence,
                        explanation="behavioral distinct-target host-discovery threshold reached on "
                                    f"{protocol} scope {scope} within {self.scan_window:g}s",
                        event_id=event_id,
                        detection_type="host_discovery",
                        confidence=90)

    def _dns_anomaly(self, packet: dict, now: float) -> None:
        """Report anomalous outbound DNS query volume from a single source.

        Responses (source port 53) and unresolved packets are not counted. The
        event is emitted as soon as the threshold is reached within the window,
        matching the streaming behavior used for port scans.
        """
        if packet.get("dst_port") != 53:
            return
        source = packet.get("src_ip")
        if not source or packet.get("src_port") == 53:
            return
        destination = packet.get("dst_ip")
        key = str(source)
        state = self._dns.setdefault(key, {"observations": deque(), "emitted": False})
        state["observations"].append((now, str(destination)))
        self._prune_dns(now)
        count = len(state["observations"])
        if count < self.dns_threshold or state["emitted"]:
            return
        state["emitted"] = True
        event_id = self._next_event_id("dns-anomaly")
        destinations = {item[1] for item in state["observations"]}
        evidence = (f"source={source}; protocol=UDP; service=dns; window_seconds={self.scan_window:g}; "
                    f"query_count={count}; distinct_destinations={len(destinations)}; "
                    f"destinations=[{', '.join(sorted(destinations))}]")
        self._alert(packet, 90004, "Medium",
                    f"high DNS query rate from {source} ({count} queries in {self.scan_window:g}s)",
                    evidence=evidence,
                    explanation="behavioral DNS query-rate threshold reached",
                    event_id=event_id,
                    detection_type="dns_anomaly", confidence=65)

    def _repeated_connection_failures(self, packet: dict, now: float) -> None:
        """Report repeated bare RST/FIN closures toward one service endpoint.

        From a passive vantage point, authentication success/failure is not
        visible for encrypted protocols. Repeated abandoned or failed
        connections to a single (destination, destination port) are the
        observable analogue of brute-force-like scanning and are reported here
        with bounded, windowed state.

        Only *bare* RST and FIN packets are counted (no ACK/SYN/PSH/URG). This
        excludes normal teardown (FIN+ACK), target rejection responses
        (RST+ACK), and probe classes such as Xmas (FIN+PSH+URG), so ordinary
        traffic and scan responses cannot accumulate as failures.
        """
        if str(packet.get("protocol") or "").upper() != "TCP":
            return
        flags = self._tcp_flags(packet.get("tcp_flags"))
        if flags not in (0x04, 0x01):
            return
        source = packet.get("src_ip")
        destination = packet.get("dst_ip")
        dst_port = packet.get("dst_port")
        if not source or not destination or dst_port is None:
            return
        key = (str(source), str(destination), int(dst_port))
        state = self._brute.setdefault(key, {"observations": deque(), "emitted": False})
        state["observations"].append((now,))
        self._prune_brute(now)
        count = len(state["observations"])
        if count < self.brute_force_threshold or state["emitted"]:
            return
        state["emitted"] = True
        event_id = self._next_event_id("connection-failures")
        evidence = (f"source={source}; destination={destination}; destination_port={int(dst_port)}; "
                    f"protocol=TCP; window_seconds={self.scan_window:g}; "
                    f"connection_failures={count}; failure_flags=bare-RST,FIN")
        self._alert(packet, 90005, "Medium",
                    f"repeated TCP connection failures from {source} to {destination}:{dst_port} ({count} in {self.scan_window:g}s)",
                    evidence=evidence,
                    explanation="behavioral repeated-connection-failure threshold reached",
                    event_id=event_id,
                    detection_type="connection_failures", confidence=75)

    def _tcp_anomaly(self, packet: dict) -> None:
        """Report invalid TCP flag combinations (SYN+FIN) as protocol anomalies.

        The classification does not depend on the originating tool; SYN+FIN is
        invalid for every TCP implementation (RFC 793).
        """
        source = packet.get("src_ip")
        destination = packet.get("dst_ip")
        if not source or not destination:
            return
        flags = self._tcp_flags(packet.get("tcp_flags"))
        if not (flags & 0x02) or not (flags & 0x01):
            return
        self._alert(packet, 90006, "Low",
                    f"invalid TCP flag combination from {source} to {destination}",
                    evidence=(f"protocol=TCP; tcp_flags={packet.get('tcp_flags')}; "
                              f"source={source}; destination={destination}; "
                              f"dst_port={packet.get('dst_port')}; tcp_sequence={packet.get('tcp_sequence')}"),
                    explanation="SYN+FIN is not a valid TCP flag combination (RFC 793)",
                    event_id=f"tcp-anomaly-{source}-{destination}-{packet.get('tcp_sequence', '')}",
                    detection_type="tcp_anomaly", confidence=90)

    def _emit_probe_if_ready(self, packet: dict, source: str, destination: str,
                             protocol: str, probe_class: str, state: dict[str, Any]) -> None:
        observations = state["observations"]
        ports_seen = {observed_port for _, observed_port in observations}
        response_counts = {name: sum(name in values for values in state["responses"].values())
                           for name in ("syn_ack", "rst", "icmp_unreachable")}
        # An ACK-only packet is common in established traffic. Only call a
        # multi-port ACK pattern a scan when the target also produced response
        # evidence (normally RSTs), making the result defensible passively.
        if probe_class == "ack" and response_counts["rst"] == 0 and response_counts["icmp_unreachable"] == 0:
            return
        if len(ports_seen) < self.port_threshold or state["emitted"]:
            return
        state["emitted"] = True
        event_id = self._next_event_id(f"{protocol.lower()}-{probe_class}-scan")
        ports = _bounded_list(ports_seen)
        evidence = (f"source={source}; destination={destination}; protocol={protocol}; "
                    f"probe_class={probe_class}; window_seconds={self.scan_window:g}; "
                    f"distinct_destination_ports={len(ports_seen)}; ports=[{ports}]; "
                    f"responses={response_counts}")
        qualifier = "possible " if probe_class == "ack" else ""
        self._alert({**packet, "src_ip": source, "dst_ip": destination,
                     "dst_port": observations[-1][1]},
                    90003, "High",
                    f"{qualifier}{protocol} {probe_class.upper()} port scan from {source} to {destination} ({len(ports_seen)} ports)",
                    evidence=evidence,
                    explanation="behavioral active-probe threshold reached",
                    event_id=event_id,
                    scan_class=probe_class,
                    response_counts=response_counts,
                    detection_type="port_scan", confidence=85)

    def _record_probe(self, packet: dict, source: str, destination: str,
                      protocol: str, probe_class: str, port: int, now: float,
                      response: str | None = None) -> None:
        key = (source, destination, protocol, probe_class)
        state = self._ports.setdefault(key, {"observations": deque(), "responses": defaultdict(set), "emitted": False})
        observations = state["observations"]
        # One source/target/class/port observation represents one probe target;
        # retransmissions and duplicate capture paths must not inflate it.
        if not any(existing_port == port for _, existing_port in observations):
            observations.append((now, port))
        if response:
            state["responses"][port].add(response)
        self._prune_ports(now)
        ports_seen = {observed_port for _, observed_port in observations}
        if len(ports_seen) < self.port_threshold:
            state["emitted"] = False
        response_counts = {name: sum(name in values for values in state["responses"].values())
                           for name in ("syn_ack", "rst", "icmp_unreachable")}
        # An ACK-only packet is common in established traffic. Only call a
        # multi-port ACK pattern a scan when the target also produced response
        # evidence (normally RSTs), making the result defensible passively.
        if probe_class == "ack" and response_counts["rst"] == 0 and response_counts["icmp_unreachable"] == 0:
            return
        if len(ports_seen) >= self.port_threshold and not state["emitted"]:
            state["emitted"] = True
            event_id = self._next_event_id(f"{protocol.lower()}-{probe_class}-scan")
            ports = _bounded_list(ports_seen)
            evidence = (f"source={source}; destination={destination}; protocol={protocol}; "
                        f"probe_class={probe_class}; window_seconds={self.scan_window:g}; "
                        f"distinct_destination_ports={len(ports_seen)}; ports=[{ports}]; "
                        f"responses={response_counts}")
            qualifier = "possible " if probe_class == "ack" else ""
            self._alert({**packet, "src_ip": source, "dst_ip": destination, "dst_port": port},
                        90003, "High",
                        f"{qualifier}{protocol} {probe_class.upper()} port scan from {source} to {destination} ({len(ports_seen)} ports)",
                        evidence=evidence,
                        explanation="behavioral active-probe threshold reached",
                        event_id=event_id,
                        scan_class=probe_class,
                        response_counts=response_counts,
                        detection_type="port_scan", confidence=85)

    def _scan_detection(self, packet: dict) -> None:
        now = float(packet.get("_monotonic", time.monotonic()))
        source = packet.get("src_ip")
        destination = packet.get("dst_ip")
        if not source or not destination:
            return
        protocol = str(packet.get("protocol") or "").upper()
        self._host_discovery(packet, now)

        if protocol == "TCP" and packet.get("dst_port") is not None:
            flags = self._tcp_flags(packet.get("tcp_flags"))
            self._tcp_anomaly(packet)
            self._repeated_connection_failures(packet, now)
            # Correlate target responses with each active probe class. The
            # response source port is the probed destination port.
            if flags & 0x04 or (flags & 0x12) == 0x12:
                response_kind = "rst" if flags & 0x04 else "syn_ack"
                for probe_class in ("syn", "fin", "null", "xmas", "maimon", "ack"):
                    response_key = (str(destination), str(source), "TCP", probe_class)
                    response_state = self._ports.get(response_key)
                    if response_state is None or packet.get("src_port") is None:
                        continue
                    response_state["responses"][int(packet["src_port"])].add(response_kind)
                    self._emit_probe_if_ready(packet, str(destination), str(source), "TCP",
                                               probe_class, response_state)
            probe_class = self._flag_class(flags)
            if probe_class is not None:
                self._record_probe(packet, str(source), str(destination), "TCP", probe_class,
                                   int(packet["dst_port"]), now)
            return

        if protocol == "UDP" and packet.get("dst_port") is not None:
            self._dns_anomaly(packet, now)
            # A UDP packet with no payload is still an observable UDP probe. Do
            # not classify common server-source replies as outbound probes.
            if packet.get("src_port") not in (53, 67, 68, 123, 161):
                self._record_probe(packet, str(source), str(destination), "UDP", "udp",
                                   int(packet["dst_port"]), now)
            return

        # ICMP port-unreachable messages carry the original UDP probe. The
        # scanner/target/port are recovered from the quoted inner IP packet.
        if protocol in ("ICMP", "ICMPV6") and packet.get("icmp_type") in (1, 3):
            inner_protocol = str(packet.get("icmp_inner_protocol") or "").upper()
            inner_source = packet.get("icmp_inner_src_ip")
            inner_destination = packet.get("icmp_inner_dst_ip")
            inner_port = packet.get("icmp_inner_dst_port")
            if inner_protocol in ("UDP", "17", "58") and inner_source and inner_destination and inner_port is not None:
                self._record_probe({**packet, "src_ip": inner_source, "dst_ip": inner_destination},
                                   str(inner_source), str(inner_destination), "UDP", "udp",
                                   int(inner_port), now, response="icmp_unreachable")

    def process_packet(self, packet):
        # Rule refresh is synchronized inside DetectionEngine; capture remains
        # the owner of packet ordering and is never stopped for an update.
        refresh = getattr(self.detection_engine, "refresh_if_changed", None)
        if refresh is not None:
            refresh()
        with self._lock:
            self.packets_sniffed += 1
            self.total_data += int(packet.get("length", 0) or 0)
            self.unique_ips.update(filter(None, (packet.get("src_ip"), packet.get("dst_ip"))))
            if packet.get("src_ip") and packet.get("dst_ip"):
                self.flows.add((packet.get("src_ip"), packet.get("src_port"), packet.get("dst_ip"),
                                packet.get("dst_port"), packet.get("protocol")))
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