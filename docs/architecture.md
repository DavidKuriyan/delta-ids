# Delta-NIDS architecture

Delta-NIDS is a passive, cross-platform Network Intrusion Detection System. It observes authorized live traffic or replays PCAP input, decodes packets, tracks bounded state, evaluates rules and behavioral detectors, persists evidence in SQLite, exposes an HTTP API, and renders the API data in the dashboard.

## Evidence flow

```text
Npcap/libpcap or PCAP replay
        ↓
packet capture and normalization
        ↓
Ethernet/IP/TCP/UDP/ICMP decoding
        ↓
flow and bounded behavioral state
        ↓
rule and scan detection
        ↓
alerts with packet-derived evidence
        ↓
SQLite traffic/alert/incident persistence
        ↓
native API → Flask proxy → dashboard
```

The common detection path receives normalized packets and does not depend on Linux or Windows APIs. Platform code is limited to interface enumeration, packet acquisition, privilege handling, filesystem paths, and system metrics.

## Scan detection contract

TCP/UDP scan detection uses a state key of source IP, destination IP, protocol, and probe class. TCP candidates are classified from observed flags (SYN, FIN, NULL, Xmas, Maimon/FIN+ACK); ACK-only probes require reverse response evidence in the Python path and remain conservative in the native path. Destination ports are deduplicated, state expires using a sliding window, and active keys/observations are bounded. Established ACK traffic, RST responses, unrelated destinations, and stale state must not create or inflate a scan event. Alert evidence contains the observed destination ports, not an inferred list of ports from scanner output.

## Incident correlation

Incidents retain their relationship to alert records. Correlation is evidence-based and constrained by source IP, destination IP, protocol, category, and the configured time window. The incident detail endpoint expands the related persisted alerts, including identifiers, rule metadata, timestamps, endpoints, ports, message, and evidence. Unrelated entities are not merged merely because they are temporally close.

## Runtime and storage

The dashboard consumes backend state and reports unavailable API data rather than generating placeholders. Reset operations clear persisted traffic, alerts, incidents, flows, and statistics while preserving schema and loaded rules; they do not stop capture or unload detection. Runtime counters are supplied by the capture/processing process when available.

## Passive-only contract

Delta-NIDS observes, analyzes, correlates, stores, and reports. It does not block, inject, modify, scan, exploit, reset connections, change firewall rules, or automatically respond to traffic.
