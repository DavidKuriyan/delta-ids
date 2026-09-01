# Nmap SYN-scan investigation and network-visibility validation

This document records the end-to-end investigation of a real incident:

```text
Windows attack host executed:  nmap -sS 10.35.194.204
NIDS host:                     Kali Linux running Delta-NIDS
Result:                        Delta-NIDS produced alerts for the ICMP probes
                               but no TCP port-scan alert
```

The purpose of this document is the required root-cause discipline: do **not**
assume that a SYN port scan actually reached the target, and do **not** add a
detection rule to compensate for a network-topology problem.

## 1. What the Nmap transcript actually says

```text
Nmap 7.99 ( https://nmap.org ) at 2026-09-01 09:04 +0530
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 1.65 seconds
```

`nmap -sS` starts with **host discovery**. Only if at least one host responds
does Nmap proceed to the SYN port-scan phase. The transcript (`0 hosts up`)
shows the port-scan phase never ran, because the target (10.35.194.204)
produced no reply to Nmap's discovery probes.

The Delta-NIDS alert queue from the same window confirms exactly that:
SID 90001 ICMP echo request alerts for `10.35.194.126 -> 10.35.194.204`
(three consecutive echo-request observations) — i.e. Delta-NIDS *did* capture
Nmap's ICMP host-discovery probes. A multi-port SYN scan was simply never sent,
so there was nothing for the scan detector to classify.

### Required fix at the test layer, not the detector

Repeat the test with the port-scan phase forced and the target able to receive
the probes:

```bash
nmap -Pn -sS 10.35.194.204          # skip host discovery; run the SYN scan
nmap -Pn -sT 10.35.194.204          # TCP connect scan
nmap -Pn -sU --top-ports 50 ...     # UDP scan (responses from target required)
nmap -Pn -sA ... -sF ... -sN ... -sX ...   # ACK / FIN / NULL / Xmas
```

If the target is deliberately blocking probes, run the scan *from* the Kali
sensor against an authorized test host such that the sensors sees both
directions, or configure `--scan-delay` so the traffic is not bursty.

## 2. Investigate packet generation and capture visibility first

Walk each layer before touching Delta-NIDS detection code:

```text
Windows
  └─ Nmap actually sent frames?        tcpdump on Windows side / pktmon
       └─ VM / network path carries them?  VirtualBox adapter mode
            └─ Kali interface sees frames?  tcpdump on the sensor interface
                 └─ Delta capture layer opens the interface?  --list-interfaces
                      └─ Decoder normalizes the packets?      capture counters
                           └─ Detection engine evaluates them? rule/behavior state
```

### 2.1 Independent packet evidence

While the scan runs, confirm frames are physically visible to the sensor
*outside* Delta-NIDS:

```bash
sudo tcpdump -i eth0 -nn 'tcp[tcpflags] & tcp-syn != 0' -c 100
sudo tcpdump -i eth0 -nn 'icmp' -c 100
ip -s link show eth0            # interface RX counters (packet drops)
ip -s -s link show eth0         # per-protocol RX error/drop counters
ethtool -S eth0 | grep -E 'rx_|drop'   # driver-level counters where available
```

Delta-NIDS's own counters are reported in `/api/status` (`packets_captured`,
`packets_processed`, `packets_failed`, `last_packet_time`) and on the
dashboard. If tcpdump sees SYN frames but Delta-NIDS does not, the problem is
in the capture/decoder path. If tcpdump sees nothing, the problem is upstream
of the sensor — no detector change can or should fix it.

### 2.2 VM / network topology checklist (VirtualBox, Windows -> Kali)

| Layer | Question | Typical failure | Evidence |
|---|---|---|---|
| Windows side | Did Nmap send anything? | Firewall blocked Nmap | `pktmon`, Windows Firewall logs, `netstat` |
| Adapter mode | Does the virtual NIC carry the frames? | NAT hides the Windows host from Kali capture | Kali cannot *see* host traffic at all |
| Bridged | Frames reach the physical segment (promiscuous NIC) | VMware/VirtualBox promiscuous mode restrictions | `tcpdump -i eth0` on Kali sees the scan |
| Host-only / internal | Only VM-to-VM traffic is visible | Correct interface not selected | `--list-interfaces` and capture on the host-only adapter |
| Sensor interface | The selected adapter matches the one carrying traffic | Auto-select picked the wrong NIC | `run_project.py --interface eth0`, compare counters |
| Kali firewall | Firewall drops or replies | `nftables`/`iptables` rules drop SYN | `nft list ruleset`, `iptables -S`; NIDS is passive but its *target* behaviour affects responses |
| Promiscuous mode | NIC sees traffic not addressed to it | SPAN-less switched port | Configure SPAN/port mirror or bridged promiscuous capture |
| BPF filter | Capture filter excludes the traffic | `--filter` narrower than expected | Default filter is empty = all protocols; any custom filter is honoured as-is |
| Target address | The scanned IP is actually the sensor's IP | Nmap targeting a different host | `ip addr`, `--list-interfaces` |

A passive NIDS on a **switched** network segment only sees traffic to/from its
own interface plus broadcast/multicast unless the port is mirrored (SPAN) or
the adapter operates in promiscuous mode on a hub/bridge. VirtualBox
**bridged** networking combined with a promiscuous-capable virtual adapter is
the setup that makes a Windows->Kali Nmap run visible to the Kali sensor;
**NAT** generally makes it invisible.

## 3. Why Delta-NIDS behaves correctly in this incident

- Real probes captured: the ICMP echo-request visibility alerts (SID 90001,
  `INFO`) prove Nmap's discovery traffic reached the capture layer.
- No scan was fabricated: with no multi-port probe stream, emitting a SYN
  port-scan alert would be exactly the kind of fake detection this project
  forbids ("if there is no real evidence, do not generate an alert").
- The `"TCP host discovery sweep"` alert (SID 90002, `IPv6`) observed in the
  same queue is evidence-keyed behavior from earlier IPv6 host-sweep traffic,
  generated only after the configured distinct-target threshold was met.

## 4. Verifying the active SYN path end-to-end (controlled, authorized)

The offline matrix in `tools/validate_local.py` replays a deterministic SYN,
FIN, NULL, Xmas, ACK, UDP, connect-scan, host-sweep, DNS, HTTP, and
brute-force pattern through the real pipeline and reports PASS/FAIL per case:

```bash
.venv/bin/python tools/validate_local.py
```

For a live confirmation on an authorized test network:

```bash
# Terminal A: sensor capture (Kali)
sudo -E env HOME="$HOME" .venv/bin/python run_project.py --interface eth0

# Terminal B: independent visibility check (Kali)
sudo tcpdump -i eth0 -nn -s 0 -w /tmp/nmap-syn.pcap

# Terminal C: authorized scan (Windows or a separate host on the same segment)
nmap -Pn -sS <sensor-ip>
```

Acceptance evidence: `tcpdump` records SYN frames; `run_project.py` capture
counters increase; `/api/alerts` contains one SID 90003 alert whose evidence
lists the distinct destination ports; no other SIDs are produced by that run.

## 4.5 Measured result of an autonomous live check (2026-09-01)

A live validation attempt from the sensor itself established the following
facts with real evidence (the sensor is `eth0 = 10.35.194.204`):

- The sensor NIC **does** live-capture real traffic with **0 dropped packets**
  (dumpcap counters: `Packets received/dropped on interface 'eth0': 41/0`).
  With a permissive capture it records neighbor traffic from `10.35.194.126`
  (the Windows scanner host) toward `140.82.114.25:443`, plus VPN heartbeat
  UDP — i.e. the capture visibility required for the original Windows→Kali
  scenario is present at the NIC.
- Replaying that genuinely captured traffic through the full production stack
  (`run_project.py --pcap`) produced 41 real traffic rows, 3 loaded rules,
  `packets_failed: 0`, and **0 alerts** — the correct outcome, because that
  capture contained no scan/anomalous evidence. No alert is fabricated when
  evidence does not exist.
- **A lone-sensor self-scan cannot exercise the NIC:** a 100-port
  `nmap -Pn -sT 10.35.194.204` (raw connect scan) while capturing `eth0`
  produced 0 captured SYN probes, because the kernel's local route loops
  traffic to the host's own IP via `lo`. Scan traffic must originate from a
  second host on the segment (for example Windows `10.35.194.126`).
- `nmap -Pn -sS` (raw-packet injection) and the production live-capture
  backend (scapy/libpcap) require root; dumpcap was usable unprivileged via
  the `wireshark` group for the independent capture in this check.

### Exact two-side live confirmation (with root and a second host)

Terminal A — Kali sensor (capture with libpcap and independent tcpdump evience):

```bash
sudo -E env HOME="$HOME" .venv/bin/python run_project.py --interface eth0 --db /tmp/live-nmap.sqlite
# in a second terminal while it runs:
sudo tcpdump -i eth0 -nn -s 0 -w /tmp/nmap-syn.pcap
```

Terminal B — Windows host (the authorized scanner from the original incident):

```powershell
nmap -Pn -sS 10.35.194.204 --top-ports 100
```

Afterwards, verify the evidence-backed alert (dedicated writable DB):

```bash
.venv/bin/python - <<'EOF'
import sqlite3
con = sqlite3.connect('/tmp/live-nmap.sqlite')
rows = con.execute("SELECT sid, message, evidence FROM alerts WHERE sid=90003 ORDER BY id DESC").fetchall()
assert rows, "no SID 90003 alert found"
for sid, message, evidence in rows:
    print(sid, message)
    print(' ', evidence)
EOF
```

Acceptance: the alert evidence lists the distinct destination ports Nmap
probed, `packets_failed` is 0, and `tcpdump` shows SYN frames matching the
scan.

## 5. What was changed in the engine because of this investigation

The investigation confirmed the detector did not need a "detect Nmap" clause.
The following behavioural improvements were made so the *same* observable
behaviour is detected regardless of tool:

- Streamed/sliding-window scan state: an alert is emitted the moment the
  distinct-port threshold is reached within the window, not when a batch
  completes (SID 90003).
- SYN+FIN and other invalid flag combinations are classified as protocol
  anomalies (SID 90006) instead of being silently discarded.
- Discovery probes (ICMP echo requests) produce bounded per-window INFO
  visibility events (SID 90001) so normal ping traffic cannot flood the alert
  stream; host-discovery sweeps still alarm at `High` once multiple distinct
  targets are observed (SID 90002).

## 6. Post-fix host-discovery validation (no false sweeps from normal traffic)

After the scope-aware fix, the previously reported `"TCP host discovery sweep"`
alerts from ordinary traffic are classified as false positives and cannot be
regenerated:

| Claimed alert | Why it was false | Post-fix behavior |
|---|---|---|
| `ARP host discovery sweep from 192.168.68.1 (N targets)` | A gateway ARPing neighbors inside the window is normal L2 resolution, regardless of how many hosts it resolves | The ARP host-discovery sweep rule was **removed**: ARP requests never correlate into a SID 90002 sweep, and `DELTA_NIDS_ARP_SWEEP_THRESHOLD` no longer exists |
| `TCP host discovery sweep from 192.168.68.112/110 (3 targets)` | 3 SYNs to ordinary *public* destinations (e.g. Google `142.250.183.170`) is client egress (browsing/CDN/API), not host discovery | Host-discovery correlation excludes globally-routable (Internet) destinations by default (`DELTA_NIDS_REMOTE_SWEEP_ENABLED=false`); public targets only correlate when remote sweeping is explicitly enabled with a far higher threshold (`DELTA_NIDS_REMOTE_SWEEP_THRESHOLD`, default 200) |
| `ICMP echo request from 192.168.68.1 to 192.168.68.112` (SID 90001) | Not a false positive: a single observed ICMP echo is reported as a bounded INFO visibility event, never as an attack | Unchanged by design; only multi-target sweeps alarm at High |

Additional evidence rules applied to SID 90002:

- TCP host sweeps are correlated **per destination port** — unrelated
  conversations on different ports cannot aggregate into a fake sweep, and
  retransmissions/duplicates of a probe to the same target never inflate the
  distinct-target count.
- Correlation state is windowed (`DELTA_NIDS_SCAN_WINDOW`, default 30s) and
  pruned; stale flows never contribute to later alerts.
- The alert is only emitted when the configured distinct-target threshold is
  actually satisfied, and the evidence records exactly the targets counted
  (`distinct_targets=N; targets=[...]`).
- Alerts stored by the pre-fix detector whose evidence cannot justify a sweep
  can be removed without touching valid data:
  `python main.py --db <path> --purge-false-positives`.

Regression coverage lives in `tests/test_host_discovery.py` (normal-traffic
negatives and real-sweep positives) and in the offline matrix
(`tools/validate_local.py`), including explicit "Internet browsing", "gateway
neighbor ARP resolution", and "single ping" negative rows.