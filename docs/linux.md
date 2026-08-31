# Linux operations

Delta-NIDS uses libpcap for both live capture and offline PCAP replay. The common
packet and detection pipeline is independent of Linux-specific interfaces.

## Build and test

```bash
sudo apt install build-essential cmake libpcap-dev libsqlite3-dev
cmake -S . -B build -DDELTA_NIDS_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

## Interface discovery

List actual adapters and deterministic suitability scores:

```bash
./build/delta-nids --list-interfaces
```

With no interface override, the manager selects the highest-ranked suitable
adapter. To select one explicitly:

```bash
./build/delta-nids --interface eth0
```

Interface names are discovered from the operating system; `eth0` is only an
example. Loopback and disconnected interfaces are not selected automatically
when a suitable active adapter exists.

## Capture privileges

Live capture may require root or Linux capabilities, depending on the libpcap
installation and interface policy. Prefer granting the executable only the
capabilities required by the deployment rather than running unrelated services
as root. If capture cannot be opened, inspect the interface and driver with
`--list-interfaces`, then run with the required authorization. PCAP replay does
not require capture privileges:

```bash
./build/delta-nids --pcap captures/sample.pcap
```

Delta-NIDS is passive: it does not inject packets, send resets, block hosts, or
modify firewall rules.

## Operational checks

```bash
./build/delta-nids --stats
./build/delta-nids --validate-rules tests/fixtures/valid.rules.json
```

`--stats` prints process-local telemetry counters. For live capture failures,
check that libpcap development/runtime files are installed, the adapter is up,
and the process has capture permission. BPF filters and snap length are passed
to libpcap; unsupported backend behavior must be reported rather than silently
emulated.
