# Windows operations

Delta-NIDS uses the libpcap-compatible Npcap backend for live capture. The
packet, flow, protocol, detection, storage, and REST layers remain shared with
Linux.

## Requirements

- Supported modern Windows version
- Visual Studio 2022 or another supported MSVC toolchain
- CMake 3.20+
- Npcap installed with WinPcap-compatible API enabled
- Administrator rights or the permissions required by the Npcap installation
  for live capture

## Build and test

From Developer PowerShell:

```powershell
cmake -S . -B build -G Ninja -DDELTA_NIDS_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

The executable is `build\delta-nids.exe`.

## Adapter selection

List adapters using the actual Windows adapter names and deterministic scores:

```powershell
.\build\delta-nids.exe --list-interfaces
```

Automatic mode selects the highest-ranked suitable active adapter:

```powershell
.\build\delta-nids.exe
```

An explicit friendly name or stable adapter identifier takes precedence:

```powershell
.\build\delta-nids.exe --interface "Ethernet"
```

Do not assume `eth0`, `wlan0`, or a particular localized adapter name.

## Npcap and permissions

If live capture fails, verify that Npcap is installed and that the adapter is
visible in `--list-interfaces`. Run the process with the required elevation for
the Npcap configuration. Offline PCAP replay does not require live capture
privileges:

```powershell
.\build\delta-nids.exe --pcap captures\sample.pcap
```

Delta-NIDS is strictly passive. It does not inject packets, send TCP resets,
block addresses, alter firewall rules, or terminate connections.

## Operational checks

```powershell
.\build\delta-nids.exe --stats
.\build\delta-nids.exe --validate-rules tests\fixtures\valid.rules.json
```

Capture-driver errors must be treated as startup failures with actionable
messages; the engine must not silently claim that capture is active.
