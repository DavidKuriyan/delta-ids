# PCAP regression testing

PCAP replay is the cross-platform deterministic input path. The capture layer
reads timestamps and bytes from the file, while decoding and detection use only
platform-independent models.

Run the complete regression suite:

```bash
cmake -S . -B build -DDELTA_NIDS_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

On Windows, use the same commands from Developer PowerShell and run:

```powershell
ctest --test-dir build --output-on-failure
```

The regression test checks canonical decoded semantics rather than interface
names, native handles, or OS-specific metadata. A future corpus should record
expected normalized events (flow identity, protocol, addresses, ports, service,
and alert fields) and compare those fields on both operating systems. Raw
formatted logs should not be used as the compatibility contract.

PCAP replay is passive and does not require an active interface or capture
privileges. Live capture remains dependent on libpcap on Linux and Npcap on
Windows.
