# Security hardening

Delta-NIDS treats packet bytes, PCAP files, rule files, and API input as
untrusted data.

## Guarantees

- Packet parsers perform bounds checks before reading headers or lengths.
- Malformed input returns a decode error instead of terminating the process.
- Rule parsing rejects unsupported and active actions.
- The API accepts only bounded GET requests and limits query fields.
- Storage uses parameterized SQLite statements for persisted values.
- Flow, alert, incident, and write-queue state is bounded by configuration.
- The dashboard binds to localhost by default.
- No packet injection, TCP reset, blocking, firewall changes, active scans, or
automated response actions exist in the common engine.

## Deployment guidance

Run live capture with the minimum privileges required by libpcap/Npcap. Keep the
REST API on loopback unless an authenticated reverse proxy and explicit network
policy are provided. Treat rule and PCAP paths as operator-controlled inputs and
avoid writable shared directories for production databases or logs.

Security tests cover malformed Ethernet input, passive-action rejection, invalid
storage configuration, request-size enforcement, malformed HTTP requests, and
bounded API query parsing. Fuzzing and sanitizer runs should be added to CI for
future releases.
