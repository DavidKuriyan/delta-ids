# Performance validation

Phase 26 provides a small benchmark contract and bounded-state regression
coverage. Benchmark values are informational and depend on compiler, CPU,
packet size, and capture backend; they are not treated as cross-machine quality
thresholds.

Run the suite:

```bash
cmake --build build
ctest --test-dir build --output-on-failure
```

Performance investigations should measure:

- packets processed per second;
- end-to-end processing latency;
- parser errors and capture drops;
- active-flow count and eviction count;
- alert/storage queue depth and dropped writes;
- resident memory over a sustained replay.

Every stateful subsystem must remain bounded by configuration. A benchmark must
use deterministic PCAP input when comparing revisions, record build type and
compiler, and compare normalized counters and results. Live-capture numbers
must not be compared directly with offline replay numbers without recording the
capture backend and operating-system context.
