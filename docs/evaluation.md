# Detection-quality evaluation

Phase 25 provides deterministic quality measurement without making machine
learning part of the primary engine. A labeled case contains:

- a stable case name;
- whether an alert is expected;
- whether the engine produced an alert.

The evaluation result reports:

```text
TP = expected alert and observed alert
FP = no expected alert but observed alert
TN = no expected alert and no observed alert
FN = expected alert but no observed alert
```

Metrics:

```text
precision = TP / (TP + FP)
recall    = TP / (TP + FN)
F1        = 2 * precision * recall / (precision + recall)
```

Undefined denominators are reported as zero. Positive and negative PCAP cases
should be kept separate from production traffic and reviewed when rules or
protocol inspectors change. Negative cases should exercise benign protocol
traffic containing common words and edge cases; they must not be reduced to an
empty capture. Results should compare normalized alerts (SID, flow entities,
service, and evidence), not timestamps or host-specific interface metadata.
