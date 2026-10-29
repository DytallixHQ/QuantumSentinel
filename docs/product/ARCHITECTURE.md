# QuantumSentinel architecture

QuantumSentinel is built around one rule: **every finding traces back to
observed evidence.** Scanners collect evidence, the risk engine turns it into
findings and a score, and planning turns findings into owned actions.

```
  Scanners                    Evidence store          Analysis                 Planning
 ┌──────────────────┐
 │ Website TLS      │──┐
 │ Repository       │──┤      ┌─────────────┐      ┌──────────────────┐      ┌──────────────────┐
 │ File             │──┼────► │ Observations│────► │ Risk engine      │────► │ Recommendations  │
 │ Network          │──┤      │ + scope     │      │  findings        │      │ Owned actions    │
 │ Device (local)   │──┘      │ + authority │      │  CBOM            │      │ Decisions        │
 └──────────────────┘         └─────────────┘      │  readiness score │      │ Export           │
                                                   └──────────────────┘      └──────────────────┘
```

## Scanners

Each scanner observes one kind of asset and records exactly what it saw,
together with the scope it was given and the authorization that was
confirmed.

| Scanner | Observes | Does not |
|---------|----------|----------|
| Website | One public TLS endpoint: protocol versions, cipher suites, key exchange, certificate algorithms. | Crawl pages, exploit services, or test the application. |
| Repository | Cryptographic references in supported text files, with file and line. | Execute code or prove runtime behavior. |
| File | One supported text file. | Accept secrets; do not submit them. |
| Network | The supplied hosts and bounded ports. | Discover unknown devices or sweep a network. |
| Device (local app) | Bounded loopback TCP/TLS services. | Inspect files, packages, stored keys, or all ports. |

Scanners are bounded: repository clones, files, bytes, findings, request
rate, and concurrency all have limits, and temporary checkouts are deleted
after each scan.

## Evidence store

Observations are stored with their scope and authorization. In the local app
the store is session-only by default; persistence is opt-in, to a file you
choose. Services that respond but do not show their cryptography are kept as
"needs review" components until follow-up evidence confirms them.

## Risk engine

- **Classification.** Each observed component is classified as
  Shor-critical, deprecated, unencrypted, hybrid, quantum-safe, or unknown,
  and given a priority: critical, high, medium, or monitor.
- **Findings.** Observations that need action become findings, each linked to
  its evidence, with a rationale and migration guidance.
- **CBOM.** Observed cryptographic components are assembled into a
  cryptographic bill of materials (local app).
- **Q-Day Readiness Score.** A prioritization score against the planning
  horizon, shown with the drivers behind it. See
  [SCAN-MODEL.md](SCAN-MODEL.md#the-q-day-readiness-score).

## Planning

Generated recommendations stay separate from **owned actions**. An action
exists only when a person gives it an owner, a target state, a deadline, and
the evidence that will show it is done. Decisions are recorded alongside the
plan, and the whole plan can be exported (local app).

## Deployment shapes

| Shape | Runs where | Data path |
|-------|------------|-----------|
| Hosted scan | dytallix.com | Targets you submit are scanned by the hosted service. The network connector runs on your approved computer and uploads its scope and observations. |
| Local app | Your machine (dashboard and API on 127.0.0.1) | Nothing leaves the machine except the scan traffic you start. |
