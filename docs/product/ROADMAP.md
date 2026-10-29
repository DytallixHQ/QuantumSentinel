# QuantumSentinel roadmap

QuantumSentinel is in **alpha**. This roadmap lists stages, not dates.

## Where things stand

| Area | Stage |
|------|-------|
| Hosted website, repository, and file scans | Available |
| Hosted network connector | Available |
| Local app: full workflow, CBOM, plan export | Available as open source (MIT) |
| Multi-user access, tenant isolation, continuous monitoring | Not yet |

## Under consideration

Candidates for the next releases. Open or comment on an issue to help
set the order.

- [ ] Downloadable CBOM and report export from the hosted scan.
- [ ] Standard CBOM output format for exchange with other tools.
- [ ] More repository detection rules, tuned from reported false positives.
- [ ] Dependency and lock-file analysis to see cryptography pulled in by
      libraries.

## Further out

- Authentication, roles, and tenant boundaries for team use.
- Scheduled re-scans and alerts when observed cryptography changes.
- Evidence retention policies.
- Wider endpoint evidence: certificates and key stores, with consent.

## Not planned

- Exploitation or vulnerability testing beyond cryptographic observation.
- Certification or compliance attestation.

## Influence the roadmap

Open an issue with the asset type, what you expected the scan to find, and
what it found. See [CONTRIBUTING.md](../../CONTRIBUTING.md).
