# Scan model, scoring, and limits

QuantumSentinel reports what it observed and nothing more. This page explains
what each scan can and cannot see, how findings are classified, what the
readiness score means, and how to scan responsibly.

## Authorization comes first

Scan only assets you own or have written permission to assess. Every scan
asks you to confirm this, and the confirmation is stored with the result.
Website scans make ordinary TLS connections; network scans probe only the
hosts and ports you supply. Neither attempts exploitation.

## What each scan sees

| Scan | Sees | Cannot see |
|------|------|-----------|
| Website | The TLS handshake of one public endpoint: versions, cipher suites, key exchange (including post-quantum groups), certificate algorithms. | Anything behind the edge: internal services, application code, stored data. |
| Repository | Cryptographic names and identifiers in supported text files, with file and line. | How the code runs, which paths are live, dependencies' internals, binary files. |
| File | The text of one supported file up to 512 KB. | Anything outside that file. |
| Network | Responding services on the supplied hosts and bounded ports. | Hosts or ports outside the scope; devices that do not respond. |
| Device (local app) | Bounded loopback TCP/TLS services. | Files, installed packages, stored keys, applications, unscanned ports. |

A service that responds without showing its cryptography is recorded as
**needs review**, not as safe or unsafe.

## How findings are classified

| Classification | Meaning | Base priority |
|----------------|---------|---------------|
| Deprecated | Already weak without a quantum computer: MD5, SHA-1, DES, 3DES, RC4, SSL and early TLS, 1024-bit keys. | Critical |
| Unencrypted | A protocol or setting with no encryption. | Critical |
| Shor-critical | Public-key cryptography a quantum computer would break: RSA, finite-field and elliptic-curve Diffie-Hellman, ECDSA, EdDSA, DSA. | High without forward secrecy, medium with it |
| Hybrid | Classical and post-quantum combined, such as X25519 with ML-KEM. | Monitor |
| Quantum-safe | Post-quantum algorithms, or symmetric and hash primitives at adequate sizes. | Monitor |
| Unknown | Not enough evidence to classify. | Monitor, marked for review |

An asset's overall risk score, which weighs harvest-now, decrypt-later
exposure, can raise a priority above its base level.

Post-quantum findings are still worth a look: the guidance asks you to
confirm implementation provenance, parameters, downgrade behavior, and test
vectors.

## The Q-Day Readiness Score

The score helps decide **what to fix first**. It is built from the
classifications and priorities of observed components, and it shows the
drivers behind the number so you can challenge it.

It is not:

- proof that a system is quantum safe,
- a certification or compliance attestation,
- a measure of anything the scan did not observe.

Data that must stay confidential beyond the horizon is at risk now from
harvest-now, decrypt-later collection, because a later migration cannot
protect ciphertext that was already captured.

## False positives

Repository scans match names in text. A comment, a test fixture, or a
dependency that is never called will still match. Review each finding's
evidence before acting, and report recurring false positives as an issue so
detection rules can improve.

## What not to submit

Passwords, private keys, tokens, customer records, or any other sensitive
data. The file scan is for source and configuration content without secrets.
