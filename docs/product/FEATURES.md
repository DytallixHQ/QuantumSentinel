# QuantumSentinel features and functions

Columns show where each function is available: the **hosted** scan at
dytallix.com, and the open-source **local** app.

## Evidence collection

| Function | What it does | Hosted | Local |
|----------|--------------|:------:|:-----:|
| Website TLS scan | Observes TLS versions, cipher suites, key exchange groups, and certificate algorithms on a public endpoint. Reports whether post-quantum key exchange was observed. Does not crawl pages or test the application. | ✓ | ✓ |
| Repository scan | Classifies cryptographic references in supported text files of a GitHub repository (local paths too, in the local app). Clones into a temporary directory and deletes it after the scan. | ✓ (public repositories) | ✓ |
| File scan | Inspects one supported text file up to 512 KB. | ✓ | |
| Network connector | A connector you run on an approved computer probes the approved scope and uploads responding addresses, service observations, and a summary. The browser cannot inspect a private network on its own. | ✓ | |
| Authorized network scan | Probes the hosts and bounded ports you enter, directly from your machine. | | ✓ |
| Device scan | Checks bounded loopback TCP/TLS services on the local machine. | | ✓ |
| Authorization step | Every scan requires confirming that you own or are authorized to assess the target. | ✓ | ✓ |

## What the repository scan recognizes

| Category | Examples of what is flagged |
|----------|-----------------------------|
| Shor-vulnerable public-key cryptography (high) | RSA and RSA-based JWT algorithms; ECDSA, ECDH, X25519, Ed25519, NIST curves, secp256k1 |
| Deprecated cryptography | MD5, SHA-1, DES, 3DES, RC4 |
| Post-quantum algorithms (informational) | ML-KEM, ML-DSA, SLH-DSA, and the pre-standard names Kyber, Dilithium, SPHINCS+ |
| Symmetric and hash primitives (informational) | AES, ChaCha20-Poly1305, SHA-2, SHA-3, SHAKE, HMAC, flagged for a parameter check rather than replacement |

Each observation carries the file, line, confidence, likely usage context,
the reason it was flagged, and migration guidance. Pattern matching shows
where cryptography is referenced; it does not prove how the application uses
it.

## Analysis

| Function | What it does | Hosted | Local |
|----------|--------------|:------:|:-----:|
| Findings with evidence | Each finding links to the observation that produced it. | ✓ | ✓ |
| Recommended actions | Generated next steps for each finding. | ✓ | ✓ |
| Q-Day Readiness Score | A prioritization score for website, repository, and file scans, with the drivers behind it. | ✓ | ✓ |
| Planning horizon | Choose the Q-Day horizon the score is measured against. | | ✓ |
| Organization and scan scope | Switch results between the whole organization and a single scan. | | ✓ |
| Cryptographic bill of materials | Build and download a CBOM from the observed evidence. | | ✓ |

## Planning and reporting

| Function | What it does | Hosted | Local |
|----------|--------------|:------:|:-----:|
| Owned actions | Turn a recommendation into an action with an owner, target state, deadline, and evidence requirement. | | ✓ |
| Decisions | Keep reports and decisions alongside the plan. | | ✓ |
| Migration plan export | Download the PQC migration plan as a report package. | | ✓ |
| Command-line reports | Produce JSON and HTML reports for a repository or domain from the command line. | | ✓ |

## Data handling

| Function | What it does | Hosted | Local |
|----------|--------------|:------:|:-----:|
| Session-only by default | The local app keeps evidence for the session unless you turn on persistence. | | ✓ |
| Optional persistence | Store evidence in a local datastore file you choose. | | ✓ |
| Bounded scanning | Clone, file, byte, finding, rate, and concurrency limits on hosted repository scans. | ✓ | |
| Runs on your machine | Local app: dashboard and API on 127.0.0.1; nothing leaves the machine except the scans you run. | | ✓ |

## What QuantumSentinel does not do

- Crawl websites, exploit services, or test for general web vulnerabilities.
- Discover unknown devices or scan whole networks.
- Inspect stored keys, installed packages, or running applications.
- Execute scanned code.
- Certify readiness or attest compliance.
