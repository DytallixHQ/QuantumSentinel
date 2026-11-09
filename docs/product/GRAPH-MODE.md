# Graph mode

`quantumsentinel scan --graph` combines the separate scan types into one
**attributed cryptographic graph**, scores Mosca/HNDL risk on it, and exports a
CycloneDX 1.7 CBOM. It needs Node.js 22.18 or newer, which runs the TypeScript
engine in `src/{core,engine,scanners,exporters}` without a build step.

```
quantumsentinel scan --graph --targets targets.json --export-cbom cbom.json --html report.html [--client "Name"] [--output graph.json] [--json]
```

## What the client receives

| Output | Flag | Content |
|--------|------|---------|
| CBOM | `--export-cbom` | CycloneDX 1.7 JSON, validated against the official schema in tests. Components of type `cryptographic-asset` (algorithm, certificate, protocol, related-crypto-material), evidence occurrences, a `dependencies` graph, and `quantumsentinel:*` properties for quantum status and risk score. Other tools that read CycloneDX can import it. |
| Client report | `--html` (+ `--client <name>`) | Self-contained HTML, with no scripts or remote assets; print it to PDF from a browser. Sections: executive summary, priority risks with their drivers, a migration plan ordered by Mosca score with a concrete action per asset, network endpoints (key exchange in use, accepted groups, classical fallback), certificates, the algorithm inventory, coverage gaps, and method notes. |
| Graph + risk | `--output` | Every vertex, edge, and risk result with its drivers, as JSON. |
| Terminal summary | (default) | Counts by quantum status and the ten highest Mosca scores. |

The files are written locally. The hosted scan on dytallix.com is not
changed and still shows results only on the page.

## Targets file

See [`docs/examples/graph-targets.json`](../examples/graph-targets.json).

- `authorization.confirmed: true` is **required** before any network probe.
  Every target is a single host; ranges and sweeps are rejected, and a scan can
  include at most 256 network targets.
- `network[].protocol`: `tls`, `ssh`, `ikev2`, or `tcp`. A `tcp` target is
  declared only and never probed; it models a plaintext internal service.
- `filesystem[]`, `code[]`: paths are relative to the targets file.
- `cloud`: `awsKms` (needs `@aws-sdk/client-kms`), `azureKeyVault` (needs
  `@azure/keyvault-keys` and `@azure/identity`), and `vault` (HashiCorp
  Transit, with the token taken from `$VAULT_TOKEN`). Install the SDKs only if
  you use them. The connectors call only list and describe/read-metadata
  operations.
- `groups[]`: clusters or applications. Each group gets a `DEPENDS_ON` edge to
  every member.
- `relations[]`: extra edges such as `{ "from": "db", "type": "TERMINATES_AT", "to": "proxy" }`.
- Any vertex can set `criticality` (1 to 10), `exposureFactor` (0.1 to 1),
  `retentionYears`, and `migrationYears`.

## Risk model

```
R(v) = C(v) · E(v) · V(v) · max(0, (T_retention + T_migration) − (T_QDay − T_now))
```

- `T_QDay` is a calendar year (default 2033) and is converted to years
  remaining. Subtracting the raw year would make every score zero.
- `V(v)` weights the effective protection: plaintext and Shor-vulnerable 1,
  unknown 0.5, Grover-degraded 0.25, hybrid and PQC 0. Without it, a service
  on ML-KEM would score the same as one on RSA. You can override the weights
  under `risk.statusWeight`.
- HNDL status comes from the key-exchange and encryption primitives applied
  directly to the asset. A certificate's key decides the status only when the
  asset has no direct crypto, such as a file that holds a key.
- Through `TERMINATES_AT`, a backend inherits its terminator's status and the
  higher of the two exposures. Through `DEPENDS_ON`, a group takes the worst
  member status, the highest exposure, and the longest retention and migration
  times, combined with its own criticality.

## Scanner notes

- **TLS**: a raw ClientHello offers hybrid and ML-KEM groups first, with both
  an X25519MLKEM768 and an X25519 key share. The probe reads ServerHello or
  HelloRetryRequest and never completes that handshake. Each TLS 1.3
  endpoint also gets two short probes, one offering only pure ML-KEM groups
  and one offering only classical groups. Their results fill
  `supportedGroups` and `classicalFallback`. TLS 1.3 certificate chains come
  from a separate standard handshake that sends no application data. TLS 1.2
  certificates and the ServerKeyExchange curve are read from the plaintext
  flight.
- **TLS and SSH are rated by the same rule**: the protection a PQ-capable
  client actually gets. For TLS that is the negotiated group. For SSH it is
  the best option in each list in `SSH_MSG_KEXINIT`. Every other algorithm
  the server accepts is still recorded and exported, linked with
  `offered: true`. If a server pairs a PQ option with continued acceptance of
  classical clients, it gets `classicalFallback: true` and a risk driver for
  it, but the fallback does not change its HNDL status.
- **IKEv2**: one `IKE_SA_INIT` (UDP/500), retried once on
  `INVALID_KE_PAYLOAD`. It offers ML-KEM-768/1024/512 as an RFC 9370
  additional key exchange (ADDKE1, with NONE allowed) and signals RFC 9242
  `INTERMEDIATE_EXCHANGE_SUPPORTED`. If the gateway picks a classical KE plus
  an ML-KEM ADDKE, the effective key exchange is recorded as one HYBRID
  primitive (for example `X25519+ML-KEM-768`), and each part is still
  exported. A second offer with no ADDKE then checks for classical fallback.
- **Files**: types are detected from content, not extensions (PEM, DER
  X.509, SPKI, PKCS#8, PKCS#12, JKS/JCEKS, OpenPGP, LUKS1/2, BitLocker).
  Encrypted keys and PKCS#12 bags are never decrypted. An unencrypted private
  key is reduced to its derived public key, so it is deduplicated against
  certificates that carry the same key. Blobs with entropy of 7.5 or more are
  recorded for review.
- **Timeouts**: 3 s by default for connect and read (`--timeout`). Endpoints
  that can't be reached are still recorded and reported as errors.
- **Deduplication**: certificates are keyed by the SHA-256 of their DER,
  public keys by the SHA-256 of their SPKI, and primitives by
  `SHA-256(alg ‖ curve/modulus ‖ key_size ‖ usage)`.
