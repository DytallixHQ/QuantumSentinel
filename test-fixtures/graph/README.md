# Graph-mode test fixtures

Synthetic, throwaway material generated with OpenSSL 3.6 for unit tests only.
Keys here protect nothing and must never be reused. Hostnames use the reserved
`.test.invalid` TLD.

| File | Content |
|------|---------|
| ca-rsa4096.pem | Self-signed RSA-4096 root (SHA256withRSA) |
| leaf-ec-p256.pem / .der | P-256 leaf signed by the root |
| chain.pem | leaf + root |
| rsa2048-selfsigned.pem | RSA-2048 self-signed |
| mldsa65-selfsigned.pem | ML-DSA-65 self-signed |
| ec-p256-public.pem | SPKI public key of the leaf |
| bundle.p12 | PKCS#12: plaintext cert bag + AES-256-CBC shrouded key (throwaway P-256 key), SHA-256 MAC |

Private-key PEM fixtures are generated at test time (`src/scanners/filesystem/keyFixtures.ts`).
JKS, LUKS, BitLocker, OpenPGP, TLS/SSH/IKE handshakes and KMS responses are built
byte-for-byte inside the tests.
