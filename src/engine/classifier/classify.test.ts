import assert from "node:assert/strict";
import test from "node:test";
import { classifyAlgorithm, ffcIfcSecurityBits } from "./classify.ts";
import { classifyIkeTransform, classifyOid, classifySsh, classifyTlsGroup, toLegacyClassification } from "./registry.ts";

const cases: Array<[Parameters<typeof classifyAlgorithm>[0], string, Partial<ReturnType<typeof classifyAlgorithm>>]> = [
  [{ name: "RSA", keySize: 2048, usage: "signature" }, "VULNERABLE_SHOR", { algorithm: "RSA-2048", classicalSecurityLevel: 112, nistQuantumSecurityLevel: 0 }],
  [{ name: "RSA", keySize: 4096, usage: "signature" }, "VULNERABLE_SHOR", { algorithm: "RSA-4096", classicalSecurityLevel: 128 }],
  [{ name: "RSA", keySize: 1024 }, "VULNERABLE_SHOR", { classicallyBroken: true }],
  [{ name: "ECDSA", curve: "prime256v1", usage: "signature" }, "VULNERABLE_SHOR", { algorithm: "ECDSA-P-256", curve: "P-256", classicalSecurityLevel: 128 }],
  [{ name: "ECDH", curve: "secp384r1", usage: "key-exchange" }, "VULNERABLE_SHOR", { algorithm: "ECDH-P-384", classicalSecurityLevel: 192 }],
  [{ name: "Ed25519" }, "VULNERABLE_SHOR", { family: "EdDSA" }],
  [{ name: "X25519" }, "VULNERABLE_SHOR", { primitive: "key-agree" }],
  [{ name: "DSA", keySize: 1024 }, "VULNERABLE_SHOR", {}],
  [{ name: "FFDH", keySize: 2048 }, "VULNERABLE_SHOR", { classicalSecurityLevel: 112 }],
  [{ name: "AES-128-GCM" }, "DEGRADED_GROVER", { keySize: 128, nistQuantumSecurityLevel: 1, primitive: "ae" }],
  [{ name: "AES-256-CBC" }, "SAFE_PQC", { keySize: 256, nistQuantumSecurityLevel: 5, primitive: "block-cipher" }],
  [{ name: "AES-256-XTS", keySize: 256 }, "SAFE_PQC", { keySize: 256 }],
  [{ name: "3DES" }, "DEGRADED_GROVER", { classicallyBroken: true }],
  [{ name: "Blowfish" }, "DEGRADED_GROVER", {}],
  [{ name: "CHACHA20-POLY1305" }, "SAFE_PQC", { primitive: "ae" }],
  [{ name: "SHA-1" }, "DEGRADED_GROVER", { classicallyBroken: true }],
  [{ name: "SHA-384" }, "SAFE_PQC", { family: "SHA-2" }],
  [{ name: "ML-KEM-768" }, "SAFE_PQC", { family: "ML-KEM", nistQuantumSecurityLevel: 3, primitive: "kem", parameterSet: "768" }],
  [{ name: "Kyber1024" }, "SAFE_PQC", { algorithm: "ML-KEM-1024", nistQuantumSecurityLevel: 5 }],
  [{ name: "ML-DSA-65" }, "SAFE_PQC", { nistQuantumSecurityLevel: 3, primitive: "signature" }],
  [{ name: "Dilithium2" }, "SAFE_PQC", { algorithm: "ML-DSA-44" }],
  [{ name: "SLH-DSA-SHA2-128s" }, "SAFE_PQC", { parameterSet: "SHA2-128s", nistQuantumSecurityLevel: 1 }],
  [{ name: "Falcon-512" }, "SAFE_PQC", { nistQuantumSecurityLevel: 1 }],
  [{ name: "LMS" }, "SAFE_PQC", { family: "LMS" }],
  [{ name: "XMSS" }, "SAFE_PQC", { family: "XMSS" }],
  [{ name: "X25519MLKEM768" }, "HYBRID", { nistQuantumSecurityLevel: 3, primitive: "combiner" }],
  [{ name: "SecP384r1MLKEM1024" }, "HYBRID", { nistQuantumSecurityLevel: 5 }],
  [{ name: "sntrup761x25519" }, "HYBRID", {}],
  [{ name: "rot13" }, "UNKNOWN", {}],
];

for (const [input, status, extra] of cases) {
  test(`classify ${input.name}${input.keySize ? "/" + input.keySize : ""} -> ${status}`, () => {
    const c = classifyAlgorithm(input);
    assert.equal(c.status, status, c.rationale);
    for (const [k, v] of Object.entries(extra)) assert.deepEqual(c[k as keyof typeof c], v, `${k}`);
    assert.ok(c.rationale.length > 0);
  });
}

test("NIST SP 800-57 classical strength table", () => {
  assert.deepEqual([1024, 2048, 3072, 7680, 15360].map(ffcIfcSecurityBits), [80, 112, 128, 192, 256]);
});

test("OID registry", () => {
  assert.equal(classifyOid("1.2.840.113549.1.1.11").status, "VULNERABLE_SHOR");
  assert.equal(classifyOid("2.16.840.1.101.3.4.3.18").algorithm, "ML-DSA-65");
  assert.equal(classifyOid("2.16.840.1.101.3.4.4.2").status, "SAFE_PQC");
  assert.equal(classifyOid("1.3.101.112").algorithm, "Ed25519");
  assert.equal(classifyOid("9.9.9").status, "UNKNOWN");
});

test("TLS named groups distinguish classical, hybrid and pure ML-KEM", () => {
  assert.equal(classifyTlsGroup(0x001d).status, "VULNERABLE_SHOR");
  assert.equal(classifyTlsGroup(0x11ec).status, "HYBRID");
  assert.equal(classifyTlsGroup(0x11ec).label, "X25519MLKEM768");
  assert.equal(classifyTlsGroup(0x0201).status, "SAFE_PQC");
  assert.equal(classifyTlsGroup(0xfafa).status, "UNKNOWN");
});

test("SSH and IKEv2 names", () => {
  assert.equal(classifySsh("sntrup761x25519-sha512@openssh.com").status, "HYBRID");
  assert.equal(classifySsh("mlkem768x25519-sha256").status, "HYBRID");
  assert.equal(classifySsh("curve25519-sha256").status, "VULNERABLE_SHOR");
  assert.equal(classifySsh("diffie-hellman-group1-sha1").classicallyBroken, true);
  assert.equal(classifySsh("aes128-ctr").status, "DEGRADED_GROVER");
  assert.equal(classifySsh("chacha20-poly1305@openssh.com").status, "SAFE_PQC");
  assert.equal(classifyIkeTransform(1, 20, 256).algorithm, "AES-256-GCM");
  assert.equal(classifyIkeTransform(1, 12, 128).status, "DEGRADED_GROVER");
  assert.equal(classifyIkeTransform(4, 36).status, "SAFE_PQC");
  assert.equal(classifyIkeTransform(4, 2).classicallyBroken, true);
});

test("legacy label mapping matches server/riskEngine.js", () => {
  assert.equal(toLegacyClassification("VULNERABLE_SHOR"), "SHOR-CRITICAL");
  assert.equal(toLegacyClassification("SAFE_PQC"), "QUANTUM-SAFE");
});
