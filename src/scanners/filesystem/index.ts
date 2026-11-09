import { lstat, open, readdir } from "node:fs/promises";
import path from "node:path";
import { addAlgorithm, addCertificate, addPrimitive, addPublicKey, link, linkChain } from "../../core/graph/builders.ts";
import { CryptoGraph } from "../../core/graph/graph.ts";
import type { CryptoMaterial, Evidence, FileAsset, RiskInputs } from "../../core/graph/types.ts";
import { classifyOid } from "../../engine/classifier/registry.ts";
import { dearmor, parseBitLocker, parseJks, parseLuks, parsePgpPackets, parsePkcs12, shannonEntropy, sniff, type ContentType } from "./containers.ts";
import { parsePem, readTlv } from "./der.ts";
import { inspectPrivateKey, parseCertificate, parseSpki, type CertInfo } from "./x509.ts";

export interface FilesystemTarget extends RiskInputs {
  path: string;
  mountPoint?: string;
  fsType?: string;
  bucket?: string;
  owner?: string;
}

export interface FilesystemScanOptions {
  maxFiles?: number;
  maxBytesPerFile?: number; // files larger than this are header-sniffed only
  headerBytes?: number;
  now?: () => string;
}

const DEFAULTS = { maxFiles: 5000, maxBytesPerFile: 4 * 1024 * 1024, headerBytes: 1024 * 1024 };
const SKIP_DIRS = new Set([".git", "node_modules", ".venv", "__pycache__"]);

async function readHead(file: string, n: number): Promise<{ buf: Uint8Array; size: number }> {
  const fh = await open(file, "r");
  try {
    const { size } = await fh.stat();
    const len = Math.min(size, n);
    const buf = new Uint8Array(len);
    await fh.read(buf, 0, len, 0);
    return { buf, size };
  } finally {
    await fh.close();
  }
}

async function* walk(root: string, limit: number): AsyncGenerator<string> {
  const st = await lstat(root);
  if (st.isFile()) {
    yield root;
    return;
  }
  let count = 0;
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop()!;
    const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) stack.push(p);
      } else if (e.isFile()) {
        if (++count > limit) return;
        yield p;
      }
    }
  }
}

/** Ingest one buffer into the graph. Exported for fixture tests; no filesystem access. */
export function ingestBuffer(g: CryptoGraph, buf: Uint8Array, file: Omit<FileAsset, "kind" | "id" | "label" | "evidence" | "contentType" | "entropy">, now: string, sizeHint = buf.length): ContentType {
  const type = sniff(buf);
  const ev: Evidence[] = [{ source: "filesystem", locator: file.path, detail: type, observedAt: now }];
  const fileId = `file:${file.path}`;
  const entropy = Math.round(shannonEntropy(buf.subarray(0, 65536)) * 100) / 100;
  const ensureFile = () => g.addVertex<FileAsset>({ ...file, id: fileId, kind: "FileAsset", label: file.path, contentType: type, entropy, evidence: ev });

  const certs = (ders: Uint8Array[], detail: string) => {
    const chain: Array<{ id: string; info: CertInfo }> = [];
    for (const der of ders) {
      try {
        const info = parseCertificate(der);
        const id = addCertificate(g, info, [{ ...ev[0], detail }]);
        link(g, fileId, "CONTAINS_KEY", id);
        chain.push({ id, info });
      } catch {
        /* malformed cert: skip */
      }
    }
    linkChain(g, chain);
  };

  const privateKey = (der: Uint8Array, label: string) => {
    const info = inspectPrivateKey(der, label);
    if (info.encrypted) {
      const encId = info.encryptionOid ? addAlgorithm(g, { ...classifyFromOid(info.encryptionOid), usage: "encryption" }, ev) : undefined;
      const id = `pkcs8enc:${file.path}`;
      g.addVertex<CryptoMaterial>({ id, kind: "CryptoMaterial", label: "Encrypted private key", materialType: "private-key-ref", format: "PKCS#8 (encrypted)", evidence: ev });
      link(g, fileId, "CONTAINS_KEY", id);
      if (encId) link(g, id, "ENCRYPTED_WITH", encId);
      return;
    }
    if (info.publicKey) {
      // Private key represented only by its derived public key; dedups with certificates using the same key.
      const id = addPublicKey(g, info.publicKey, [{ ...ev[0], detail: `${label} (private key present)` }], "private-key-ref");
      link(g, fileId, "CONTAINS_KEY", id);
    } else if (info.oid) {
      link(g, fileId, "CONTAINS_KEY", addPrimitive(g, classifyOid(info.oid, { curve: info.curve, usage: "public-key" }), ev));
    }
  };

  switch (type) {
    case "pem": {
      ensureFile();
      const blocks = parsePem(new TextDecoder("latin1").decode(buf));
      certs(blocks.filter((b) => b.label === "CERTIFICATE" || b.label === "TRUSTED CERTIFICATE").map((b) => b.der), "PEM certificate");
      for (const block of blocks) {
        try {
          if (block.label === "CERTIFICATE" || block.label === "TRUSTED CERTIFICATE") continue;
          else if (block.label === "PUBLIC KEY") link(g, fileId, "CONTAINS_KEY", addPublicKey(g, parseSpki(readTlv(block.der, 0)), ev));
          else if (/PRIVATE KEY$/.test(block.label)) {
            if (block.headers) {
              const id = `pemenc:${file.path}`;
              g.addVertex<CryptoMaterial>({ id, kind: "CryptoMaterial", label: "Legacy encrypted PEM key", materialType: "private-key-ref", format: "PEM (Proc-Type ENCRYPTED)", evidence: ev });
              link(g, fileId, "CONTAINS_KEY", id);
            } else privateKey(block.der, block.label);
          }
        } catch {
          /* malformed block */
        }
      }
      break;
    }
    case "x509-der":
      ensureFile();
      certs([buf], "DER certificate");
      break;
    case "spki-der":
      ensureFile();
      link(g, fileId, "CONTAINS_KEY", addPublicKey(g, parseSpki(readTlv(buf, 0)), ev));
      break;
    case "pkcs8-der":
      ensureFile();
      privateKey(buf, "PRIVATE KEY");
      break;
    case "pkcs12": {
      ensureFile();
      const p12 = parsePkcs12(buf);
      certs(p12.certs, "PKCS#12 certificate bag");
      for (const oid of [...p12.encryptedContentOids, ...p12.shroudedKeyOids]) link(g, fileId, "ENCRYPTED_WITH", addAlgorithm(g, { ...classifyFromOid(oid), usage: "encryption" }, ev));
      if (p12.macDigestOid) link(g, fileId, "ENCRYPTED_WITH", addAlgorithm(g, { ...classifyFromOid(p12.macDigestOid), usage: "hash" }, ev));
      if (p12.shroudedKeyBags + p12.plainKeyBags > 0) {
        const id = `p12keys:${file.path}`;
        g.addVertex<CryptoMaterial>({ id, kind: "CryptoMaterial", label: `${p12.shroudedKeyBags + p12.plainKeyBags} private key bag(s)`, materialType: "private-key-ref", format: "PKCS#12", evidence: ev });
        link(g, fileId, "CONTAINS_KEY", id);
      }
      break;
    }
    case "jks":
    case "jceks":
      ensureFile();
      for (const entry of parseJks(buf)) {
        certs(entry.certs, `${type.toUpperCase()} ${entry.kind} '${entry.alias}'`);
        if (entry.kind === "secret-key") {
          const id = `jceks:${file.path}#${entry.alias}`;
          g.addVertex<CryptoMaterial>({ id, kind: "CryptoMaterial", label: `JCEKS secret key '${entry.alias}'`, materialType: "secret-key-ref", format: "JCEKS", evidence: ev });
          link(g, fileId, "CONTAINS_KEY", id);
        }
      }
      break;
    case "openpgp": {
      ensureFile();
      const bin = buf[0] & 0x80 ? buf : dearmor(new TextDecoder("latin1").decode(buf));
      for (const pkt of parsePgpPackets(bin)) {
        if (!pkt.algorithm) continue;
        const usage = pkt.tag === 1 ? "key-exchange" : "public-key";
        const detail = pkt.tag === 1 ? `OpenPGP PKESK v${pkt.version}${pkt.keyId ? " key " + pkt.keyId : ""}` : `OpenPGP public key v${pkt.version}`;
        link(g, fileId, pkt.tag === 1 ? "ENCRYPTED_WITH" : "CONTAINS_KEY", addAlgorithm(g, { name: pkt.algorithm.replace("+", ""), usage }, [{ ...ev[0], detail }]));
      }
      break;
    }
    case "luks1":
    case "luks2":
    case "bitlocker": {
      const vol = type === "bitlocker" ? parseBitLocker(buf) : parseLuks(buf);
      g.addVertex<FileAsset>({ ...file, id: fileId, kind: "FileAsset", label: `${vol.format} volume ${file.path}`, contentType: type, fsType: file.fsType ?? vol.format, entropy, evidence: ev });
      const name = vol.cipher ? `${vol.cipher.split("-")[0]}-${vol.keyBits ?? ""}-${vol.cipher.split("-")[1] ?? ""}` : "AES";
      link(g, fileId, "ENCRYPTED_WITH", addAlgorithm(g, { name: name.toUpperCase().replace(/-+$/, ""), keySize: vol.keyBits, usage: "encryption" }, [{ ...ev[0], detail: `${vol.format} ${vol.cipher ?? "cipher unknown"}` }]));
      if (vol.hash) link(g, fileId, "ENCRYPTED_WITH", addAlgorithm(g, { name: vol.hash, usage: "hash" }, ev));
      break;
    }
    case "high-entropy":
      // Opaque encrypted/compressed blob: record it so it can be reviewed, without guessing an algorithm.
      if (sizeHint >= 1024) ensureFile();
      break;
    default:
      break;
  }
  return type;
}

function classifyFromOid(oid: string): { name: string; oid: string } {
  return { name: classifyOid(oid).algorithm, oid };
}

export async function scanFilesystem(targets: FilesystemTarget[], opts: FilesystemScanOptions = {}): Promise<CryptoGraph> {
  const o = { ...DEFAULTS, ...opts };
  const now = (opts.now ?? (() => new Date().toISOString()))();
  const g = new CryptoGraph();
  for (const t of targets) {
    for await (const file of walk(path.resolve(t.path), o.maxFiles)) {
      try {
        const { buf, size } = await readHead(file, o.headerBytes);
        if (size > o.maxBytesPerFile && !["luks1", "luks2", "bitlocker", "high-entropy"].includes(sniff(buf))) continue;
        const { path: _root, ...attrs } = t;
        ingestBuffer(g, buf, { ...attrs, path: file }, now, size);
      } catch {
        /* unreadable or malformed: skip */
      }
    }
  }
  return g;
}
