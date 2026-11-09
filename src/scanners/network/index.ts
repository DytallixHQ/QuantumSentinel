import tls from "node:tls";
import { addAlgorithm, addCertificate, addPrimitive, link, linkChain } from "../../core/graph/builders.ts";
import { CryptoGraph } from "../../core/graph/graph.ts";
import type { Evidence, Exposure, NetworkEndpoint, RiskInputs } from "../../core/graph/types.ts";
import { classifyAlgorithm } from "../../engine/classifier/classify.ts";
import { classifyIkeTransform, classifySsh, classifyTlsGroup, TLS_CIPHER_SUITES } from "../../engine/classifier/registry.ts";
import { parseCertificate, type CertInfo } from "../filesystem/x509.ts";
import { DEFAULT_TIMEOUT_MS } from "./io.ts";
import { probeIke, type IkeProbeResult } from "./ike.ts";
import { probeSsh, type SshKexInit } from "./ssh.ts";
import { PROBE_GROUPS_CLASSICAL, PROBE_GROUPS_PURE_MLKEM, probeTls, type TlsProbeResult } from "./tls.ts";

export interface NetworkTarget extends RiskInputs {
  host: string;
  port?: number;
  protocol: "tls" | "ssh" | "ikev2" | "tcp";
  posture?: Exposure;
  domain?: string;
  id?: string; // stable ID for relations in the targets file
}

export interface NetworkProbes {
  tls: (host: string, port: number, o: { serverName?: string; maxVersion?: "1.2" | "1.3"; groups?: number[]; shares?: number[]; timeoutMs?: number }) => Promise<TlsProbeResult>;
  tlsChain: (host: string, port: number, serverName: string | undefined, timeoutMs: number) => Promise<Uint8Array[]>;
  ssh: (host: string, port: number, timeoutMs: number) => Promise<SshKexInit>;
  ike: (host: string, port: number, timeoutMs: number) => Promise<IkeProbeResult>;
}

/** Completes a TLS handshake (no application data) to read the certificate chain, which TLS 1.3 encrypts. */
export function fetchTlsChain(host: string, port: number, serverName: string | undefined, timeoutMs: number): Promise<Uint8Array[]> {
  return new Promise((resolve, reject) => {
    const sock = tls.connect({ host, port, servername: serverName, rejectUnauthorized: false, ALPNProtocols: ["http/1.1"] });
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error(`tls chain ${host}:${port} timed out after ${timeoutMs} ms`));
    }, timeoutMs);
    sock.once("secureConnect", () => {
      clearTimeout(timer);
      const chain: Uint8Array[] = [];
      const seen = new Set<string>();
      let c: tls.DetailedPeerCertificate | undefined = sock.getPeerCertificate(true);
      while (c?.raw && !seen.has(c.fingerprint256)) {
        seen.add(c.fingerprint256);
        chain.push(new Uint8Array(c.raw));
        c = c.issuerCertificate;
      }
      sock.destroy();
      resolve(chain);
    });
    sock.once("error", (e) => {
      clearTimeout(timer);
      sock.destroy();
      reject(e);
    });
  });
}

export const LIVE_PROBES: NetworkProbes = { tls: probeTls, tlsChain: fetchTlsChain, ssh: probeSsh, ike: probeIke };

const DEFAULT_PORTS = { tls: 443, ssh: 22, ikev2: 500, tcp: 0 } as const;
const PROTO = { tls: "TLS", ssh: "SSH", ikev2: "IKEv2", tcp: "TCP" } as const;

export function endpointId(t: NetworkTarget): string {
  return t.id ?? `net:${t.protocol}://${t.host}:${t.port ?? DEFAULT_PORTS[t.protocol]}`;
}

export interface NetworkScanOptions {
  timeoutMs?: number;
  concurrency?: number;
  probes?: NetworkProbes;
  now?: () => string;
}

export interface ProbeError {
  target: string;
  error: string;
}

function addCerts(g: CryptoGraph, epId: string, ders: Uint8Array[], ev: Evidence[]): CertInfo | undefined {
  const chain: Array<{ id: string; info: CertInfo }> = [];
  for (const der of ders) {
    try {
      const info = parseCertificate(der);
      chain.push({ id: addCertificate(g, info, ev), info });
    } catch {
      /* skip malformed */
    }
  }
  linkChain(g, chain);
  if (chain[0]) link(g, epId, "CONTAINS_KEY", chain[0].id, { role: "leaf" });
  for (const c of chain.slice(1)) link(g, epId, "CONTAINS_KEY", c.id, { role: "chain" });
  return chain[0]?.info;
}

function ingestTls(g: CryptoGraph, epId: string, r: TlsProbeResult, chain: Uint8Array[], ev: Evidence[]): void {
  const ep = g.get(epId) as NetworkEndpoint;
  ep.protocolVersion = r.version;
  const leaf = addCerts(g, epId, r.certificates.length ? r.certificates : chain, ev);
  const group = r.group ?? r.ske?.group;
  if (group !== undefined) {
    const c = classifyTlsGroup(group);
    link(g, epId, "ENCRYPTED_WITH", addPrimitive(g, c, ev), { role: "key-exchange", group: c.label, helloRetryRequest: r.helloRetry });
  }
  const suite = r.cipherSuite !== undefined ? TLS_CIPHER_SUITES[r.cipherSuite] : undefined;
  if (r.cipherSuite !== undefined) {
    const suiteId = `0x${r.cipherSuite.toString(16).padStart(4, "0").toUpperCase()}`;
    const name = suite?.name ?? `TLS_SUITE_${suiteId}`;
    if (suite) {
      link(g, epId, "ENCRYPTED_WITH", addAlgorithm(g, { name: suite.cipher, usage: "encryption" }, ev), { cipherSuite: name, suiteId, role: "bulk" });
      if (suite.kex === "RSA" && leaf) {
        // Static RSA key transport: session keys are encrypted to the certificate key (no forward secrecy).
        link(g, epId, "ENCRYPTED_WITH", addPrimitive(g, classifyAlgorithm({ name: "RSA", keySize: leaf.publicKey.keySize, usage: "key-exchange" }), ev), { role: "key-exchange", forwardSecrecy: false });
      } else if (suite.kex === "DHE" && group === undefined) {
        link(g, epId, "ENCRYPTED_WITH", addAlgorithm(g, { name: "FFDH", usage: "key-exchange" }, ev), { role: "key-exchange" });
      }
    }
  }
}

// Lower = better for a PQ-capable client.
const RANK: Record<string, number> = { SAFE_PQC: 0, HYBRID: 1, DEGRADED_GROVER: 2, UNKNOWN: 3, VULNERABLE_SHOR: 4 };

/**
 * SSH lists what the server *supports*. To match TLS (where we observe what a PQ-capable client negotiates),
 * the best option per category is the effective one; the others are linked with `offered: true` and do not
 * drive the HNDL status. A classical option kept next to a PQ one is flagged as classical fallback.
 */
function ingestSsh(g: CryptoGraph, epId: string, k: SshKexInit, ev: Evidence[]): void {
  const ep = g.get(epId) as NetworkEndpoint;
  ep.protocolVersion = k.banner;
  const add = (names: string[], role: string, usage: string) => {
    const cs = names.map((n) => ({ n, c: classifySsh(n, usage) }));
    const best = cs.reduce<(typeof cs)[number] | undefined>((b, x) => (!b || RANK[x.c.status] < RANK[b.c.status] ? x : b), undefined);
    cs.forEach(({ n, c }, i) =>
      link(g, epId, "ENCRYPTED_WITH", addPrimitive(g, c, [{ ...ev[0], detail: `${role}: ${n}` }]), { role, name: n, preference: i, offered: n !== best?.n }));
    return cs;
  };
  const kex = add(k.kex.filter((n) => !n.startsWith("ext-info") && !n.startsWith("kex-strict")), "key-exchange", "key-exchange");
  add(k.hostKey, "host-key", "signature");
  add([...new Set([...k.encS2C, ...k.encC2S])].filter((n) => n !== "none"), "encryption", "encryption");
  ep.supportedGroups = kex.map((x) => x.n);
  ep.classicalFallback = kex.some((x) => RANK[x.c.status] <= 1) && kex.some((x) => x.c.status === "VULNERABLE_SHOR");
}

function ingestIke(g: CryptoGraph, epId: string, r: IkeProbeResult, ev: Evidence[]): void {
  for (const t of r.accepted) {
    const c = classifyIkeTransform(t.type, t.id, t.keyLength);
    link(g, epId, "ENCRYPTED_WITH", addPrimitive(g, c, ev), { role: c.label, transformType: t.type });
  }
  if (r.invalidKeGroup !== undefined && !r.accepted.some((t) => t.type === 4)) {
    const c = classifyIkeTransform(4, r.invalidKeGroup);
    link(g, epId, "ENCRYPTED_WITH", addPrimitive(g, c, ev), { role: c.label, transformType: 4, via: "INVALID_KE_PAYLOAD" });
  }
}

/**
 * Two extra ClientHellos per TLS 1.3 endpoint: pure ML-KEM only, and classical only. Each accepted group is
 * linked with `offered: true` (supported, not what a PQ-capable client negotiates), and a server that pairs
 * a PQ group with classical acceptance is flagged as classical fallback.
 */
async function probeTlsGroups(g: CryptoGraph, epId: string, probes: NetworkProbes, host: string, port: number, serverName: string | undefined, timeoutMs: number, main: TlsProbeResult, ev: Evidence[]): Promise<void> {
  const ep = g.get(epId) as NetworkEndpoint;
  const accepted = new Set<number>(main.group !== undefined ? [main.group] : []);
  const attempt = async (groups: number[], shares: number[]) => {
    try {
      const r = await probes.tls(host, port, { serverName, maxVersion: "1.3", groups, shares, timeoutMs });
      // Only trust a selection from the groups we offered.
      if (r.version === "TLS1.3" && r.group !== undefined && groups.includes(r.group)) return r.group;
    } catch {
      /* not supported or unreachable: absence is the observation */
    }
    return undefined;
  };
  const pure = await attempt(PROBE_GROUPS_PURE_MLKEM, [0x0201]);
  const classical = await attempt(PROBE_GROUPS_CLASSICAL, [0x001d]);
  for (const grp of [pure, classical]) {
    if (grp === undefined || accepted.has(grp)) continue;
    accepted.add(grp);
    const c = classifyTlsGroup(grp);
    link(g, epId, "ENCRYPTED_WITH", addPrimitive(g, c, ev), { role: "supported-group", group: c.label, offered: true });
  }
  ep.supportedGroups = [...accepted].map((x) => classifyTlsGroup(x).label);
  const pq = [...accepted].some((x) => RANK[classifyTlsGroup(x).status] <= 1);
  ep.classicalFallback = pq && classical !== undefined;
}

async function pool<T>(items: T[], n: number, fn: (t: T) => Promise<void>): Promise<void> {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) await fn(items[i++]);
  }));
}

export async function scanNetwork(targets: NetworkTarget[], opts: NetworkScanOptions = {}): Promise<{ graph: CryptoGraph; errors: ProbeError[] }> {
  const probes = opts.probes ?? LIVE_PROBES;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const now = opts.now ?? (() => new Date().toISOString());
  const g = new CryptoGraph();
  const errors: ProbeError[] = [];
  await pool(targets, opts.concurrency ?? 8, async (t) => {
    const port = t.port ?? DEFAULT_PORTS[t.protocol];
    const id = endpointId(t);
    const locator = `${t.host}:${port}`;
    const ev: Evidence[] = [{ source: "network", locator, detail: `${PROTO[t.protocol]} probe`, observedAt: now() }];
    const { host: _h, port: _p, protocol: _pr, posture, domain, id: _id, ...risk } = t;
    g.addVertex<NetworkEndpoint>({ ...risk, id, kind: "NetworkEndpoint", label: `${PROTO[t.protocol]} ${locator}`, host: t.host, port, protocol: PROTO[t.protocol], posture: posture ?? "unknown", domain, evidence: ev });
    try {
      if (t.protocol === "tls") {
        const serverName = t.domain ?? (/^[\d.:]+$/.test(t.host) ? undefined : t.host);
        let r = await probes.tls(t.host, port, { serverName, maxVersion: "1.3", timeoutMs });
        if (!r.version || r.alert) r = await probes.tls(t.host, port, { serverName, maxVersion: "1.2", timeoutMs });
        const chain = r.version === "TLS1.3" ? await probes.tlsChain(t.host, port, serverName, timeoutMs).catch(() => []) : [];
        ingestTls(g, id, r, chain, ev);
        if (r.version === "TLS1.3") await probeTlsGroups(g, id, probes, t.host, port, serverName, timeoutMs, r, ev);
      } else if (t.protocol === "ssh") {
        ingestSsh(g, id, await probes.ssh(t.host, port, timeoutMs), ev);
      } else if (t.protocol === "ikev2") {
        ingestIke(g, id, await probes.ike(t.host, port, timeoutMs), ev);
      }
    } catch (e) {
      errors.push({ target: `${t.protocol}://${locator}`, error: e instanceof Error ? e.message : String(e) });
    }
  });
  return { graph: g, errors };
}
