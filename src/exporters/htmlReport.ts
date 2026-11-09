// Self-contained HTML client report for graph mode: executive summary, prioritized risks,
// classical-fallback exposure, inventory and a migration plan ordered by Mosca score.
import type { CryptoGraph } from "../core/graph/graph.ts";
import type { CryptoMaterial, CryptoPrimitive, NetworkEndpoint, Vertex } from "../core/graph/types.ts";
import type { EffectiveStatus, RiskConfig, RiskResult } from "../engine/risk/mosca.ts";
import type { MigrationPriority } from "../engine/risk/priority.ts";

export interface HtmlReportOptions {
  risk: RiskResult[];
  riskConfig: Pick<RiskConfig, "qDayYear" | "currentYear">;
  title?: string;
  client?: string;
  generatedAt?: string;
  errors?: Array<{ target: string; error: string }>;
  /** Optional migration order (engine/risk/priority.ts); adds a "Migrate first" section. */
  priorities?: MigrationPriority[];
  /** Optional call to action at the end (hosted scans); omitted from client deliverables. */
  cta?: { heading: string; text: string; url: string; label: string };
}

const esc = (v: unknown) => String(v ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");

const STATUS_LABEL: Record<EffectiveStatus, string> = {
  PLAINTEXT: "Plaintext",
  VULNERABLE_SHOR: "Quantum-vulnerable",
  UNKNOWN: "Needs review",
  DEGRADED_GROVER: "Weakened (Grover/legacy)",
  HYBRID: "Hybrid PQC",
  SAFE_PQC: "Quantum-resistant",
};
const STATUS_ORDER: EffectiveStatus[] = ["PLAINTEXT", "VULNERABLE_SHOR", "UNKNOWN", "DEGRADED_GROVER", "HYBRID", "SAFE_PQC"];

function priority(r: RiskResult, maxScore: number): "Critical" | "High" | "Medium" | "Monitor" {
  if (r.combinedScore <= 0) return "Monitor";
  const rel = maxScore > 0 ? r.combinedScore / maxScore : 0;
  if (r.status === "PLAINTEXT" || (rel >= 0.66 && r.exposure >= 0.7)) return "Critical";
  if (rel >= 0.33) return "High";
  return "Medium";
}

function effectivePrimitives(g: CryptoGraph, id: string): CryptoPrimitive[] {
  return g.outgoing(id, ["ENCRYPTED_WITH", "DEPENDS_ON"])
    .filter((e) => e.attrs?.offered !== true)
    .map((e) => g.get(e.to))
    .filter((v): v is CryptoPrimitive => v?.kind === "CryptoPrimitive");
}

/** Concrete migration action for an asset, derived from what was observed on it. */
export function recommend(g: CryptoGraph, v: Vertex, r: RiskResult): string[] {
  const out: string[] = [];
  const prims = effectivePrimitives(g, v.id);
  const broken = prims.filter((p) => p.classicallyBroken);
  if (broken.length) out.push(`Remove classically broken algorithms now: ${[...new Set(broken.map((p) => p.algorithm))].join(", ")}.`);
  if (r.status === "PLAINTEXT") out.push("Encrypt this traffic; terminate it with TLS 1.3 using the hybrid X25519MLKEM768 group.");
  if (v.kind === "NetworkEndpoint") {
    const kexWeak = prims.some((p) => p.usage === "key-exchange" && p.status === "VULNERABLE_SHOR");
    if (kexWeak && v.protocol === "TLS") out.push("Enable hybrid key exchange (X25519MLKEM768): OpenSSL 3.5+, BoringSSL, Go 1.24+, or a CDN/load balancer that supports it.");
    if (kexWeak && v.protocol === "SSH") out.push("Enable mlkem768x25519-sha256 (OpenSSH 9.9+) and list it first in KexAlgorithms.");
    if (kexWeak && v.protocol === "IKEv2") out.push("Enable ML-KEM additional key exchange (RFC 9370) on the VPN gateway.");
    if (prims.some((p) => p.usage === "encryption" && p.status === "DEGRADED_GROVER")) out.push("Prefer AES-256-GCM or ChaCha20-Poly1305 over 128-bit or legacy ciphers.");
    if (v.classicalFallback) out.push("Classical-only clients are still accepted; inventory clients and set a date to require hybrid key exchange.");
  }
  if (v.kind === "CryptoMaterial") {
    if (v.materialType === "key-metadata") out.push("Create replacement keys with ML-DSA (signing) or ML-KEM-based wrapping where the KMS supports it; rotate dependents.");
    else out.push("Track for re-issuance with ML-DSA or composite certificates once your CA supports them; shorten lifetimes meanwhile.");
  }
  if (v.kind === "FileAsset" && prims.some((p) => p.status === "VULNERABLE_SHOR")) out.push("Re-key stored material and protect at-rest data with AES-256; plan PQC replacement of the public-key layer.");
  if (v.kind === "CodeAsset") out.push("Route this call site through a crypto-agile wrapper and add an ML-KEM / ML-DSA option.");
  if (r.tnfl.score > 0) {
    const anchors = g.outgoing(v.id, ["CONTAINS_KEY"]).map((e) => g.get(e.to)).filter((m): m is CryptoMaterial => m?.kind === "CryptoMaterial" && m.materialType === "certificate" && !!m.subject && m.subject === m.issuer);
    if (v.kind === "NetworkEndpoint" && v.protocol === "TLS") out.push(`Signatures here must stay trusted for ${r.tnfl.trustYears} years, past Q-Day. Plan ML-DSA or composite certificates with your CA${anchors.length ? ", and confirm when the trust anchors (" + anchors.map((a) => a.subject).join("; ") + ") will be replaced" : ""}.`);
    else if (v.kind === "NetworkEndpoint" && v.protocol === "SSH") out.push("Host-key signatures can be forged after Q-Day. Track post-quantum SSH host-key support, keep host-key rotation automated, and avoid long-lived pinned host keys.");
    else if (v.kind === "NetworkEndpoint" && v.protocol === "IKEv2") out.push("VPN peer authentication relies on classical signatures. Plan post-quantum (ML-DSA) authentication certificates for the gateway.");
    else if (v.kind === "CodeAsset") out.push("Signatures from this code path must stay unforgeable. Move signing to ML-DSA or SLH-DSA (LMS/XMSS for firmware, NIST SP 800-208), with a dual-signing transition period.");
    else if (v.kind === "ServiceGroup" || v.kind === "FileAsset") out.push(`Signing keys and certificates held here stay trusted for ${r.tnfl.trustYears} years, past Q-Day. Re-issue them with ML-DSA or SLH-DSA, starting with the longest-lived.`);
  }
  if (v.kind === "ServiceGroup") out.push("Coordinate migration across the members listed in the drivers; this group carries their highest exposure.");
  if (!out.length && r.combinedScore > 0) out.push("Review the drivers and confirm the retention and migration assumptions for this asset.");
  return out;
}

const CSS = `body{margin:0;background:#f6f8fb;color:#14202b;font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1180px;margin:auto;padding:40px 28px}h1{font-size:30px;margin:0 0 4px}h2{font-size:20px;margin:36px 0 10px;border-bottom:1px solid #d9e1ea;padding-bottom:6px}
.muted{color:#5b6b7a}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:22px 0}
.card{background:#fff;border:1px solid #d9e1ea;border-radius:10px;padding:14px 16px}.card .n{font-size:28px;font-weight:700}.card .l{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#5b6b7a}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #d9e1ea;font-size:14px}th,td{text-align:left;vertical-align:top;padding:8px 10px;border-bottom:1px solid #e8edf2}th{background:#eef2f6}
code{font-size:12.5px;color:#28506e;word-break:break-all}.pill{display:inline-block;border-radius:999px;padding:1px 9px;font-size:12px;font-weight:600;white-space:nowrap}
.Critical,.PLAINTEXT,.VULNERABLE_SHOR{background:#fde2e2;color:#9b1c1c}.High,.UNKNOWN{background:#fff0d6;color:#8a4b00}.Medium,.DEGRADED_GROVER{background:#fdf6c8;color:#6b5800}
.Monitor,.HYBRID{background:#e3effd;color:#1e4f8a}.SAFE_PQC{background:#ddf5e6;color:#17663a}ul{margin:4px 0;padding-left:18px}
.cta{margin:32px 0;padding:18px 22px;border:1px solid #0f766e;border-radius:10px;background:#effaf7}.cta h2{border:0;margin:0 0 6px;padding:0}.cta a{display:inline-block;background:#0f766e;color:#fff;padding:8px 16px;border-radius:6px;text-decoration:none;font-weight:600}
.notice{border-left:3px solid #c48a00;background:#fffaf0;padding:10px 14px;margin:18px 0}@media print{body{background:#fff}main{padding:0}h2{break-after:avoid}tr{break-inside:avoid}}`;

const pill = (cls: string, text: string) => `<span class="pill ${esc(cls)}">${esc(text)}</span>`;

export function buildHtmlReport(g: CryptoGraph, o: HtmlReportOptions): string {
  const assets = o.risk.filter((r) => g.get(r.id)?.kind !== "CryptoMaterial");
  const ranked = assets.filter((r) => r.combinedScore > 0);
  const max = ranked[0]?.combinedScore ?? 0;
  const hndlCount = assets.filter((r) => r.score > 0).length;
  const tnflCount = assets.filter((r) => r.tnfl.score > 0).length;
  const forgeable = o.risk.filter((r) => r.tnfl.score > 0).sort((a, b) => b.tnfl.score - a.tnfl.score);
  const yearsLeft = o.riskConfig.qDayYear - o.riskConfig.currentYear;
  const prims = g.allVertices("CryptoPrimitive") as CryptoPrimitive[];
  const endpoints = g.allVertices("NetworkEndpoint") as NetworkEndpoint[];
  const certs = (g.allVertices("CryptoMaterial") as CryptoMaterial[]).filter((m) => m.materialType === "certificate");
  const byStatus = new Map<EffectiveStatus, number>();
  for (const r of assets) byStatus.set(r.status, (byStatus.get(r.status) ?? 0) + 1);
  const counts = { crit: 0, high: 0 };
  for (const r of ranked) {
    const p = priority(r, max);
    if (p === "Critical") counts.crit++;
    else if (p === "High") counts.high++;
  }
  const fallback = endpoints.filter((e) => e.classicalFallback);
  // An endpoint "has PQC" when the key exchange in effect is hybrid or post-quantum.
  const pqEndpoints = endpoints.filter((e) => effectivePrimitives(g, e.id).some((p) => p.usage === "key-exchange" && (p.status === "HYBRID" || p.status === "SAFE_PQC")));

  const headline = ranked.length
    ? `${ranked.length} of ${assets.length} assets are at risk before the ${o.riskConfig.qDayYear} Q-Day planning horizon (${yearsLeft} years away). ${hndlCount} hold data that must stay confidential past Q-Day but is protected by breakable or weakened encryption (harvest now, decrypt later). ${tnflCount} rely on signatures that must stay trusted past Q-Day but could then be forged (trust now, forge later). Critical: ${counts.crit}; high: ${counts.high}.`
    : `No assessed asset exceeds the Mosca threshold against a ${o.riskConfig.qDayYear} Q-Day horizon, for either confidentiality (harvest now, decrypt later) or signatures (trust now, forge later).`;

  const label = (id: string) => esc(g.get(id)?.label ?? id);
  const riskRows = ranked.slice(0, 25).map((r) => {
    const tn = r.primaryThreat === "TNFL";
    const status = tn ? r.tnfl.status ?? "UNKNOWN" : r.status;
    const drivers = tn ? r.tnfl.drivers : r.drivers;
    return `<tr><td>${pill(priority(r, max), priority(r, max))}</td><td>${label(r.id)}<br><code>${esc(r.id)}</code></td><td>${tn ? "Trust now, forge later" : "Harvest now, decrypt later"}</td><td>${pill(status, STATUS_LABEL[status])}</td><td>${r.score.toFixed(1)}</td><td>${r.tnfl.score.toFixed(1)}</td><td>${r.exposure}</td><td><ul>${drivers.slice(0, 4).map((d) => `<li>${esc(d)}</li>`).join("")}</ul></td></tr>`;
  }).join("");
  const forgeRows = forgeable.slice(0, 30).map((r) => {
    const v = g.get(r.id)!;
    const kind = v.kind === "CryptoMaterial" ? (v.materialType === "certificate" ? (v.subject && v.subject === v.issuer ? "Trust anchor (root)" : "Certificate") : "Signing key") : v.kind === "NetworkEndpoint" ? `${v.protocol} endpoint` : v.kind === "CodeAsset" ? "Code" : v.kind === "ServiceGroup" ? "Group" : "File";
    return `<tr><td>${label(r.id)}</td><td>${esc(kind)}</td><td>${pill(r.tnfl.status ?? "UNKNOWN", STATUS_LABEL[r.tnfl.status ?? "UNKNOWN"])}</td><td>${r.tnfl.trustYears} y</td><td>${r.tnfl.score.toFixed(1)}</td><td><ul>${r.tnfl.drivers.slice(0, 3).map((d) => `<li>${esc(d)}</li>`).join("")}</ul></td></tr>`;
  }).join("");

  const planRows = ranked.map((r, i) => {
    const v = g.get(r.id)!;
    return `<tr><td>${i + 1}</td><td>${label(r.id)}</td><td>${pill(priority(r, max), priority(r, max))}</td><td><ul>${recommend(g, v, r).map((x) => `<li>${esc(x)}</li>`).join("")}</ul></td></tr>`;
  }).join("");

  const endpointRows = endpoints.map((e) => {
    const r = o.risk.find((x) => x.id === e.id);
    const kex = effectivePrimitives(g, e.id).filter((p) => p.usage === "key-exchange").map((p) => p.algorithm);
    return `<tr><td>${esc(e.protocol)}</td><td>${esc(e.host)}:${e.port}</td><td>${esc(e.posture)}</td><td>${esc(e.protocolVersion ?? "")}</td><td>${esc(kex.join(", ") || "none observed")}</td><td>${esc((e.supportedGroups ?? []).join(", "))}</td><td>${e.classicalFallback ? "yes" : ""}</td><td>${r ? pill(r.status, STATUS_LABEL[r.status]) : ""}</td></tr>`;
  }).join("");

  const primRows = [...prims].sort((a, b) => STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status) || a.algorithm.localeCompare(b.algorithm)).map((p) => {
    const users = g.incoming(p.id).length;
    return `<tr><td>${esc(p.algorithm)}</td><td>${esc(p.usage)}</td><td>${pill(p.status, STATUS_LABEL[p.status])}${p.classicallyBroken ? " " + pill("Critical", "classically broken") : ""}</td><td>${p.classicalSecurityLevel ?? ""}</td><td>${p.nistQuantumSecurityLevel ?? ""}</td><td>${users}</td></tr>`;
  }).join("");

  const certRows = [...certs].sort((a, b) => (a.notAfter ?? "").localeCompare(b.notAfter ?? "")).map((c) => {
    const key = g.outgoing(c.id, ["ENCRYPTED_WITH"]).map((e) => (g.get(e.to) as CryptoPrimitive).algorithm).join(", ");
    const sig = g.incoming(c.id, ["SIGNS"]).map((e) => g.get(e.from)).filter((x): x is CryptoPrimitive => x?.kind === "CryptoPrimitive").map((p) => p.algorithm).join(", ");
    const where = new Set(c.evidence.map((e) => e.locator)).size;
    return `<tr><td>${esc(c.subject)}</td><td>${esc(c.issuer)}</td><td>${esc(key)}</td><td>${esc(sig)}</td><td>${esc((c.notAfter ?? "").slice(0, 10))}</td><td>${where}</td></tr>`;
  }).join("");

  const statusCards = STATUS_ORDER.filter((s) => byStatus.get(s)).map((s) => `<div class="card"><div class="l">Data protection: ${esc(STATUS_LABEL[s])}</div><div class="n">${byStatus.get(s)}</div></div>`).join("");
  const errors = o.errors?.length ? `<h2>Coverage gaps</h2><p class="muted">These targets could not be fully assessed and are not reflected above.</p><table><tr><th>Target</th><th>Reason</th></tr>${o.errors.map((e) => `<tr><td>${esc(e.target)}</td><td>${esc(e.error)}</td></tr>`).join("")}</table>` : "";

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(o.title ?? "Post-Quantum Readiness Assessment")}</title><style>${CSS}</style></head><body><main>
<h1>${esc(o.title ?? "Post-Quantum Readiness Assessment")}</h1>
<p class="muted">${o.client ? esc(o.client) + " · " : ""}Generated ${esc(o.generatedAt ?? new Date().toISOString())} by QuantumSentinel</p>
<h2>Executive summary</h2>
<p>${esc(headline)}</p>
<div class="cards"><div class="card"><div class="l">Critical</div><div class="n">${counts.crit}</div></div><div class="card"><div class="l">High</div><div class="n">${counts.high}</div></div><div class="card"><div class="l">Endpoints with PQC</div><div class="n">${pqEndpoints.length}/${endpoints.length}</div></div><div class="card"><div class="l">Classical fallback</div><div class="n">${fallback.length}</div></div><div class="card"><div class="l">Forgeable signatures</div><div class="n">${forgeable.length}</div></div><div class="card"><div class="l">Certificates</div><div class="n">${certs.length}</div></div><div class="card"><div class="l">Algorithms</div><div class="n">${prims.length}</div></div></div>
<div class="cards">${statusCards}</div>
<div class="notice">Scores use Mosca's inequality against Q-Day (${o.riskConfig.qDayYear}). <strong>Harvest now, decrypt later</strong>: encrypted data recorded today is at risk when its required confidentiality period plus migration time runs past Q-Day. <strong>Trust now, forge later</strong>: signatures, certificates and signing keys are at risk when they must stay trusted past Q-Day, because a quantum computer could then forge them. Risk = criticality × exposure × protection weight × years over the horizon. This assessment reports observed evidence; it is a prioritization aid, not a certification.</div>
<h2>Priority risks</h2>${ranked.length ? `<table><tr><th>Priority</th><th>Asset</th><th>Main threat</th><th>Protection</th><th>HNDL</th><th>TNFL</th><th>Exposure</th><th>Why</th></tr>${riskRows}</table>` : "<p>None above the threshold.</p>"}
<h2>Trust now, forge later</h2>${forgeable.length ? `<p class="muted">Certificates, trust anchors, signing keys and the assets that rely on them, where signatures must stay trusted past Q-Day.</p><table><tr><th>Item</th><th>Type</th><th>Signature protection</th><th>Trusted for</th><th>Score</th><th>Why</th></tr>${forgeRows}</table>` : "<p>No signature or certificate needs to stay trusted past the Q-Day horizon.</p>"}
${o.priorities?.length ? `<h2>Migrate first</h2><p class="muted">Total risk removed if only this asset's own cryptography (key exchange, keys and certificates it holds) moves to post-quantum, across every asset that depends on it.</p><table><tr><th>#</th><th>Asset</th><th>Risk removed</th><th>Assets improved</th></tr>${o.priorities.slice(0, 10).map((p, i) => `<tr><td>${i + 1}</td><td>${esc(p.label)}<br><code>${esc(p.id)}</code></td><td>${p.reduction.toFixed(1)}</td><td>${p.assetsImproved}</td></tr>`).join("")}</table>` : ""}
<h2>Migration plan</h2>${ranked.length ? `<table><tr><th>#</th><th>Asset</th><th>Priority</th><th>Action</th></tr>${planRows}</table>` : "<p>No actions required at the current horizon. Re-assess when retention requirements or the Q-Day estimate change.</p>"}
<h2>Network endpoints</h2>${endpoints.length ? `<table><tr><th>Protocol</th><th>Endpoint</th><th>Posture</th><th>Version</th><th>Key exchange in use</th><th>Accepted groups</th><th>Classical fallback</th><th>Protection</th></tr>${endpointRows}</table>` : "<p>No network endpoints in scope.</p>"}
<h2>Certificates</h2>${certs.length ? `<table><tr><th>Subject</th><th>Issuer</th><th>Key</th><th>Signed with</th><th>Expires</th><th>Seen at</th></tr>${certRows}</table>` : "<p>No certificates observed.</p>"}
<h2>Algorithm inventory</h2><table><tr><th>Algorithm</th><th>Usage</th><th>Status</th><th>Classical bits</th><th>NIST PQ category</th><th>Used by</th></tr>${primRows}</table>
${errors}
${o.cta && /^https:\/\//.test(o.cta.url) ? `<div class="cta"><h2>${esc(o.cta.heading)}</h2><p>${esc(o.cta.text)}</p><p><a href="${esc(o.cta.url)}">${esc(o.cta.label)}</a></p></div>` : ""}
<h2>Method and limits</h2><ul><li>Network: TLS ClientHello, SSH KEXINIT and IKEv2 IKE_SA_INIT observation; no exploitation and no application data.</li><li>Files: content-sniffed certificates, keys and keystores; private keys and encrypted containers are never read out or decrypted.</li><li>Cloud: key metadata only (type, size, allowed operations).</li><li>Code: static references; reachability is not proven.</li><li>The machine-readable CycloneDX 1.7 CBOM accompanies this report.</li></ul>
</main></body></html>`;
}
