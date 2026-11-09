import assert from "node:assert/strict";
import dgram from "node:dgram";
import { readFile } from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import test from "node:test";
import type { CryptoMaterial, CryptoPrimitive, NetworkEndpoint } from "../../core/graph/types.ts";
import { parsePem } from "../filesystem/der.ts";
import { buildIkeSaInit, parseIkeResponse } from "./ike.ts";
import { resolveRiskConfig, scoreGraph } from "../../engine/risk/mosca.ts";
import { LIVE_PROBES, scanNetwork } from "./index.ts";
import { interpretSsh } from "./ssh.ts";
import { buildClientHello, HRR_RANDOM, interpretFlight, parseServerFlight } from "./tls.ts";

const FIX = path.resolve(import.meta.dirname, "../../../test-fixtures/graph");
const NOW = () => "2026-11-09T00:00:00Z";
const u16 = (n: number) => [(n >> 8) & 255, n & 255];
const u24 = (n: number) => [(n >> 16) & 255, (n >> 8) & 255, n & 255];
const u32 = (n: number) => [(n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];

// ---------------------------------------------------------------- synthetic TLS server flights

const record = (type: number, body: number[]) => [type, 3, 3, ...u16(body.length), ...body];
const hsMsg = (type: number, body: number[]) => [type, ...u24(body.length), ...body];
const ext = (t: number, b: number[]) => [...u16(t), ...u16(b.length), ...b];

function serverHello(o: { suite: number; random?: number[]; exts?: number[] }): number[] {
  const random = o.random ?? new Array(32).fill(7);
  const exts = o.exts ?? [];
  return hsMsg(2, [3, 3, ...random, 32, ...new Array(32).fill(1), ...u16(o.suite), 0, ...u16(exts.length), ...exts]);
}

function tls13Flight(group: number): Uint8Array {
  const sh = serverHello({ suite: 0x1302, exts: [...ext(0x002b, u16(0x0304)), ...ext(0x0033, [...u16(group), ...u16(32), ...new Array(32).fill(9)])] });
  return new Uint8Array([...record(22, sh), ...record(20, [1]), ...record(23, [0xde, 0xad])]);
}

function hrrFlight(group: number): Uint8Array {
  const random = [...Buffer.from(HRR_RANDOM, "hex")];
  return new Uint8Array(record(22, serverHello({ suite: 0x1301, random, exts: [...ext(0x002b, u16(0x0304)), ...ext(0x0033, u16(group))] })));
}

async function tls12Flight(): Promise<Uint8Array> {
  const chain = parsePem(await readFile(path.join(FIX, "chain.pem"), "utf8")).map((b) => [...b.der]);
  const certList = chain.flatMap((c) => [...u24(c.length), ...c]);
  const cert = hsMsg(11, [...u24(certList.length), ...certList]);
  const ske = hsMsg(12, [3, ...u16(0x0017), 65, ...new Array(65).fill(4), ...u16(0x0403), ...u16(8), ...new Array(8).fill(0)]);
  const hs = [...serverHello({ suite: 0xc02f }), ...cert, ...ske, ...hsMsg(14, [])];
  // Split across two records to exercise reassembly.
  const cut = 50;
  return new Uint8Array([...record(22, hs.slice(0, cut)), ...record(22, hs.slice(cut))]);
}

function sshServerBytes(kex: string[], hostKey: string[], enc: string[]): Uint8Array {
  const list = (xs: string[]) => [...u32(Buffer.byteLength(xs.join(","))), ...Buffer.from(xs.join(","))];
  const payload = [20, ...new Array(16).fill(0xaa), ...list(kex), ...list(hostKey), ...list(enc), ...list(enc), ...list(["hmac-sha2-256"]), ...list(["hmac-sha2-256"]), ...list(["none"]), ...list(["none"]), ...list([]), ...list([]), 0, ...u32(0)];
  const pad = 8 - ((payload.length + 5) % 8) + 4;
  const pkt = [...u32(payload.length + pad + 1), pad, ...payload, ...new Array(pad).fill(0)];
  return new Uint8Array([...Buffer.from("SSH-2.0-OpenSSH_9.9 test\r\n"), ...pkt]);
}

function ikeResponse(transforms: Array<[number, number, number?]>, notifyType?: number): Uint8Array {
  const ts = transforms.flatMap(([type, id, kl], i) => {
    const attrs = kl ? [0x80, 0x0e, ...u16(kl)] : [];
    return [i === transforms.length - 1 ? 0 : 3, 0, ...u16(8 + attrs.length), type, 0, ...u16(id), ...attrs];
  });
  const prop = [0, 0, ...u16(8 + ts.length), 1, 1, 0, transforms.length, ...ts];
  const notify = notifyType ? [0, 0, ...u16(8), 0, 0, ...u16(notifyType)] : [];
  const sa = [notifyType ? 41 : 0, 0, ...u16(4 + prop.length), ...prop];
  return new Uint8Array([...new Array(8).fill(1), ...new Array(8).fill(2), 33, 0x20, 34, 0x20, ...u32(0), ...u32(28 + sa.length + notify.length), ...sa, ...notify]);
}

function ikeInvalidKe(group: number): Uint8Array {
  const n = [0, 0, 0, 10, 1, 0, ...u16(17), ...u16(group)];
  return new Uint8Array([...new Array(16).fill(0), 41, 0x20, 34, 0x20, ...u32(0), ...u32(28 + n.length), ...n]);
}

async function tcpServer(onData: (sock: net.Socket, data: Buffer) => void, onConnect?: (sock: net.Socket) => void): Promise<{ port: number; close: () => Promise<void> }> {
  const socks = new Set<net.Socket>();
  const srv = net.createServer((s) => {
    socks.add(s);
    s.on("error", () => {});
    onConnect?.(s);
    s.on("data", (d) => onData(s, d));
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  return { port: (srv.address() as net.AddressInfo).port, close: () => new Promise((r) => { socks.forEach((s) => s.destroy()); srv.close(() => r()); }) };
}

// ---------------------------------------------------------------- unit tests on bytes

test("ClientHello advertises PQ-first groups with hybrid and X25519 shares", () => {
  const ch = buildClientHello({ maxVersion: "1.3", serverName: "a.test.invalid", random: new Uint8Array(32) });
  assert.equal(ch[0], 0x16);
  const hex = Buffer.from(ch).toString("hex");
  assert.ok(hex.includes("11ec"), "X25519MLKEM768 offered");
  assert.ok(hex.includes("0033"), "key_share present");
  assert.equal(parseServerFlight(ch).messages[0].type, 1);
  assert.ok(hex.includes("11ec04c0"), "X25519MLKEM768 share of 1216 bytes");
  const classicalOnly = Buffer.from(buildClientHello({ maxVersion: "1.3", groups: [0x001d, 0x0017] })).toString("hex");
  assert.ok(!classicalOnly.includes("11ec"));
  assert.ok(ch.length < 16384, "fits in one TLS record");
  const pure = Buffer.from(buildClientHello({ maxVersion: "1.3", groups: [0x0201], shares: [0x0201] })).toString("hex");
  assert.ok(pure.includes("020104a0"), "pure ML-KEM-768 share of 1184 bytes");
});

test("TLS 1.3 ServerHello with hybrid key share", () => {
  const r = interpretFlight(tls13Flight(0x11ec));
  assert.equal(r.version, "TLS1.3");
  assert.equal(r.group, 0x11ec);
  assert.equal(r.cipherSuite, 0x1302);
  assert.equal(r.helloRetry, false);
});

test("HelloRetryRequest reveals the preferred group", () => {
  const r = interpretFlight(hrrFlight(0x11ec));
  assert.equal(r.helloRetry, true);
  assert.equal(r.group, 0x11ec);
});

test("TLS 1.2 flight split across records: suite, certs, SKE curve", async () => {
  const r = interpretFlight(await tls12Flight());
  assert.equal(r.version, "TLS1.2");
  assert.equal(r.cipherSuite, 0xc02f);
  assert.equal(r.certificates.length, 2);
  assert.deepEqual(r.ske, { curveType: 3, group: 0x0017 });
  assert.equal(r.complete, true);
});

test("TLS alert is captured", () => {
  const r = interpretFlight(new Uint8Array(record(21, [2, 40])));
  assert.deepEqual(r.alert, { level: 2, description: 40 });
});

test("SSH KEXINIT parsing tolerates pre-banner lines", () => {
  const bytes = Buffer.concat([Buffer.from("hello\r\n"), sshServerBytes(["sntrup761x25519-sha512@openssh.com", "curve25519-sha256"], ["ssh-ed25519"], ["aes256-gcm@openssh.com"])]);
  const k = interpretSsh(bytes)!;
  assert.equal(k.banner, "SSH-2.0-OpenSSH_9.9 test");
  assert.deepEqual(k.kex, ["sntrup761x25519-sha512@openssh.com", "curve25519-sha256"]);
  assert.deepEqual(k.hostKey, ["ssh-ed25519"]);
  assert.equal(interpretSsh(bytes.subarray(0, bytes.length - 10)), null, "partial packet");
});

test("IKE_SA_INIT request is well-formed and responses parse", () => {
  const req = buildIkeSaInit();
  assert.equal(req[17], 0x20);
  assert.equal(req[18], 34);
  assert.equal(new DataView(req.buffer).getUint32(24), req.length);
  const r = parseIkeResponse(ikeResponse([[1, 20, 256], [2, 7], [4, 31]]));
  assert.deepEqual(r.accepted, [{ type: 1, id: 20, keyLength: 256 }, { type: 2, id: 7 }, { type: 4, id: 31 }]);
  assert.equal(parseIkeResponse(ikeInvalidKe(14)).invalidKeGroup, 14);
});

// ---------------------------------------------------------------- live sockets on loopback

test("scanNetwork over loopback: TLS 1.3 hybrid, TLS 1.2 classical, SSH, IKEv2", async () => {
  const tls13 = await tcpServer((s) => s.end(tls13Flight(0x11ec)));
  const t12bytes = await tls12Flight();
  const tls12 = await tcpServer((s, d) => {
    // Answer 1.3 hellos with protocol_version alert, 1.2 hellos with a full flight.
    s.end(Buffer.from(d).includes(Buffer.from([0x00, 0x2b])) ? new Uint8Array(record(21, [2, 70])) : t12bytes);
  });
  const ssh = await tcpServer(() => {}, (s) => s.write(sshServerBytes(["curve25519-sha256", "diffie-hellman-group14-sha256"], ["rsa-sha2-512", "ssh-ed25519"], ["chacha20-poly1305@openssh.com", "aes128-ctr"])));
  const udp = dgram.createSocket("udp4");
  udp.on("message", (_m, rinfo) => udp.send(ikeResponse([[1, 12, 128], [2, 5], [3, 12], [4, 14]]), rinfo.port, rinfo.address));
  await new Promise<void>((r) => udp.bind(0, "127.0.0.1", r));
  const ikePort = (udp.address() as net.AddressInfo).port;
  try {
    const { graph, errors } = await scanNetwork(
      [
        { host: "127.0.0.1", port: tls13.port, protocol: "tls", posture: "external", id: "tls13" },
        { host: "127.0.0.1", port: tls12.port, protocol: "tls", posture: "external", id: "tls12" },
        { host: "127.0.0.1", port: ssh.port, protocol: "ssh", posture: "internal", id: "ssh" },
        { host: "127.0.0.1", port: ikePort, protocol: "ikev2", posture: "external", id: "vpn" },
      ],
      { probes: { ...LIVE_PROBES, tlsChain: async () => [] }, timeoutMs: 1500, now: NOW },
    );
    assert.deepEqual(errors, []);
    const kexOf = (id: string) => graph.outgoing(id, ["ENCRYPTED_WITH"]).filter((e) => e.attrs?.role === "key-exchange").map((e) => graph.get(e.to) as CryptoPrimitive);
    assert.deepEqual(kexOf("tls13").map((p) => p.status), ["HYBRID"]);
    assert.equal((graph.get("tls13") as NetworkEndpoint).protocolVersion, "TLS1.3");
    assert.deepEqual(kexOf("tls12").map((p) => p.algorithm), ["ECDH-P-256"]);
    assert.equal((graph.get("tls12") as NetworkEndpoint).protocolVersion, "TLS1.2");
    const leaf = graph.outgoing("tls12", ["CONTAINS_KEY"]).find((e) => e.attrs?.role === "leaf")!;
    assert.match((graph.get(leaf.to) as CryptoMaterial).subject!, /proxy/);
    const suiteEdge = graph.outgoing("tls12", ["ENCRYPTED_WITH"]).find((e) => e.attrs?.cipherSuite)!;
    assert.equal(suiteEdge.attrs!.cipherSuite, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
    assert.equal((graph.get(suiteEdge.to) as CryptoPrimitive).status, "DEGRADED_GROVER");
    const sshAlgs = graph.outgoing("ssh", ["ENCRYPTED_WITH"]).map((e) => `${e.attrs!.role}:${(graph.get(e.to) as CryptoPrimitive).algorithm}`).sort();
    assert.ok(sshAlgs.includes("key-exchange:FFDH-2048"));
    assert.ok(sshAlgs.includes("host-key:Ed25519"));
    assert.ok(sshAlgs.includes("encryption:AES-128-CTR"));
    const vpn = graph.outgoing("vpn", ["ENCRYPTED_WITH"]).map((e) => (graph.get(e.to) as CryptoPrimitive).algorithm).sort();
    assert.deepEqual(vpn, ["AES-128-CBC", "FFDH-2048", "HMAC-SHA-256", "HMAC-SHA-256"], "PRF and INTEG are distinct usages");
  } finally {
    await Promise.all([tls13.close(), tls12.close(), ssh.close()]);
    udp.close();
  }
});

test("graceful timeouts: silent server, refused port, unroutable host, silent UDP", async () => {
  const silent = await tcpServer(() => {});
  const refused = await tcpServer(() => {});
  await refused.close();
  const udp = dgram.createSocket("udp4");
  await new Promise<void>((r) => udp.bind(0, "127.0.0.1", r));
  const t0 = Date.now();
  try {
    const { graph, errors } = await scanNetwork(
      [
        { host: "127.0.0.1", port: silent.port, protocol: "tls" },
        { host: "127.0.0.1", port: refused.port, protocol: "ssh" },
        { host: "10.255.255.1", port: 443, protocol: "tls" },
        { host: "127.0.0.1", port: (udp.address() as net.AddressInfo).port, protocol: "ikev2" },
      ],
      { timeoutMs: 300, now: NOW },
    );
    const elapsed = Date.now() - t0;
    assert.equal(errors.length, 4, JSON.stringify(errors));
    assert.ok(errors.some((e) => /timed out after 300 ms/.test(e.error)));
    assert.ok(elapsed < 3000, `took ${elapsed} ms`);
    assert.equal(graph.allVertices("NetworkEndpoint").length, 4, "endpoints recorded even when unreachable");
  } finally {
    await silent.close();
    udp.close();
  }
});


// ---------------------------------------------------------------- RFC 9370 additional key exchange

/** Walk the transforms of every proposal in an IKE_SA_INIT request; returns "type:id" strings. */
function requestTransforms(req: Uint8Array): { transforms: string[]; notifies: number[] } {
  const transforms: string[] = [];
  const notifies: number[] = [];
  let next = req[16];
  let p = 28;
  while (next !== 0 && p + 4 <= req.length) {
    const np = req[p];
    const len = (req[p + 2] << 8) | req[p + 3];
    if (next === 33) {
      let q = p + 4;
      while (q < p + len) {
        const plen = (req[q + 2] << 8) | req[q + 3];
        let t = q + 8 + req[q + 6];
        while (t < q + plen) {
          const tlen = (req[t + 2] << 8) | req[t + 3];
          transforms.push(`${req[t + 4]}:${(req[t + 6] << 8) | req[t + 7]}`);
          t += tlen;
        }
        q += plen;
      }
    } else if (next === 41) notifies.push((req[p + 6] << 8) | req[p + 7]);
    next = np;
    p += len;
  }
  return { transforms, notifies };
}

test("IKE_SA_INIT offers ML-KEM as ADDKE1 with NONE and signals IKE_INTERMEDIATE", () => {
  const req = buildIkeSaInit();
  const { transforms, notifies } = requestTransforms(req);
  for (const t of ["6:36", "6:37", "6:35", "6:0", "4:31", "4:36"]) assert.ok(transforms.includes(t), t);
  assert.deepEqual(notifies, [16438]);
  assert.equal(new DataView(req.buffer).getUint32(24), req.length);
  const classical = requestTransforms(buildIkeSaInit({ addke: false }));
  assert.ok(!classical.transforms.some((t) => t.startsWith("6:")));
  assert.deepEqual(classical.notifies, []);
  // An ML-KEM-768 KE payload carries a 1184-byte encapsulation key.
  const mlkem = buildIkeSaInit({ dhGroup: 36 });
  assert.ok(mlkem.length > 1184 + 28);
});

test("ADDKE responses parse, including the IKE_INTERMEDIATE notify", () => {
  const r = parseIkeResponse(ikeResponse([[1, 20, 256], [2, 7], [4, 31], [6, 36]], 16438));
  assert.deepEqual(r.accepted.map((t) => `${t.type}:${t.id}`), ["1:20", "2:7", "4:31", "6:36"]);
  assert.equal(r.intermediateSupported, true);
});

test("loopback gateway: x25519 + ML-KEM-768 ADDKE rates HYBRID, classical-only acceptance is flagged", async () => {
  const udp = dgram.createSocket("udp4");
  udp.on("message", (msg, rinfo) => {
    const wantsAddke = requestTransforms(new Uint8Array(msg)).notifies.includes(16438);
    const reply = wantsAddke ? ikeResponse([[1, 20, 256], [2, 7], [4, 31], [6, 36]], 16438) : ikeResponse([[1, 20, 256], [2, 7], [4, 31]]);
    udp.send(reply, rinfo.port, rinfo.address);
  });
  await new Promise<void>((r) => udp.bind(0, "127.0.0.1", r));
  try {
    const { graph, errors } = await scanNetwork([{ host: "127.0.0.1", port: (udp.address() as net.AddressInfo).port, protocol: "ikev2", posture: "external", id: "vpn" }], { timeoutMs: 1500, now: NOW });
    assert.deepEqual(errors, []);
    const vpn = graph.get("vpn") as NetworkEndpoint;
    assert.equal(vpn.classicalFallback, true);
    assert.equal(vpn.protocolVersion, "IKEv2 (IKE_INTERMEDIATE)");
    assert.deepEqual(vpn.supportedGroups, ["X25519", "ML-KEM-768"]);
    const effective = graph.outgoing("vpn", ["ENCRYPTED_WITH"]).filter((e) => e.attrs?.role === "key-exchange").map((e) => graph.get(e.to) as CryptoPrimitive);
    assert.deepEqual(effective.map((p) => `${p.algorithm}:${p.status}`), ["X25519+ML-KEM-768:HYBRID"]);
    assert.ok(graph.outgoing("vpn", ["ENCRYPTED_WITH"]).filter((e) => e.attrs?.role === "key-exchange-component").every((e) => e.attrs?.offered === true));
    const [risk] = scoreGraph(graph, resolveRiskConfig({ qDayYear: 2033, currentYear: 2026 }));
    assert.equal(risk.status, "HYBRID");
    assert.equal(risk.score, 0);
    assert.ok(risk.drivers.some((d) => /classical fallback/.test(d)));
  } finally {
    udp.close();
  }
});

test("gateway that answers the ML-KEM offer with ADDKE NONE stays classical", async () => {
  let requests = 0;
  const udp = dgram.createSocket("udp4");
  udp.on("message", (_msg, rinfo) => {
    requests++;
    udp.send(ikeResponse([[1, 20, 256], [2, 7], [4, 19], [6, 0]]), rinfo.port, rinfo.address);
  });
  await new Promise<void>((r) => udp.bind(0, "127.0.0.1", r));
  try {
    const { graph } = await scanNetwork([{ host: "127.0.0.1", port: (udp.address() as net.AddressInfo).port, protocol: "ikev2", posture: "external", id: "vpn" }], { timeoutMs: 1500, now: NOW });
    assert.equal(requests, 1, "no fallback probe when no PQ ADDKE was chosen");
    const kex = graph.outgoing("vpn", ["ENCRYPTED_WITH"]).filter((e) => e.attrs?.role === "key-exchange").map((e) => (graph.get(e.to) as CryptoPrimitive).algorithm);
    assert.deepEqual(kex, ["ECDH-P-256"]);
    assert.equal((graph.get("vpn") as NetworkEndpoint).classicalFallback, undefined);
    const [risk] = scoreGraph(graph, resolveRiskConfig({ qDayYear: 2033, currentYear: 2026 }));
    assert.equal(risk.status, "VULNERABLE_SHOR");
  } finally {
    udp.close();
  }
});
