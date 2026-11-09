// IKEv2 IKE_SA_INIT probe (RFC 7296). Sends one initiator request; never completes the exchange.
import { randomBytes } from "node:crypto";
import { udpExchange } from "./io.ts";

interface Transform {
  type: number;
  id: number;
  keyLength?: number;
}

const AEAD_PROPOSAL: Transform[] = [
  { type: 1, id: 20, keyLength: 256 }, { type: 1, id: 20, keyLength: 128 }, { type: 1, id: 28 },
  { type: 2, id: 7 }, { type: 2, id: 6 }, { type: 2, id: 5 }, { type: 2, id: 2 },
];
const CBC_PROPOSAL: Transform[] = [
  { type: 1, id: 12, keyLength: 256 }, { type: 1, id: 12, keyLength: 128 }, { type: 1, id: 3 },
  { type: 2, id: 7 }, { type: 2, id: 6 }, { type: 2, id: 5 }, { type: 2, id: 2 },
  { type: 3, id: 14 }, { type: 3, id: 13 }, { type: 3, id: 12 }, { type: 3, id: 2 },
];
// Key exchange (type 4). Pure ML-KEM IDs per draft-ietf-ipsecme-ikev2-mlkem.
export const PROBE_DH = [36, 37, 35, 31, 32, 19, 20, 21, 14, 15, 16, 2];

const u16 = (n: number) => [(n >> 8) & 0xff, n & 0xff];
const u32 = (n: number) => [(n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];

function transformBytes(t: Transform, last: boolean): number[] {
  const attrs = t.keyLength ? [0x80, 0x0e, ...u16(t.keyLength)] : [];
  return [last ? 0 : 3, 0, ...u16(8 + attrs.length), t.type, 0, ...u16(t.id), ...attrs];
}

function proposal(num: number, ts: Transform[], last: boolean): number[] {
  const body = ts.flatMap((t, i) => transformBytes(t, i === ts.length - 1));
  return [last ? 0 : 2, 0, ...u16(8 + body.length), num, 1, 0, ts.length, ...body];
}

export function buildIkeSaInit(opts: { dhGroup?: number; spi?: Uint8Array; nonce?: Uint8Array } = {}): Uint8Array {
  const dh = opts.dhGroup ?? 31;
  const dhs = PROBE_DH.map((id) => ({ type: 4, id }));
  const props = [...proposal(1, [...AEAD_PROPOSAL, ...dhs], false), ...proposal(2, [...CBC_PROPOSAL, ...dhs], true)];
  const sa = [34, 0, ...u16(4 + props.length), ...props]; // next = KE
  const keLen = ({ 31: 32, 32: 56, 19: 64, 20: 96, 21: 132, 14: 256, 15: 384, 16: 512, 2: 128 } as Record<number, number>)[dh] ?? 32;
  const ke = [40, 0, ...u16(8 + keLen), ...u16(dh), 0, 0, ...randomBytes(keLen)]; // next = Nonce
  const nonce = [...(opts.nonce ?? randomBytes(32))];
  const ni = [0, 0, ...u16(4 + nonce.length), ...nonce];
  const payloads = [...sa, ...ke, ...ni];
  const spi = [...(opts.spi ?? randomBytes(8))];
  const hdr = [...spi, ...new Array(8).fill(0), 33, 0x20, 34, 0x08, ...u32(0), ...u32(28 + payloads.length)];
  return new Uint8Array([...hdr, ...payloads]);
}

export interface IkeProbeResult {
  accepted: Transform[]; // transforms in the responder's chosen proposal
  invalidKeGroup?: number; // INVALID_KE_PAYLOAD: responder wants this DH group
  notifyError?: number; // e.g. 14 NO_PROPOSAL_CHOSEN
}

export function parseIkeResponse(buf: Uint8Array): IkeProbeResult {
  if (buf.length < 28 || buf[17] !== 0x20) throw new Error("not an IKEv2 message");
  const out: IkeProbeResult = { accepted: [] };
  let next = buf[16];
  let p = 28;
  while (next !== 0 && p + 4 <= buf.length) {
    const np = buf[p];
    const len = (buf[p + 2] << 8) | buf[p + 3];
    const body = buf.subarray(p + 4, p + len);
    if (next === 33) {
      // SA: first (chosen) proposal
      const tcount = body[7];
      let q = 8 + body[6];
      for (let i = 0; i < tcount && q + 8 <= body.length; i++) {
        const tlen = (body[q + 2] << 8) | body[q + 3];
        const t: Transform = { type: body[q + 4], id: (body[q + 6] << 8) | body[q + 7] };
        for (let a = q + 8; a + 4 <= q + tlen; a += 4) if (((body[a] << 8) | body[a + 1]) === 0x800e) t.keyLength = (body[a + 2] << 8) | body[a + 3];
        out.accepted.push(t);
        q += tlen;
      }
    } else if (next === 41) {
      const type = (body[2] << 8) | body[3];
      const spiSize = body[1];
      if (type === 17) out.invalidKeGroup = (body[4 + spiSize] << 8) | body[5 + spiSize];
      else if (type < 16384) out.notifyError = type;
    }
    next = np;
    p += len;
  }
  return out;
}

export async function probeIke(host: string, port = 500, timeoutMs?: number): Promise<IkeProbeResult> {
  let res = parseIkeResponse(await udpExchange(host, port, buildIkeSaInit(), timeoutMs));
  if (res.invalidKeGroup !== undefined && !res.accepted.length) {
    // Retry once with the group the responder asked for; the SA it returns lists the full chosen suite.
    try {
      const again = parseIkeResponse(await udpExchange(host, port, buildIkeSaInit({ dhGroup: res.invalidKeGroup }), timeoutMs));
      res = { ...again, invalidKeGroup: res.invalidKeGroup };
    } catch {
      /* keep the INVALID_KE_PAYLOAD observation */
    }
  }
  return res;
}
