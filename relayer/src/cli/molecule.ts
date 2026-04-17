/**
 * Molecule encoding for AgentRecord
 */
export type AgentRecord = {
  emailHash: Uint8Array;
  identityCommitment: Uint8Array;
  ownerPubkey: Uint8Array;
  timelockBlocks: bigint;
  nonce: bigint;
};
function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}
function u64le(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, true);
  return b;
}
function fixvec(data: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + data.length);
  new DataView(out.buffer).setUint32(0, data.length, true);
  out.set(data, 4);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function encodeAgentRecord(r: AgentRecord): Uint8Array {
  const fields = [
    r.emailHash,
    r.identityCommitment,
    fixvec(r.ownerPubkey),
    u64le(r.timelockBlocks),
    u64le(r.nonce),
  ];
  const headerSize = 4 + fields.length * 4;
  let cursor = headerSize;
  const offsets = fields.map((f) => {
    const o = cursor;
    cursor += f.length;
    return o;
  });
  return concat(u32le(cursor), ...offsets.map(u32le), ...fields);
}

export function decodeAgentRecord(bytes: Uint8Array): AgentRecord {
  const v = new DataView(bytes.buffer, bytes.byteOffset);
  if (v.getUint32(0, true) !== bytes.length)
    throw new Error("molecule: size mismatch");
  const o0 = v.getUint32(4, true);
  const o1 = v.getUint32(8, true);
  const o2 = v.getUint32(12, true);
  const o3 = v.getUint32(16, true);
  const o4 = v.getUint32(20, true);

  const pubkeyLen = v.getUint32(o2, true);
  return {
    emailHash: bytes.slice(o0, o0 + 32),
    identityCommitment: bytes.slice(o1, o1 + 32),
    ownerPubkey: bytes.slice(o2 + 4, o2 + 4 + pubkeyLen),
    timelockBlocks: v.getBigUint64(o3, true),
    nonce: v.getBigUint64(o4, true),
  };
}
