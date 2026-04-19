/**
 * Creates agent cell on-chain
 * This is what the lock script controls
 */
import * as ccc from "@ckb-ccc/ccc";
import { blake2b } from "@noble/hashes/blake2.js";
import * as dotenv from "dotenv";
import { cccSigner } from "./network.js";
import { loadConfig, saveConfig } from "./config.js";
import { encodeAgentRecord } from "./molecule.js";
dotenv.config();

//create.ts <email> <secret_phrase> [timelock_blocks] [guardian_pubkeys_csv] [threshold]
//
// guardian_pubkeys_csv: comma-separated compressed pubkey hex values (33 bytes each)
// threshold:            m in m-of-n; defaults to total number of guardians
//
// example (1-of-1 guardian):
//   create.ts alice@example.com mysecret 2880 0x02abcd...ef 1
const [email, secret, timelockArg, guardiansArg, thresholdArg] =
  process.argv.slice(2);
if (!email || !secret)
  throw new Error(
    "usage: create.ts <email> <secret_phrase> [timelock_blocks] [guardian_pubkeys_csv] [threshold]"
  );
const timelockBlocks = BigInt(timelockArg ?? "2880");

// Parse guardian pubkeys → pack as N × 20-byte blake160 hashes.
const guardianPubkeys = guardiansArg
  ? guardiansArg
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
  : [];
const guardianHashes = new Uint8Array(guardianPubkeys.length * 20);
for (const [i, hex] of guardianPubkeys.entries()) {
  const pubkey = ccc.bytesFrom(hex);
  if (pubkey.length !== 33)
    throw new Error(`guardian pubkey ${i} must be 33 bytes`);
  const hash = blake2b(pubkey, { dkLen: 32 });
  guardianHashes.set(hash.slice(0, 20), i * 20);
}
const guardianThreshold = BigInt(thresholdArg ?? guardianPubkeys.length);

// Hash email and secret phrase with CKB's blake2b-256.
// These become the immutable recovery commitments stored on-chain.
const emailHash = blake2b(new TextEncoder().encode(email), { dkLen: 32 });
const identityCommitment = blake2b(new TextEncoder().encode(secret), {
  dkLen: 32,
});

const config = await loadConfig();

// Derive blake160(owner_pubkey) to use as lock.args.
const pubkeyBytes = ccc.bytesFrom(cccSigner.publicKey); // 33 bytes
const pubkeyHash = blake2b(pubkeyBytes, { dkLen: 32 });
const blake160 = ccc.hexFrom(pubkeyHash.slice(0, 20));
// Build the lock script
const agentLockScript = ccc.Script.from({
  codeHash: config.codeHash,
  hashType: "data1",
  args: blake160,
});
const agentTypeScript = ccc.Script.from({
  codeHash: config.typeCodeHash,
  hashType: "data1",
  args: "0x",
});
const record = encodeAgentRecord({
  emailHash,
  identityCommitment,
  ownerPubkey: pubkeyBytes,
  timelockBlocks: timelockBlocks,
  nonce: 0n,
  guardians: guardianHashes,
  guardianThreshold: guardianThreshold,
  pendingOwnerPubkey: new Uint8Array(0),
});
const tx = ccc.Transaction.from({
  cellDeps: [
    {
      outPoint: { txHash: config.codeCellTxHash, index: config.codeCellIndex },
      depType: "code",
    },
    {
      outPoint: {
        txHash: config.typeCodeCellTxHash,
        index: config.typeCodeCellIndex,
      },
      depType: "code",
    },
  ],
  outputs: [
    {
      capacity: BigInt(record.length + 94) * 100_000_000n,
      lock: agentLockScript,
      type: agentTypeScript,
    },
  ],
  outputsData: [ccc.hexFrom(record)],
});

await tx.completeInputsByCapacity(cccSigner);
await tx.completeFeeBy(cccSigner, 1000n);
const txHash = await cccSigner.sendTransaction(tx);
console.log("agent cell created. tx hash:", txHash);

await saveConfig({ ...config, agentCellTxHash: txHash, agentCellIndex: 0 });
console.log("config updated.");
