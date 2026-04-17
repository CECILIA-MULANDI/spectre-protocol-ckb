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

const [email, secret, timelockArg] = process.argv.slice(2);
if (!email || !secret)
  throw new Error("usage: create.ts <email> <secret_phrase> [timelock_blocks]");
const timelockBlocks = BigInt(timelockArg ?? "2880");

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
      capacity: 300n * 100_000_000n,
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
