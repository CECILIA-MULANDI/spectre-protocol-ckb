import * as ccc from "@ckb-ccc/ccc";
import { blake2b } from "@noble/hashes/blake2.js";
import * as dotenv from "dotenv";
import { cccSigner } from "./network.js";
import { loadConfig, saveConfig } from "./config.js";
dotenv.config();
/**
 * Creates agent cell on-chain
 * This is what the lock script controls
 */

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

const tx = ccc.Transaction.from({
  cellDeps: [
    {
      outPoint: { txHash: config.codeCellTxHash, index: config.codeCellIndex },
      depType: "code",
    },
  ],
  outputs: [{ capacity: 62n * 100_000_000n, lock: agentLockScript }],
  outputsData: ["0x"],
});

await tx.completeInputsByCapacity(cccSigner);
await tx.completeFeeBy(cccSigner, 1000n);
const txHash = await cccSigner.sendTransaction(tx);
console.log("agent cell created. tx hash:", txHash);

await saveConfig({ ...config, agentCellTxHash: txHash, agentCellIndex: 0 });
console.log("config updated.");
