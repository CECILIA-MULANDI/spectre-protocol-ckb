/**
 * Execute recovery: anyone can run this after the timelock to complete the key swap.
 *
 * What this builds:
 *   Input:  recovery-pending cell  (recovery-lock), since = relative block >= timelock_blocks
 *   Output: agent cell  (agent-lock with new owner key + agent-type), pending cleared, nonce+1
 *   Witness: empty lock field → recovery-lock takes the timelock path (no sig needed).
 */
import * as ccc from "@ckb-ccc/ccc";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { blake2b } from "@noble/hashes/blake2.js";
import { cccClient, cccSigner } from "./network.js";
import { loadConfig, saveConfig } from "./config.js";
import { decodeAgentRecord, encodeAgentRecord } from "./molecule.js";

const config = await loadConfig();

const pendingTx = await cccClient.getTransaction(config.agentCellTxHash);
if (!pendingTx) throw new Error("recovery-pending cell tx not found");
const pendingRecord = decodeAgentRecord(
  ccc.bytesFrom(pendingTx.transaction.outputsData[config.agentCellIndex]!)
);

if (pendingRecord.pendingOwnerPubkey.length !== 33)
  throw new Error(
    "no recovery in progress (pendingOwnerPubkey is not 33 bytes)"
  );

const newOwnerPubKey = pendingRecord.pendingOwnerPubkey;
console.log(
  "executing recovery to new owner pubkey:",
  ccc.hexFrom(newOwnerPubKey)
);

// blake160(new_owner_pubkey) becomes the new agent-lock args.
const newOwnerHash = blake2b(newOwnerPubKey, { dkLen: 32 });
const newBlake160 = ccc.hexFrom(newOwnerHash.slice(0, 20));

const newAgentLock = ccc.Script.from({
  codeHash: config.codeHash,
  hashType: "data1",
  args: newBlake160,
});

const agentTypeScript = ccc.Script.from({
  codeHash: config.typeCodeHash,
  hashType: "data1",
  args: "0x",
});

const executedRecord = encodeAgentRecord({
  ...pendingRecord,
  ownerPubkey: new Uint8Array(newOwnerPubKey),
  nonce: pendingRecord.nonce + 1n,
  pendingOwnerPubkey: new Uint8Array(0),
});

// since = relative block number >= timelock_blocks.
// Bit 63 = 1 (relative), bits 62-61 = 00 (block metric), rest = value.
const since = (0b10n << 62n) | pendingRecord.timelockBlocks;

const tx = ccc.Transaction.from({
  inputs: [
    {
      previousOutput: {
        txHash: config.agentCellTxHash,
        index: config.agentCellIndex,
      },
      since: `0x${since.toString(16)}`,
    },
  ],
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
    {
      outPoint: {
        txHash: config.recoveryLockCodeCellTxHash,
        index: config.recoveryLockCodeCellIndex,
      },
      depType: "code",
    },
  ],
  outputs: [
    {
      capacity: BigInt(executedRecord.length + 94) * 100_000_000n,
      lock: newAgentLock,
      type: agentTypeScript,
    },
  ],
  outputsData: [ccc.hexFrom(executedRecord)],
});

// Empty witness lock field → recovery-lock takes the timelock path.
tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: "0x" }));
await tx.completeFeeBy(cccSigner, 1000n);

const txHash = await cccClient.sendTransaction(tx);
console.log("recovery executed. new owner is now in control.");
console.log("tx hash:", txHash);

await saveConfig({ ...config, agentCellTxHash: txHash, agentCellIndex: 0 });
