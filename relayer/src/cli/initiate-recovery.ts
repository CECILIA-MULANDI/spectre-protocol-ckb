/**
 * Initiate recovery: guardian signs a tx that moves the agent cell to recovery-pending state.
 *
 * What this builds:
 *   Input:  agent cell  (agent-lock + agent-type)
 *   Output: recovery-pending cell  (recovery-lock + agent-type)
 *   Data:   AgentRecord with pending_owner_pubkey = new_owner_pubkey (33 bytes)
 *   Witness: [0x01][recovery_id (1)][r+s (64)][compressed_pubkey (33)] = 99 bytes
 *
 * The recovery-lock args = blake160(current_owner_pubkey) — same as current agent-lock args —
 * so the owner can still cancel with their current key during the timelock window.
 */
import * as ccc from "@ckb-ccc/ccc";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { blake2b } from "@noble/hashes/blake2.js";
import { cccClient, cccSigner } from "./network.js";
import { loadConfig, saveConfig } from "./config.js";
import { decodeAgentRecord, encodeAgentRecord } from "./molecule.js";

const guardianPrivKey = process.argv[2];
const newOwnerPubKeyHex = process.argv[3];
if (!guardianPrivKey || !newOwnerPubKeyHex)
  throw new Error(
    "usage: initiate-recovery.ts <guardian-private-key> <new-owner-pubkey-hex>"
  );

const config = await loadConfig();

// Load current agent cell.
const currentTx = await cccClient.getTransaction(config.agentCellTxHash);
if (!currentTx) throw new Error("agent cell tx not found");
const currentRecord = decodeAgentRecord(
  ccc.bytesFrom(currentTx.transaction.outputsData[config.agentCellIndex]!)
);
console.log("current nonce:", currentRecord.nonce);
console.log("guardian threshold:", currentRecord.guardianThreshold);

const newOwnerPubKey = ccc.bytesFrom(newOwnerPubKeyHex);
if (newOwnerPubKey.length !== 33)
  throw new Error("new-owner-pubkey must be 33 bytes (compressed)");

// recovery-lock args = blake160(owner_pubkey) = same as current agent-lock args.
// This lets the owner cancel with their current key during the timelock.
const currentAgentLock =
  currentTx.transaction.outputs[config.agentCellIndex]!.lock;
const recoveryLockArgs = currentAgentLock.args;

const recoveryLock = ccc.Script.from({
  codeHash: config.recoveryLockCodeHash,
  hashType: "data1",
  args: recoveryLockArgs,
});

const agentTypeScript = ccc.Script.from({
  codeHash: config.typeCodeHash,
  hashType: "data1",
  args: "0x",
});

const pendingRecord = encodeAgentRecord({
  ...currentRecord,
  pendingOwnerPubkey: new Uint8Array(newOwnerPubKey),
});

const tx = ccc.Transaction.from({
  inputs: [
    {
      previousOutput: {
        txHash: config.agentCellTxHash,
        index: config.agentCellIndex,
      },
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
      capacity: BigInt(pendingRecord.length + 94) * 100_000_000n,
      lock: recoveryLock,
      type: agentTypeScript,
    },
  ],
  outputsData: [ccc.hexFrom(pendingRecord)],
});

// Guardian witness: [0x01][recovery_id][r+s][compressed_pubkey]
// The 0x01 prefix tells agent-lock to use the guardian path.
tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: "0x" + "00".repeat(99) }));
await tx.completeFeeBy(cccSigner, 1000n);

const rawTxHash = tx.hash();
const guardianPubKey = secp256k1.getPublicKey(
  ccc.bytesFrom(guardianPrivKey),
  true
);
const sig = secp256k1.sign(
  ccc.bytesFrom(rawTxHash),
  ccc.bytesFrom(guardianPrivKey)
);

const witness = new Uint8Array(99);
witness[0] = 0x01; // guardian path marker
witness[1] = sig.recovery;
witness.set(sig.toCompactRawBytes(), 2); // r+s at offset 2
witness.set(guardianPubKey, 66); // compressed pubkey at offset 66

// Sign fee inputs (input[1]) via cccSigner, then overwrite witness[0] with guardian sig.
// Order matters: secp256k1 sighash for input[1] does NOT include witness[0] (different lock group),
// so setting witness[0] after the fact does not invalidate input[1]'s signature.
const signedTx = await cccSigner.signTransaction(tx);
signedTx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: ccc.hexFrom(witness) }));

const txHash = await cccClient.sendTransaction(signedTx);
console.log("recovery initiated. tx hash:", txHash);
console.log("recovery-pending cell is at index 0 of this tx.");
console.log(
  `timelock: wait ${currentRecord.timelockBlocks} blocks before executing.`
);

await saveConfig({ ...config, agentCellTxHash: txHash, agentCellIndex: 0 });
