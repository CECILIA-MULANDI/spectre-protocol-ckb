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

const newOwnerPubKeyHex = process.argv[2];
const guardianPrivKeys = process.argv.slice(3);
if (!newOwnerPubKeyHex || guardianPrivKeys.length === 0)
  throw new Error(
    "usage: initiate-recovery.ts <new-owner-pubkey-hex> <guardian-key-1> [guardian-key-2] ..."
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

if (guardianPrivKeys.length < currentRecord.guardianThreshold)
  throw new Error(
    `need at least ${currentRecord.guardianThreshold} guardian keys, got ${guardianPrivKeys.length}`
  );

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

// Guardian witness: [0x01][sig1 (98)][sig2 (98)]...[sigM (98)]
// Each sig block: [recovery_id (1)][r+s (64)][compressed_pubkey (33)] = 98 bytes
const witnessLen = 1 + guardianPrivKeys.length * 98;
tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: "0x" + "00".repeat(witnessLen) }));
await tx.completeFeeBy(cccSigner, 1000n);

const rawTxHash = tx.hash();

const witness = new Uint8Array(witnessLen);
witness[0] = 0x01; // guardian path marker

for (let i = 0; i < guardianPrivKeys.length; i++) {
  const privKey = ccc.bytesFrom(guardianPrivKeys[i]!);
  const pubKey = secp256k1.getPublicKey(privKey, true);
  const sig = secp256k1.sign(ccc.bytesFrom(rawTxHash), privKey);

  const offset = 1 + i * 98;
  witness[offset] = sig.recovery;
  witness.set(sig.toCompactRawBytes(), offset + 1); // r+s
  witness.set(pubKey, offset + 65); // compressed pubkey
}

// Sign fee inputs (input[1]) via cccSigner, then overwrite witness[0] with guardian sigs.
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
