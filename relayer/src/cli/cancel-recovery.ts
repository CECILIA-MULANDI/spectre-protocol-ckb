/**
 * Cancel recovery: owner signs to reclaim the recovery-pending cell before the timelock expires.
 * (uses the owner private key from the configured signer)
 *
 * What this builds:
 *   Input:  recovery-pending cell  (recovery-lock)
 *   Output: agent cell  (agent-lock + agent-type), same owner key, pending cleared, nonce+1
 *   Witness: [recovery_id (1)][r+s (64)][compressed_pubkey (33)] = 98 bytes
 *
 * recovery-lock sees a 98-byte witness → cancellation path → verifies owner sig.
 */
import * as ccc from "@ckb-ccc/ccc";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { cccClient, cccSigner } from "./network.js";
import { loadConfig, saveConfig } from "./config.js";
import { decodeAgentRecord, encodeAgentRecord } from "./molecule.js";

const config = await loadConfig();

const pendingTx = await cccClient.getTransaction(config.agentCellTxHash);
if (!pendingTx) throw new Error("recovery-pending cell tx not found");
const pendingRecord = decodeAgentRecord(
  ccc.bytesFrom(pendingTx.transaction.outputsData[config.agentCellIndex]!)
);

if (pendingRecord.pendingOwnerPubkey.length === 0)
  throw new Error("no recovery in progress (pendingOwnerPubkey is empty)");

console.log(
  "cancelling recovery for pending key:",
  ccc.hexFrom(pendingRecord.pendingOwnerPubkey)
);

// Output: same owner key as before, pending cleared, nonce+1.
const cancelledRecord = encodeAgentRecord({
  ...pendingRecord,
  nonce: pendingRecord.nonce + 1n,
  pendingOwnerPubkey: new Uint8Array(0),
});

const agentLock = ccc.Script.from({
  codeHash: config.codeHash,
  hashType: "data1",
  args: pendingTx.transaction.outputs[config.agentCellIndex]!.lock.args,
});

const agentTypeScript = ccc.Script.from({
  codeHash: config.typeCodeHash,
  hashType: "data1",
  args: "0x",
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
    { capacity: BigInt(cancelledRecord.length + 94) * 100_000_000n, lock: agentLock, type: agentTypeScript },
  ],
  outputsData: [ccc.hexFrom(cancelledRecord)],
});

// 98-byte owner sig → recovery-lock cancellation path.
tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: "0x" + "00".repeat(98) }));
await tx.completeFeeBy(cccSigner, 1000n);

const rawTxHash = tx.hash();
const sig = secp256k1.sign(
  ccc.bytesFrom(rawTxHash),
  ccc.bytesFrom(cccSigner.privateKey)
);

const witness = new Uint8Array(98);
witness[0] = sig.recovery;
witness.set(sig.toCompactRawBytes(), 1);
witness.set(ccc.bytesFrom(cccSigner.publicKey), 65);

tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: ccc.hexFrom(witness) }));

const txHash = await cccSigner.sendTransaction(tx);
console.log("recovery cancelled. tx hash:", txHash);

await saveConfig({ ...config, agentCellTxHash: txHash, agentCellIndex: 0 });
