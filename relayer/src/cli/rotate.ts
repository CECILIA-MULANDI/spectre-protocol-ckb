/**
 * Spends the current agent cell and create a new one with different blake160(new_pubkey)
 *
 *
 **/
import * as ccc from "@ckb-ccc/ccc";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { blake2b } from "@noble/hashes/blake2.js";
import { cccClient, cccSigner } from "./network.js";
import { loadConfig, saveConfig } from "./config.js";
const config = await loadConfig();
const newPrivKey = process.argv[2];
if (!newPrivKey) throw new Error("usage: rotate.ts <new-private-key>");
const newPubKeyBytes = secp256k1.getPublicKey(ccc.bytesFrom(newPrivKey), true);
const newPubKeyHash = blake2b(newPubKeyBytes, { dkLen: 32 });
const newBlake160 = ccc.hexFrom(newPubKeyHash.slice(0, 20));
console.log("new blake160:", newBlake160);

/**
 * Build tx
 * --input: current agent cell
 * --cellDep:code cell
 * --output:new agent cell with new blake160 as args
 */

const newAgentLock = ccc.Script.from({
  codeHash: config.codeHash,
  hashType: "data1",
  args: newBlake160,
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
  ],
  outputs: [{ capacity: 62n * 100_000_000n, lock: newAgentLock }],
  outputsData: ["0x"],
});
tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: "0x" + "00".repeat(98) }));
await tx.completeFeeBy(cccSigner, 1000n);

const rawTxHash = tx.hash();

const sig = secp256k1.sign(
  ccc.bytesFrom(rawTxHash),
  ccc.bytesFrom(cccSigner.privateKey)
);

const witness = new Uint8Array(98);
witness[0] = sig.recovery;
witness.set(sig.toCompactRawBytes(), 1); // r+s = 64 bytes at offset 1
witness.set(ccc.bytesFrom(cccSigner.publicKey), 65); // compressed pubkey at offset 65

const witnessArgs = ccc.WitnessArgs.from({ lock: ccc.hexFrom(witness) });
tx.setWitnessArgsAt(0, witnessArgs);

const signedTx = await cccSigner.signTransaction(tx);
const txHash = await cccClient.sendTransaction(signedTx);

console.log("key rotated. tx hash:", txHash);
await saveConfig({ ...config, agentCellTxHash: txHash, agentCellIndex: 0 });
