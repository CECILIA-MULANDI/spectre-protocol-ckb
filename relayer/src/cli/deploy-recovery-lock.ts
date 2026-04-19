/**
 * Deploy the recovery-lock binary to testnet and write its code hash into spectre.config.json.
 *
 * Run this once before using initiate-recovery, cancel-recovery, or execute-recovery.
 * agent-lock and agent-type must already be deployed (run deploy.ts first).
 */
import * as ccc from "@ckb-ccc/ccc";
import { readFile } from "fs/promises";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import * as dotenv from "dotenv";
import { cccSigner } from "./network.js";
import { loadConfig, saveConfig } from "./config.js";
dotenv.config();

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONTRACTS = resolve(
  __dirname,
  "../../../contracts/spectre-contracts/target/riscv64imac-unknown-none-elf/release"
);

const recoveryLockBin = await readFile(resolve(CONTRACTS, "recovery-lock"));

const prevConfig = await loadConfig();

// If a previous recovery-lock cell exists, recycle it as input.
const prevInputs = prevConfig.recoveryLockCodeCellTxHash
  ? [
      {
        previousOutput: {
          txHash: prevConfig.recoveryLockCodeCellTxHash,
          index: prevConfig.recoveryLockCodeCellIndex,
        },
      },
    ]
  : [];

const ownerScript = await cccSigner
  .getRecommendedAddressObj()
  .then((a) => a.script);

const tx = ccc.Transaction.from({
  inputs: prevInputs,
  outputs: [
    {
      capacity: BigInt(recoveryLockBin.length + 61) * 100_000_000n,
      lock: ownerScript,
    },
  ],
  outputsData: [ccc.bytesFrom(recoveryLockBin)],
});

await tx.completeInputsByCapacity(cccSigner);
await tx.completeFeeBy(cccSigner, 1000n);
const txHash = await cccSigner.sendTransaction(tx);

console.log("recovery-lock deployed. tx hash:", txHash);
console.log("recovery-lock code hash:", ccc.hashCkb(recoveryLockBin));

await saveConfig({
  ...prevConfig,
  recoveryLockCodeCellTxHash: txHash,
  recoveryLockCodeCellIndex: 0,
  recoveryLockCodeHash: ccc.hashCkb(recoveryLockBin),
});
