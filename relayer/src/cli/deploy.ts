/**
 * Stores the lock script binary on-chain
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

const binary = await readFile(
  resolve(
    __dirname,
    "../../../contracts/spectre-contracts/target/riscv64imac-unknown-none-elf/release/agent-lock"
  )
);

// Explicitly reclaim the previous code cell if one exists, so the indexer
// doesn't need to discover it automatically via completeInputsByCapacity.
const prevConfig = await loadConfig().catch(() => null);
const prevCodeInput =
  prevConfig?.codeCellTxHash
    ? [{ previousOutput: { txHash: prevConfig.codeCellTxHash, index: prevConfig.codeCellIndex } }]
    : [];

const tx = ccc.Transaction.from({
  inputs: prevCodeInput,
  outputs: [
    {
      capacity: BigInt(binary.length + 61) * 100_000_000n,
      lock: await cccSigner.getRecommendedAddressObj().then((a) => a.script),
    },
  ],
  outputsData: [ccc.bytesFrom(binary)],
});

await tx.completeInputsByCapacity(cccSigner);
await tx.completeFeeBy(cccSigner, 1000n);
const codeHash = ccc.hashCkb(binary);
const txHash = await cccSigner.sendTransaction(tx);
console.log("agent-lock deployed. tx hash:", txHash);
await saveConfig({
  codeCellTxHash: txHash,
  codeCellIndex: 0,
  codeHash,
  agentCellTxHash: "",
  agentCellIndex: 0,
});
console.log("config saved. code hash:", codeHash);
