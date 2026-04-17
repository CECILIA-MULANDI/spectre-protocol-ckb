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

const lockBin = await readFile(resolve(CONTRACTS, "agent-lock"));
const typeBin = await readFile(resolve(CONTRACTS, "agent-type"));

const prevConfig = await loadConfig().catch(() => null);
const prevInputs = prevConfig?.codeCellTxHash
  ? [
      {
        previousOutput: {
          txHash: prevConfig.codeCellTxHash,
          index: prevConfig.codeCellIndex,
        },
      },
      {
        previousOutput: {
          txHash: prevConfig.typeCodeCellTxHash,
          index: prevConfig.typeCodeCellIndex,
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
    { capacity: BigInt(lockBin.length + 61) * 100_000_000n, lock: ownerScript },
    { capacity: BigInt(typeBin.length + 61) * 100_000_000n, lock: ownerScript },
  ],
  outputsData: [ccc.bytesFrom(lockBin), ccc.bytesFrom(typeBin)],
});

await tx.completeInputsByCapacity(cccSigner);
await tx.completeFeeBy(cccSigner, 1000n);
const txHash = await cccSigner.sendTransaction(tx);

console.log("deployed. tx hash:", txHash);
await saveConfig({
  codeCellTxHash: txHash,
  codeCellIndex: 0,
  codeHash: ccc.hashCkb(lockBin),
  typeCodeCellTxHash: txHash,
  typeCodeCellIndex: 1,
  typeCodeHash: ccc.hashCkb(typeBin),
  agentCellTxHash: prevConfig?.agentCellTxHash ?? "",
  agentCellIndex: prevConfig?.agentCellIndex ?? 0,
});
console.log("agent-lock code hash:", ccc.hashCkb(lockBin));
console.log("agent-type code hash:", ccc.hashCkb(typeBin));
