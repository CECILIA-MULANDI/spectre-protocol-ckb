import { readFile, writeFile } from "fs/promises";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONFIG_PATH = resolve(__dirname, "../../../spectre.config.json");

export type Config = {
  // where the agent-lock binary is deployed
  codeCellTxHash: string;
  codeCellIndex: number;
  // data1 code hash of the deployed binary (used to build the lock script)
  codeHash: string;
  // where the current agent cell lives
  agentCellTxHash: string;
  agentCellIndex: number;
  // agent-type binary cell
  typeCodeCellTxHash: string;
  typeCodeCellIndex: number;
  typeCodeHash: string;
  // recovery-lock binary cell (Phase 3)
  recoveryLockCodeCellTxHash: string;
  recoveryLockCodeCellIndex: number;
  recoveryLockCodeHash: string;
};

export async function saveConfig(config: Config): Promise<void> {
  await writeFile(CONFIG_PATH, JSON.stringify(config, null, 2));
}

export async function loadConfig(): Promise<Config> {
  const raw = await readFile(CONFIG_PATH, "utf-8");
  return JSON.parse(raw) as Config;
}
