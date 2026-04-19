/**
 *
 * Generates a ckb-debugger transaction mock for the agent-type script.
 * Models a key rotation: one input cell (nonce=0) → one output cell (nonce=1).
 *
 * The mock JSON teaches ckb-debugger how to answer CKB syscalls:
 *   - ckb_load_cell_data(GroupInput, 0)  → input AgentRecord bytes
 *   - ckb_load_cell_data(GroupOutput, 0) → output AgentRecord bytes
 *
 *
 * cd relayer && npx tsx src/mock/gen_agent_type.ts
 * Output:
 *   ../contracts/spectre-contracts/mock/agent_type_rotate.json
 */

import { blake2b } from "@noble/hashes/blake2b";
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Path to the compiled RISC-V binary (built by `make build` in contracts/)
const BINARY_PATH = resolve(
  __dirname,
  "../../../contracts/spectre-contracts/target/riscv64imac-unknown-none-elf/release/agent-type"
);

const OUT_PATH = resolve(
  __dirname,
  "../../../contracts/spectre-contracts/mock/agent_type_rotate.json"
);

// CKB uses blake2b-256 with the personalisation string "ckb-default-hash".
// This is the hash that becomes code_hash in a Script with hash_type "data1".
function ckbHash(data: Uint8Array): Uint8Array {
  return blake2b(data, {
    personalization: new TextEncoder().encode("ckb-default-hash"),
    dkLen: 32,
  });
}

function toHex(bytes: Uint8Array): string {
  return "0x" + Buffer.from(bytes).toString("hex");
}

function hexPad(value: number, byteLength: number): string {
  return "0x" + value.toString(16).padStart(byteLength * 2, "0");
}

/**
 * Molecule encoding for AgentRecord (table with 5 fields):
 *
 *   table AgentRecord {
 *     email_hash:          Byte32,   // 32 bytes fixed
 *     identity_commitment: Byte32,   // 32 bytes fixed
 *     owner_pubkey:        Bytes,    // dynamic vector: [total_size u32 LE][items]
 *     timelock_blocks:     Uint64,   // 8 bytes fixed
 *     nonce:               Uint64,   // 8 bytes fixed
 *   }
 *
 * Molecule table layout:
 *   [total_size: u32 LE]          4 bytes
 *   [offset_0 .. offset_4: u32]  20 bytes  (5 × 4)
 *   [field data …]
 *
 * All offsets are absolute byte positions from the start of the table.
 * The number of offsets equals the number of fields (not fields+1 like some formats).
 */
function encodeAgentRecord(nonce: bigint): Buffer {
  const emailHash = Buffer.alloc(32, 0x00);
  const identityCommitment = Buffer.alloc(32, 0x00);

  // 33-byte compressed public key placeholder: 0x02 followed by 32 zero bytes
  const pubkeyData = Buffer.concat([
    Buffer.from([0x02]),
    Buffer.alloc(32, 0x00),
  ]);
  // Molecule fixvec (vector of fixed-size byte items): [item_count as u32 LE][items]
  // The header stores the NUMBER OF ITEMS (33), not the total byte length (37).
  const ownerPubkeyVec = Buffer.alloc(4 + pubkeyData.length);
  ownerPubkeyVec.writeUInt32LE(pubkeyData.length, 0);
  pubkeyData.copy(ownerPubkeyVec, 4);

  // 2880 blocks ≈ 1 day on CKB (block time ~30 s)
  const timelockBlocks = Buffer.alloc(8, 0x00);
  timelockBlocks.writeBigUInt64LE(2880n, 0);

  const nonceBytes = Buffer.alloc(8, 0x00);
  nonceBytes.writeBigUInt64LE(nonce, 0);

  // Compute offsets (absolute byte positions from start of table)
  const headerSize = 4 + 5 * 4; // 24 bytes
  const o0 = headerSize;
  const o1 = o0 + emailHash.length;
  const o2 = o1 + identityCommitment.length;
  const o3 = o2 + ownerPubkeyVec.length;
  const o4 = o3 + timelockBlocks.length;
  const totalSize = o4 + nonceBytes.length;

  const header = Buffer.alloc(headerSize);
  header.writeUInt32LE(totalSize, 0);
  for (const [i, offset] of [o0, o1, o2, o3, o4].entries()) {
    header.writeUInt32LE(offset, 4 + i * 4);
  }

  return Buffer.concat([
    header,
    emailHash,
    identityCommitment,
    ownerPubkeyVec,
    timelockBlocks,
    nonceBytes,
  ]);
}

// Placeholder tx hashes — arbitrary but recognisable in debug output
const INPUT_TX_HASH =
  "0x1111111111111111111111111111111111111111111111111111111111111111";
const DEP_TX_HASH =
  "0x2222222222222222222222222222222222222222222222222222222222222222";

// Capacity: 100 CKB in shannons (1 CKB = 10^8 shannons). No leading zeros.
const CAPACITY = "0x" + (100n * 100_000_000n).toString(16);

// always_success placeholder for the lock script (not executed in this test)
const ALWAYS_SUCCESS_HASH =
  "0x0000000000000000000000000000000000000000000000000000000000000001";

function main() {
  const binary = readFileSync(BINARY_PATH);
  const codeHash = toHex(ckbHash(binary));

  console.log(`agent-type binary: ${binary.length} bytes`);
  console.log(`code_hash (blake2b-256):  ${codeHash}`);

  const agentTypeScript = {
    code_hash: codeHash,
    hash_type: "data1", // VM version 1, code_hash = blake2b(binary)
    args: "0x",
  };

  const lockScript = {
    code_hash: ALWAYS_SUCCESS_HASH,
    hash_type: "data",
    args: "0x",
  };

  const inputData = "0x" + encodeAgentRecord(0n).toString("hex");
  const outputData = "0x" + encodeAgentRecord(1n).toString("hex");

  console.log(
    `input  AgentRecord (nonce=0): ${inputData.length / 2 - 1} bytes`
  );
  console.log(
    `output AgentRecord (nonce=1): ${outputData.length / 2 - 1} bytes`
  );

  const mock = {
    mock_info: {
      // mock_info.inputs describes the cells being consumed (the "live cells").
      // The debugger answers ckb_load_cell_data(Source::Input, …) from here.
      inputs: [
        {
          input: {
            previous_output: { tx_hash: INPUT_TX_HASH, index: "0x0" },
            since: "0x0",
          },
          output: {
            capacity: CAPACITY,
            lock: lockScript,
            type: agentTypeScript,
          },
          data: inputData,
        },
      ],
      // cell_deps hold the script binaries.
      // The VM loads code from here when it encounters a matching code_hash.
      cell_deps: [
        {
          cell_dep: {
            out_point: { tx_hash: DEP_TX_HASH, index: "0x0" },
            dep_type: "code",
          },
          output: {
            capacity: CAPACITY,
            lock: lockScript,
            type: null,
          },
          data: toHex(binary),
        },
      ],
      header_deps: [],
    },
    tx: {
      version: "0x0",
      cell_deps: [
        {
          out_point: { tx_hash: DEP_TX_HASH, index: "0x0" },
          dep_type: "code",
        },
      ],
      header_deps: [],
      inputs: [
        {
          previous_output: { tx_hash: INPUT_TX_HASH, index: "0x0" },
          since: "0x0",
        },
      ],
      outputs: [
        {
          capacity: CAPACITY,
          lock: lockScript,
          type: agentTypeScript,
        },
      ],
      outputs_data: [outputData],
      witnesses: ["0x"],
    },
  };

  mkdirSync(dirname(OUT_PATH), { recursive: true });
  writeFileSync(OUT_PATH, JSON.stringify(mock, null, 2));
  console.log(`\nWrote mock to: ${OUT_PATH}`);
  console.log(
    `\nRun the debugger:\n  ckb-debugger --tx-file contracts/spectre-contracts/mock/agent_type_rotate.json --script-group-type type --cell-index 0 --cell-type output`
  );
}

main();
