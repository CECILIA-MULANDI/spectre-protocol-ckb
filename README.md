# Spectre Protocol

Key recovery for autonomous AI agents on CKB, without exposing secrets or trusting a centralized service.

## What it does

An AI agent holds a CKB key that authorizes all its on-chain actions. If that key is compromised, the agent is stuck. Spectre lets registered guardians trigger a time-locked key rotation. During the timelock, the real owner can cancel a fraudulent recovery. After the timelock, anyone can execute it. No trusted third party required.

## How it works now

```
Agent cell (agent-lock + agent-type)
  │
  │  Guardian signs tx → sets pending_owner_pubkey
  ▼
Recovery-pending cell (recovery-lock + agent-type)
  │
  ├── Owner cancels (any time before timelock) → restored agent cell, nonce+1
  │
  └── Timelock expires (2880 blocks ≈ 6.4h) → new agent cell with new owner key
```

**agent-lock**: two spending paths, distinguished by witness layout:

- 98-byte witness: owner signs directly (key rotation)
- `[0x01] + N×98-byte sigs`: M-of-N guardians sign (initiate recovery)

**agent-type**: enforces state transitions in the AgentRecord. Prevents nonce reuse and invalid pending state changes.

**recovery-lock**: gates the recovery-pending cell. Owner sig cancels; empty witness + satisfied timelock executes.

## Contracts (testnet)

All contracts are deployed. You do not need to redeploy to test.

| Contract      | Code Hash                                                            |
| ------------- | -------------------------------------------------------------------- |
| agent-lock    | `0x01c36835398a6d1224f059e9e63f2a0404860e714120a73c5702552d3e27ca5c` |
| agent-type    | `0xa2c17896aaab2b868d1c71cde87b3fe268ecdfa46c0c787bdf6e477132a525d9` |
| recovery-lock | `0x29fb2cf2c601bdd8850d61841836db31884e0a51ac1d389f755edd437f61b3d3` |

## Test the recovery flow (testnet)

### Prerequisites

- Node.js 18+
- A CKB testnet private key
- Testnet CKB, get from the faucet at https://faucet.nervos.org/ (you need ~400 CKB)

### 1. Clone and install

```bash
git clone https://github.com/CECILIA-MULANDI/spectre-protocol-ckb
cd spectre/relayer
npm install
```

### 2. Configure

Create `relayer/.env`:

```
PRIVATE_KEY=0x<your-32-byte-private-key>
NETWORK=testnet
```

Create `spectre.config.json` in the repo root with the deployed contract references:

```json
{
  "codeCellTxHash": "0x6eb7054885ec3d1b8185c225c6476fc241acfc890e09f6f26e49a6f9bf63f70c",
  "codeCellIndex": 0,
  "codeHash": "0x01c36835398a6d1224f059e9e63f2a0404860e714120a73c5702552d3e27ca5c",
  "typeCodeCellTxHash": "0x6eb7054885ec3d1b8185c225c6476fc241acfc890e09f6f26e49a6f9bf63f70c",
  "typeCodeCellIndex": 1,
  "typeCodeHash": "0xa2c17896aaab2b868d1c71cde87b3fe268ecdfa46c0c787bdf6e477132a525d9",
  "agentCellTxHash": "",
  "agentCellIndex": 0,
  "recoveryLockCodeCellTxHash": "0xd19bc3c2346d85b083f0e508994a725cfec00e5c28df64967edbf4009b6ec861",
  "recoveryLockCodeCellIndex": 0,
  "recoveryLockCodeHash": "0x29fb2cf2c601bdd8850d61841836db31884e0a51ac1d389f755edd437f61b3d3"
}
```

### 3. Get your public key

```bash
cd relayer
npx tsx get-pubkey.mts
# → pubkey: 0x02...
```

Fund the address shown. To get the address:

```bash
npx tsx get-addr.mjs
# → ckt1q...
```

Paste that address into https://faucet.nervos.org/ and request CKB. Request a few times; you need at least 400 CKB.

### 4. Generate a "new owner" keypair (simulates the recovered key)

```bash
npx tsx gen-keypair.mts
# → private key: 0x...
# → public key:  0x...
```

Save both. You'll use the public key in the next step and the private key later if you want to prove the new owner can spend the cell.

### 5. Create the agent cell

Registers you as a 1-of-1 guardian. Replace the values:

```bash
npx tsx src/cli/create.ts \
  alice@example.com \
  mysecretphrase \
  2880 \
  <your-pubkey-from-step-3> \
  1
```

Wait for the tx to confirm (~10 seconds), then proceed.

### 6. Initiate recovery

The guardian (you, in this test) signs a tx that moves the agent cell to recovery-pending state with the new owner key set:

```bash
npx tsx src/cli/initiate-recovery.ts \
  <your-private-key> \
  <new-owner-pubkey-from-step-4>
```

Output: `recovery initiated. tx hash: 0x...`

The cell is now locked under `recovery-lock`. The timelock is 2880 blocks.

### 7a. Cancel recovery (owner path, no waiting required)

The current owner can abort at any time during the timelock:

```bash
npx tsx src/cli/cancel-recovery.ts
```

The cell returns to normal agent-lock state with nonce incremented. Recovery is cleanly aborted.

### 7b. Execute recovery (timelock path, after 2880 blocks)

After the timelock expires (~6.4 hours on testnet), anyone can execute:

```bash
npx tsx src/cli/execute-recovery.ts
```

The agent cell reappears with the new owner's key in `agent-lock.args`. The old key can no longer spend it.

## On-chain data (AgentRecord)

Every agent cell carries a Molecule-encoded record:

| Field                  | Size     | Description                                                 |
| ---------------------- | -------- | ----------------------------------------------------------- |
| `email_hash`           | 32 bytes | blake2b-256 of recovery email address                       |
| `identity_commitment`  | 32 bytes | blake2b-256 of secret phrase (Phase 1); World ID in Phase 4 |
| `owner_pubkey`         | 33 bytes | Current owner's compressed secp256k1 pubkey                 |
| `timelock_blocks`      | 8 bytes  | Blocks to wait before recovery executes                     |
| `nonce`                | 8 bytes  | Incremented on each state change; prevents replay           |
| `guardians`            | variable | N × 20-byte blake160 pubkey hashes                          |
| `guardian_threshold`   | 8 bytes  | M in M-of-N                                                 |
| `pending_owner_pubkey` | variable | 33 bytes during recovery, empty otherwise                   |

## Running integration tests

```bash
cd contracts/spectre-contracts
cargo test --target x86_64-unknown-linux-gnu -p tests
```
