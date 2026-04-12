# Spectre Protocol

Key recovery for autonomous AI agents on CKB, using ZK email proofs.

## Overview

Spectre lets an AI agent's controlling key be rotated or recovered without exposing long-term secrets. The owner proves (in zero-knowledge) that they received an authenticating email, triggering a time-locked key rotation on-chain.

## Architecture

```
spectre/
├── circuits/        # Noir ZK circuit — DKIM email proof
├── contracts/       # On-chain CKB scripts (Rust → RISC-V)
│   └── spectre-contracts/
│       └── agent-lock/   # Lock script controlling the agent cell
└── relayer/         # Off-chain: email parser, ZK prover, CKB tx builder
```

## Status

Active development. Phase 1: agent cell lock script on CKB devnet.

## Tech

- **ZK circuit**: Noir + Barretenberg (DKIM signature verification)
- **On-chain**: Rust → RISC-V (CKB-VM), `ckb-std`
- **Off-chain**: TypeScript, `ckb-sdk`
