#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
ckb_std::default_alloc!(16384, 1258306, 64);

use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1};

use ckb_std::ckb_constants::Source;
use ckb_std::high_level::{load_script, load_tx_hash, load_witness_args};

// agent-lock: authorizes spending of the agent cell.
//
// Responsibility: verify that the spender holds the private key corresponding
// to the blake160 pubkey hash stored in lock.args. Nothing more.
//
// What this script does NOT do (by design):
//   - Nonce enforcement: nonce lives in cell data (AgentRecord) and is
//     validated by the agent-type script (Phase 2). CKB's cell model already
//     prevents replay for sig-based rotation — a spent cell is consumed and
//     cannot be re-used. Nonce becomes critical for ZK recovery (Phase 3-4)
//     where proofs reference a specific nonce; that check belongs in agent-type.
//   - State transitions: AgentRecord schema and mutation rules are agent-type's job.
//   - ZK proof verification: handled by a separate PLONK verifier script (Phase 4).
//
// lock.args layout: [blake160(owner_pubkey)] = 20 bytes
// witness layout:   [recovery_id (1)][r (32)][s (32)][compressed_pubkey (33)] = 98 bytes

// Error codes
// lock.args must be exactly 20 bytes (blake160 pubkey hash)
const ERROR_ARGS_LEN: i8 = 1;
// witness must contain a valid secp256k1 signature + pubkey
const ERROR_INVALID_WITNESS: i8 = 2;
// signature doesn't match the pubkey hash in lock.args
const ERROR_INVALID_SIGNATURE: i8 = 3;

pub fn program_entry() -> i8 {
    // Read lock.args: this is the blake160 hash of the owner's pubkey.
    // Script:{code_hash, hash_type,args}
    let script = match load_script() {
        Ok(s) => s,
        Err(_) => return ERROR_ARGS_LEN,
    };

    let args = script.args();
    let args_bytes = args.raw_data();

    // blake160 is always 20 bytes.
    // If it's anything else, the cell was set up wrong.
    if args_bytes.len() != 20 {
        return ERROR_ARGS_LEN;
    }

    // Read the witness
    let witness_args = match load_witness_args(0, Source::GroupInput) {
        Ok(w) => w,
        Err(_) => return ERROR_INVALID_WITNESS,
    };
    let lock_field = match witness_args.lock().to_opt() {
        Some(l) => l,
        None => return ERROR_INVALID_WITNESS,
    };
    let witness_bytes = lock_field.raw_data();
    if witness_bytes.len() != 98 {
        return ERROR_INVALID_WITNESS;
    }
    // Load the tx hash: this is what the owner signed.
    // It's already a hash so we use it directly as the message.
    let tx_hash = match load_tx_hash() {
        Ok(h) => h,
        Err(_) => return ERROR_INVALID_WITNESS,
    };

    let recovery_id = match RecoveryId::from_i32(witness_bytes[0] as i32) {
        Ok(id) => id,
        Err(_) => return ERROR_INVALID_SIGNATURE,
    };
    let sig = match RecoverableSignature::from_compact(&witness_bytes[1..65], recovery_id) {
        Ok(s) => s,
        Err(_) => return ERROR_INVALID_SIGNATURE,
    };
    let msg = match Message::from_digest_slice(&tx_hash) {
        Ok(m) => m,
        Err(_) => return ERROR_INVALID_SIGNATURE,
    };
    let secp = Secp256k1::verification_only();
    let recovered_key = match secp.recover_ecdsa(&msg, &sig) {
        Ok(k) => k,
        Err(_) => return ERROR_INVALID_SIGNATURE,
    };
    let pubkey_serialized = recovered_key.serialize(); // [u8; 33], compressed

    if &witness_bytes[65..] != pubkey_serialized.as_ref() {
        return ERROR_INVALID_SIGNATURE;
    }

    let mut hasher = Blake2bVar::new(32).unwrap();
    hasher.update(&pubkey_serialized);
    let mut hash_out = [0u8; 32];
    hasher.finalize_variable(&mut hash_out).unwrap();
    let pubkey_hash = &hash_out[..20];

    if pubkey_hash != args_bytes.as_ref() {
        return ERROR_INVALID_SIGNATURE;
    }

    0
}
