#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
ckb_std::default_alloc!(16384, 1258306, 64);

use blake2::{Blake2bVar, digest::{Update, VariableOutput}};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1};

use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::prelude::Unpack;
use ckb_std::high_level::{load_cell_data, load_input, load_script, load_tx_hash, load_witness_args};
use spectre_types::{AgentRecordReader, prelude::Reader as _};

// recovery-lock: authorizes spending of a recovery-pending agent cell.
//
// lock.args: blake160(original_owner_pubkey) = 20 bytes
//
// Two spending paths:
//   Cancellation: witness contains a valid owner sig → verify and allow.
//   Execution:    no valid sig in witness → verify that input.since encodes
//                 a relative block number ≥ timelock_blocks in the AgentRecord.
//                 CKB nodes enforce the since constraint at consensus; we verify
//                 it here so a transaction with since=0 cannot bypass the lock.

const ERROR_ARGS_LEN: i8 = 1;
const ERROR_INVALID_WITNESS: i8 = 2;
const ERROR_INVALID_SIGNATURE: i8 = 3;
const ERROR_TIMELOCK_NOT_MET: i8 = 4;
const ERROR_INVALID_RECORD: i8 = 5;

pub fn program_entry() -> i8 {
    let script = match load_script() {
        Ok(s) => s,
        Err(_) => return ERROR_ARGS_LEN,
    };
    let args = script.args();
    let args_bytes = args.raw_data();
    if args_bytes.len() != 20 {
        return ERROR_ARGS_LEN;
    }

    // Determine path by whether a valid-length witness lock field is present.
    // A missing witness or wrong-length field → execution path (since check).
    let has_witness = match load_witness_args(0, Source::GroupInput) {
        Ok(w) => w.lock().to_opt().map(|l| l.raw_data().len() == 98).unwrap_or(false),
        Err(_) => false,
    };

    if has_witness {
        return verify_owner_sig(&args_bytes);
    }

    verify_timelock()
}

fn verify_owner_sig(args_bytes: &[u8]) -> i8 {
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
    let pubkey_serialized = recovered_key.serialize();

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

fn verify_timelock() -> i8 {
    let input = match load_input(0, Source::GroupInput) {
        Ok(i) => i,
        Err(_) => return ERROR_TIMELOCK_NOT_MET,
    };
    let since: u64 = input.since().unpack();

    // since must encode a relative block number:
    // bit 63 = 1 (relative), bits 62-61 = 00 (block number metric)
    if since >> 62 != 0b10 {
        return ERROR_TIMELOCK_NOT_MET;
    }
    let since_blocks = since & 0x00FF_FFFF_FFFF_FFFF;

    let cell_data = match load_cell_data(0, Source::GroupInput) {
        Ok(d) => d,
        Err(_) => return ERROR_INVALID_RECORD,
    };
    let record = match AgentRecordReader::from_slice(&cell_data) {
        Ok(r) => r,
        Err(_) => return ERROR_INVALID_RECORD,
    };
    let timelock = u64::from_le_bytes(
        record.timelock_blocks().as_slice().try_into().unwrap_or([0u8; 8]),
    );

    if since_blocks < timelock {
        return ERROR_TIMELOCK_NOT_MET;
    }
    0
}
