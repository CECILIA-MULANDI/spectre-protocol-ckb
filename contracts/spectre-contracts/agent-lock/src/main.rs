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
use ckb_std::high_level::{load_cell_data, load_script, load_tx_hash, load_witness_args};
use spectre_types::{AgentRecordReader, prelude::Reader as _};

// agent-lock: authorizes spending of the agent cell.
//
// Two spending paths, distinguished by witness layout:
//
//   Owner path (key rotation):
//     witness = [recovery_id (1)][r (32)][s (32)][compressed_pubkey (33)] = 98 bytes
//     Verifies the spender holds the private key for blake160(pubkey) in lock.args.
//
//   Guardian path (initiate recovery):
//     witness = [0x01][sig1 (98)][sig2 (98)]...[sigN (98)] = 1 + N*98 bytes
//     Verifies that at least `guardian_threshold` of the registered guardians
//     have signed this transaction. Guardian list is in the input AgentRecord.
//
// lock.args layout: [blake160(owner_pubkey)] = 20 bytes

const ERROR_ARGS_LEN: i8 = 1;
const ERROR_INVALID_WITNESS: i8 = 2;
const ERROR_INVALID_SIGNATURE: i8 = 3;
const ERROR_INVALID_RECORD: i8 = 4;
const ERROR_GUARDIAN_DISABLED: i8 = 5;
const ERROR_INSUFFICIENT_GUARDIAN_SIGS: i8 = 6;

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

    let witness_args = match load_witness_args(0, Source::GroupInput) {
        Ok(w) => w,
        Err(_) => return ERROR_INVALID_WITNESS,
    };
    let lock_field = match witness_args.lock().to_opt() {
        Some(l) => l,
        None => return ERROR_INVALID_WITNESS,
    };
    let witness_bytes = lock_field.raw_data();

    if witness_bytes.len() == 98 {
        // Owner path: single sig.
        verify_owner_sig(&args_bytes, &witness_bytes)
    } else if witness_bytes.len() >= 99
        && witness_bytes[0] == 0x01
        && (witness_bytes.len() - 1) % 98 == 0
    {
        // Guardian path: 0x01 prefix + N * 98-byte sigs.
        verify_guardian_sigs(&witness_bytes[1..])
    } else {
        ERROR_INVALID_WITNESS
    }
}

fn blake160(data: &[u8]) -> [u8; 20] {
    let mut hasher = Blake2bVar::new(32).unwrap();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).unwrap();
    let mut result = [0u8; 20];
    result.copy_from_slice(&out[..20]);
    result
}

fn recover_pubkey_hash(sig_bytes: &[u8], msg: &Message, secp: &Secp256k1<secp256k1::VerifyOnly>) -> Option<[u8; 20]> {
    // sig_bytes layout: [recovery_id (1)][r+s (64)][compressed_pubkey (33)] = 98 bytes
    let recovery_id = RecoveryId::from_i32(sig_bytes[0] as i32).ok()?;
    let sig = RecoverableSignature::from_compact(&sig_bytes[1..65], recovery_id).ok()?;
    let recovered_key = secp.recover_ecdsa(msg, &sig).ok()?;
    let pubkey_serialized = recovered_key.serialize();

    // Verify the embedded pubkey matches what was actually recovered.
    // This prevents grinding attacks where an attacker substitutes a different pubkey.
    if sig_bytes[65..] != pubkey_serialized {
        return None;
    }
    Some(blake160(&pubkey_serialized))
}

fn verify_owner_sig(args_bytes: &[u8], witness_bytes: &[u8]) -> i8 {
    let tx_hash = match load_tx_hash() {
        Ok(h) => h,
        Err(_) => return ERROR_INVALID_WITNESS,
    };
    let msg = match Message::from_digest_slice(&tx_hash) {
        Ok(m) => m,
        Err(_) => return ERROR_INVALID_SIGNATURE,
    };
    let secp = Secp256k1::verification_only();
    let pubkey_hash = match recover_pubkey_hash(witness_bytes, &msg, &secp) {
        Some(h) => h,
        None => return ERROR_INVALID_SIGNATURE,
    };
    if pubkey_hash.as_ref() != args_bytes.as_ref() {
        return ERROR_INVALID_SIGNATURE;
    }
    0
}

fn verify_guardian_sigs(sigs: &[u8]) -> i8 {
    // Load input AgentRecord to get the registered guardian list and threshold.
    let cell_data = match load_cell_data(0, Source::GroupInput) {
        Ok(d) => d,
        Err(_) => return ERROR_INVALID_RECORD,
    };
    let record = match AgentRecordReader::from_slice(&cell_data) {
        Ok(r) => r,
        Err(_) => return ERROR_INVALID_RECORD,
    };

    let guardians_bytes = record.guardians().raw_data();
    // guardians field is N packed blake160 hashes (20 bytes each).
    if guardians_bytes.len() % 20 != 0 {
        return ERROR_INVALID_RECORD;
    }
    let threshold = u64::from_le_bytes(
        record.guardian_threshold().as_slice().try_into().unwrap_or([0u8; 8]),
    );
    if threshold == 0 {
        return ERROR_GUARDIAN_DISABLED;
    }

    let tx_hash = match load_tx_hash() {
        Ok(h) => h,
        Err(_) => return ERROR_INVALID_WITNESS,
    };
    let msg = match Message::from_digest_slice(&tx_hash) {
        Ok(m) => m,
        Err(_) => return ERROR_INVALID_SIGNATURE,
    };
    let secp = Secp256k1::verification_only();

    // Bitmask tracking which guardian indices have already been counted.
    // Supports up to 64 guardians — more than enough for v1.
    let mut seen: u64 = 0;
    let mut valid_count: u64 = 0;

    let num_sigs = sigs.len() / 98;
    for i in 0..num_sigs {
        let sig_bytes = &sigs[i * 98..(i + 1) * 98];
        let pubkey_hash = match recover_pubkey_hash(sig_bytes, &msg, &secp) {
            Some(h) => h,
            None => continue,
        };

        // Find this pubkey_hash in the guardian list.
        for (idx, guardian) in guardians_bytes.chunks(20).enumerate() {
            if idx >= 64 {
                break; // bitmask only covers 64 slots
            }
            let already_counted = (seen >> idx) & 1 == 1;
            if !already_counted && guardian == pubkey_hash.as_ref() {
                seen |= 1u64 << idx;
                valid_count += 1;
                break;
            }
        }

        if valid_count >= threshold {
            return 0;
        }
    }

    if valid_count >= threshold { 0 } else { ERROR_INSUFFICIENT_GUARDIAN_SIGS }
}
