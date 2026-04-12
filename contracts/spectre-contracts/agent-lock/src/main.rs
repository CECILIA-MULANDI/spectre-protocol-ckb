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
use ckb_std::ckb_constants::Source;
use ckb_std::high_level::{load_script, load_tx_hash, load_witness_args};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

// Error codes
// lock.args must be exactly 20 bytes (blake160 pubkey hash)
const ERROR_ARGS_LEN: i8 = 1;
// witness must contain a valid secp256k1 signature + pubkey
const ERROR_INVALID_WITNESS: i8 = 2;
// signature doesn't match the pubkey hash in lock.args
const ERROR_INVALID_SIGNATURE: i8 = 3;

pub fn program_entry() -> i8 {
    // Read lock.args: this is the blake160 hash of the owner's pubkey.
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
    let signature_bytes = &witness_bytes[..65];
    let pubkey_bytes = &witness_bytes[65..];

    // Load the tx hash: this is what the owner signed.
    // It's already a hash so we use it directly as the message.
    let tx_hash = match load_tx_hash() {
        Ok(h) => h,
        Err(_) => return ERROR_INVALID_WITNESS,
    };

    // Verify the secp256k1 signature.
    // signature_bytes layout: [recovery_id (1)][r (32)][s (32)] = 65 bytes
    let recovery_id = match RecoveryId::from_byte(signature_bytes[0]) {
        Some(id) => id,
        None => return ERROR_INVALID_SIGNATURE,
    };
    let sig = match Signature::from_bytes(signature_bytes[1..65].into()) {
        Ok(s) => s,
        Err(_) => return ERROR_INVALID_SIGNATURE,
    };
    // Recover the public key from the signature + message hash.
    // "prehash" means the message is already hashed — don't hash it again.
    let recovered_key = match VerifyingKey::recover_from_prehash(&tx_hash, &sig, recovery_id) {
        Ok(k) => k,
        Err(_) => return ERROR_INVALID_SIGNATURE,
    };

    // blake160(recovered_pubkey) must equal lock.args.
    // blake160 = first 20 bytes of blake2b-256 of the compressed pubkey.
    let encoded = recovered_key.to_encoded_point(true); // true = compressed (33 bytes)

    // blake160 = first 20 bytes of blake2b-256 of the pubkey.

    let mut hasher = Blake2bVar::new(32).unwrap();
    hasher.update(encoded.as_bytes());
    let mut hash_out = [0u8; 32];
    hasher.finalize_variable(&mut hash_out).unwrap();
    let pubkey_hash = &hash_out[..20];

    if pubkey_bytes != encoded.as_bytes() {
        return ERROR_INVALID_SIGNATURE;
    }

    if pubkey_hash != args_bytes.as_ref() {
        return ERROR_INVALID_SIGNATURE;
    }

    0
}
