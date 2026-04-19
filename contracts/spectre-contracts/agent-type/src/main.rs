#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
ckb_std::default_alloc!(16384, 1258306, 64);

use ckb_std::ckb_constants::Source;
use ckb_std::high_level::load_cell_data;
use spectre_types::{AgentRecordReader, prelude::Reader as _};

// agent-type: validates AgentRecord state transitions on the agent cell.
//
// Five valid operations (distinguished by pending_owner_pubkey state):
//
//   Registration (GroupInput empty):
//     Accept any parseable AgentRecord in the single output cell.
//
//   Key rotation (pending_in empty, pending_out empty):
//     - nonce increments by 1
//     - email_hash, identity_commitment, timelock_blocks, guardians,
//       guardian_threshold are immutable
//     - owner_pubkey may change (checked by agent-lock)
//
//   Initiate recovery (pending_in empty, pending_out non-empty):
//     - nonce unchanged (the clock starts; rotation happens at execute)
//     - pending_owner_pubkey must be exactly 33 bytes
//     - all immutable fields unchanged
//
//   Execute or Cancel recovery (pending_in non-empty, pending_out empty):
//     - nonce increments by 1
//     - all immutable fields unchanged
//     - whether owner_pubkey changed is the lock script's concern
//
// Authorization is entirely the lock script's job.
// This script only enforces the data rules.

const ERROR_OUTPUT_COUNT: i8 = 1;
const ERROR_INPUT_COUNT: i8 = 2;
const ERROR_INVALID_RECORD: i8 = 3;
const ERROR_INVALID_NONCE: i8 = 4;
const ERROR_IMMUTABLE_FIELD: i8 = 5;
const ERROR_INVALID_RECOVERY: i8 = 6;
const ERROR_IMMUTABLE_GUARDIAN: i8 = 7;

pub fn program_entry() -> i8 {
    // Must be exactly one output cell in this script group.
    let output_data = match load_cell_data(0, Source::GroupOutput) {
        Ok(d) => d,
        Err(_) => return ERROR_OUTPUT_COUNT,
    };
    if load_cell_data(1, Source::GroupOutput).is_ok() {
        return ERROR_OUTPUT_COUNT;
    }

    let output_record = match AgentRecordReader::from_slice(&output_data) {
        Ok(r) => r,
        Err(_) => return ERROR_INVALID_RECORD,
    };

    // GroupInput empty → registration. Output already validated above.
    let input_data = match load_cell_data(0, Source::GroupInput) {
        Ok(d) => d,
        Err(_) => return 0,
    };
    if load_cell_data(1, Source::GroupInput).is_ok() {
        return ERROR_INPUT_COUNT;
    }

    let input_record = match AgentRecordReader::from_slice(&input_data) {
        Ok(r) => r,
        Err(_) => return ERROR_INVALID_RECORD,
    };

    let nonce_in = u64::from_le_bytes(
        input_record
            .nonce()
            .as_slice()
            .try_into()
            .unwrap_or([0u8; 8]),
    );
    let nonce_out = u64::from_le_bytes(
        output_record
            .nonce()
            .as_slice()
            .try_into()
            .unwrap_or([0u8; 8]),
    );

    // Use raw_data() not as_slice(): as_slice() includes the 4-byte Molecule length header,
    // so an empty Bytes field returns [0,0,0,0] and is_empty() would always be false.
    let pending_in = input_record.pending_owner_pubkey().raw_data();
    let pending_out = output_record.pending_owner_pubkey().raw_data();

    match (pending_in.is_empty(), pending_out.is_empty()) {
        (true, true) => {
            // Key rotation: nonce increments, immutable fields unchanged.
            if nonce_out != nonce_in.wrapping_add(1) {
                return ERROR_INVALID_NONCE;
            }
            if input_record.email_hash().as_slice() != output_record.email_hash().as_slice() {
                return ERROR_IMMUTABLE_FIELD;
            }
            if input_record.identity_commitment().as_slice()
                != output_record.identity_commitment().as_slice()
            {
                return ERROR_IMMUTABLE_FIELD;
            }
            if input_record.timelock_blocks().as_slice()
                != output_record.timelock_blocks().as_slice()
            {
                return ERROR_IMMUTABLE_FIELD;
            }
            if input_record.guardians().as_slice() != output_record.guardians().as_slice() {
                return ERROR_IMMUTABLE_GUARDIAN;
            }
            if input_record.guardian_threshold().as_slice()
                != output_record.guardian_threshold().as_slice()
            {
                return ERROR_IMMUTABLE_GUARDIAN;
            }
        }
        (true, false) => {
            /* Initiate recovery */
            if nonce_out != nonce_in {
                return ERROR_INVALID_NONCE;
            }
            if pending_out.len() != 33 {
                return ERROR_INVALID_RECOVERY;
            }
            if input_record.email_hash().as_slice() != output_record.email_hash().as_slice() {
                return ERROR_IMMUTABLE_FIELD;
            }
            if input_record.identity_commitment().as_slice()
                != output_record.identity_commitment().as_slice()
            {
                return ERROR_IMMUTABLE_FIELD;
            }
            if input_record.timelock_blocks().as_slice()
                != output_record.timelock_blocks().as_slice()
            {
                return ERROR_IMMUTABLE_FIELD;
            }
            if input_record.guardians().as_slice() != output_record.guardians().as_slice() {
                return ERROR_IMMUTABLE_GUARDIAN;
            }
            if input_record.guardian_threshold().as_slice()
                != output_record.guardian_threshold().as_slice()
            {
                return ERROR_IMMUTABLE_GUARDIAN;
            }
        }
        (false, true) => {
            /* Execute or Cancel recovery */
            if nonce_out != nonce_in.wrapping_add(1) {
                return ERROR_INVALID_NONCE;
            }
            if input_record.email_hash().as_slice() != output_record.email_hash().as_slice() {
                return ERROR_IMMUTABLE_FIELD;
            }
            if input_record.identity_commitment().as_slice()
                != output_record.identity_commitment().as_slice()
            {
                return ERROR_IMMUTABLE_FIELD;
            }
            if input_record.timelock_blocks().as_slice()
                != output_record.timelock_blocks().as_slice()
            {
                return ERROR_IMMUTABLE_FIELD;
            }
            if input_record.guardians().as_slice() != output_record.guardians().as_slice() {
                return ERROR_IMMUTABLE_GUARDIAN;
            }
            if input_record.guardian_threshold().as_slice()
                != output_record.guardian_threshold().as_slice()
            {
                return ERROR_IMMUTABLE_GUARDIAN;
            }
        }
        (false, false) => return ERROR_INVALID_RECOVERY,
    }

    0
}
