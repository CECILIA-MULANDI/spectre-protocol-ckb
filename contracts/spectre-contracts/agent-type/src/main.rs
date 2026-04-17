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
// Two valid operations:
//
//   Registration (GroupInput is empty:no existing agent cell with this type):
//     Accept any parseable AgentRecord in the single output cell.
//     The owner chose their initial values; we just ensure the data is valid.
//
//   Key rotation (one GroupInput, one GroupOutput):
//     - nonce must increment by exactly 1 (replay protection)
//     - email_hash, identity_commitment, timelock_blocks are immutable
//     - owner_pubkey may change (spending authority is checked by agent-lock)
//
// Authorization is entirely the lock script's job.
// This script only enforces the data rules.

const ERROR_OUTPUT_COUNT: i8 = 1;
const ERROR_INPUT_COUNT: i8 = 2;
const ERROR_INVALID_RECORD: i8 = 3;
const ERROR_INVALID_NONCE: i8 = 4;
const ERROR_IMMUTABLE_FIELD: i8 = 5;

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

    // Check for an input cell with this type script.
    // GroupInput empty → registration. Return early: output already validated above.
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

    // Nonce must increment by exactly 1.
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
    if nonce_out != nonce_in.wrapping_add(1) {
        return ERROR_INVALID_NONCE;
    }

    // These fields are immutable after registration.
    if input_record.email_hash().as_slice() != output_record.email_hash().as_slice() {
        return ERROR_IMMUTABLE_FIELD;
    }
    if input_record.identity_commitment().as_slice()
        != output_record.identity_commitment().as_slice()
    {
        return ERROR_IMMUTABLE_FIELD;
    }
    if input_record.timelock_blocks().as_slice() != output_record.timelock_blocks().as_slice() {
        return ERROR_IMMUTABLE_FIELD;
    }

    0
}
