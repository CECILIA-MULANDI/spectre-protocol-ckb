use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;
use molecule::prelude::Byte;
use spectre_types::prelude::{Builder, Entity};
use spectre_types::{AgentRecord, Byte32, Bytes as MolBytes, Uint64};

const MAX_CYCLES: u64 = 10_000_000;

// Path to the compiled agent-type RISC-V binary (relative to tests/ crate root).
const AGENT_TYPE_BIN: &str = "../target/riscv64imac-unknown-none-elf/release/agent-type";

//
// Fixed-size Molecule types (Byte32, Uint64) use new_unchecked — the raw bytes
// are the value with no header. The dynamic vector (MolBytes) uses the builder
// which prepends the 4-byte item-count header automatically.

fn mol_byte32(val: [u8; 32]) -> Byte32 {
    Byte32::new_unchecked(Bytes::copy_from_slice(&val))
}

fn mol_uint64(val: u64) -> Uint64 {
    Uint64::new_unchecked(Bytes::copy_from_slice(&val.to_le_bytes()))
}

fn mol_bytes_vec(data: &[u8]) -> MolBytes {
    MolBytes::new_builder()
        .extend(data.iter().copied().map(Byte::new))
        .build()
}

/// Build a Molecule-encoded AgentRecord as raw bytes ready to store in cell.data.
fn make_record(email_hash: [u8; 32], owner_pubkey: [u8; 33], nonce: u64) -> Bytes {
    AgentRecord::new_builder()
        .email_hash(mol_byte32(email_hash))
        .identity_commitment(mol_byte32([0u8; 32]))
        .owner_pubkey(mol_bytes_vec(&owner_pubkey))
        .timelock_blocks(mol_uint64(2880))
        .nonce(mol_uint64(nonce))
        .build()
        .as_bytes()
}

fn setup() -> (Context, OutPoint, Script) {
    let mut context = Context::default();

    // Deploy always_success as the lock script for all test cells.
    // We are only testing agent-type here, not agent-lock.
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_lock = context
        .build_script(&always_success_out_point, Bytes::new())
        .expect("always_success script");

    // Deploy the agent-type RISC-V binary. context.deploy_cell returns the
    // OutPoint of the cell holding the binary. build_script then creates a
    // Script whose code_hash = blake2b256(binary).
    let agent_type_bin = std::fs::read(AGENT_TYPE_BIN)
        .expect("agent-type binary not found — run `make build` in agent-type/ first");
    let agent_type_out_point = context.deploy_cell(Bytes::from(agent_type_bin));

    (context, agent_type_out_point, always_success_lock)
}

fn make_agent_output(lock: Script, type_script: Script) -> CellOutput {
    CellOutput::default()
        .as_builder()
        .capacity(500u64)
        .lock(lock)
        .type_(Some(type_script).pack())
        .build()
}

/// Registration: no input agent cell, valid AgentRecord in output. Should pass.
///
/// agent-type sees GroupInput = empty → registration branch:
/// only validates that the output parses as a valid AgentRecord.
#[test]
fn test_registration() {
    let (mut context, agent_type_out_point, always_success_lock) = setup();

    let agent_type_script = context
        .build_script(&agent_type_out_point, Bytes::new())
        .expect("agent_type script");

    // A plain funding cell (no agent-type) consumed as input.
    // agent-type does NOT run for this cell — it has no type script.
    let funding_cell = context.create_cell(
        CellOutput::default()
            .as_builder()
            .capacity(1000u64)
            .lock(always_success_lock.clone())
            .build(),
        Bytes::new(),
    );

    let output = make_agent_output(always_success_lock, agent_type_script);
    let record = make_record([1u8; 32], [2u8; 33], 0);

    let tx = TransactionBuilder::default()
        .input(CellInput::new(funding_cell, 0))
        .output(output)
        .output_data(record.pack())
        .build();

    let tx = context.complete_tx(tx);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("registration should succeed");
}

/// Valid rotation: nonce increments by 1, all other fields unchanged. Should pass.
///
/// agent-type sees GroupInput = [old cell], GroupOutput = [new cell].
/// Checks: nonce_out == nonce_in + 1, immutable fields match.
#[test]
fn test_rotation_valid() {
    let (mut context, agent_type_out_point, always_success_lock) = setup();

    let agent_type_script = context
        .build_script(&agent_type_out_point, Bytes::new())
        .expect("agent_type script");

    let old_record = make_record([1u8; 32], [2u8; 33], 0);
    let new_record = make_record([1u8; 32], [3u8; 33], 1); // nonce 0→1, new pubkey

    let cell_output = make_agent_output(always_success_lock, agent_type_script);
    let input_cell = context.create_cell(cell_output.clone(), old_record);

    let tx = TransactionBuilder::default()
        .input(CellInput::new(input_cell, 0))
        .output(cell_output)
        .output_data(new_record.pack())
        .build();

    let tx = context.complete_tx(tx);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("valid rotation should succeed");
}

/// Rotation with nonce unchanged. Should fail (ERROR_INVALID_NONCE = 4).
#[test]
fn test_rotation_nonce_not_incremented() {
    let (mut context, agent_type_out_point, always_success_lock) = setup();

    let agent_type_script = context
        .build_script(&agent_type_out_point, Bytes::new())
        .expect("agent_type script");

    let old_record = make_record([1u8; 32], [2u8; 33], 5);
    let bad_record = make_record([1u8; 32], [3u8; 33], 5); // nonce unchanged — invalid

    let cell_output = make_agent_output(always_success_lock, agent_type_script);
    let input_cell = context.create_cell(cell_output.clone(), old_record);

    let tx = TransactionBuilder::default()
        .input(CellInput::new(input_cell, 0))
        .output(cell_output)
        .output_data(bad_record.pack())
        .build();

    let tx = context.complete_tx(tx);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect_err("should fail: nonce not incremented");
}

/// Rotation that changes email_hash (an immutable field). Should fail
/// (ERROR_IMMUTABLE_FIELD = 5).
#[test]
fn test_rotation_immutable_field_changed() {
    let (mut context, agent_type_out_point, always_success_lock) = setup();

    let agent_type_script = context
        .build_script(&agent_type_out_point, Bytes::new())
        .expect("agent_type script");

    let old_record = make_record([1u8; 32], [2u8; 33], 0);
    let bad_record = make_record([9u8; 32], [2u8; 33], 1); // email_hash changed — invalid

    let cell_output = make_agent_output(always_success_lock, agent_type_script);
    let input_cell = context.create_cell(cell_output.clone(), old_record);

    let tx = TransactionBuilder::default()
        .input(CellInput::new(input_cell, 0))
        .output(cell_output)
        .output_data(bad_record.pack())
        .build();

    let tx = context.complete_tx(tx);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect_err("should fail: email_hash is immutable");
}
