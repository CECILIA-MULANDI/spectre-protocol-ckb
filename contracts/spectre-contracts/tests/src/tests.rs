use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*, core::DepType};
use ckb_testtool::context::Context;
use molecule::prelude::Byte;
use spectre_types::prelude::{Builder, Entity};
use spectre_types::{AgentRecord, Byte32, Bytes as MolBytes, Uint64};

use blake2::{Blake2bVar, digest::{Update, VariableOutput}};
use secp256k1::{Secp256k1, SecretKey, Message};
use secp256k1::rand::thread_rng;

const MAX_CYCLES: u64 = 10_000_000;

const AGENT_LOCK_BIN: &str = "../target/riscv64imac-unknown-none-elf/release/agent-lock";
const AGENT_TYPE_BIN: &str = "../target/riscv64imac-unknown-none-elf/release/agent-type";
const RECOVERY_LOCK_BIN: &str = "../target/riscv64imac-unknown-none-elf/release/recovery-lock";

// ── Molecule helpers ──────────────────────────────────────────────────────────

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

/// Build a fully-specified AgentRecord with all Phase 3 fields.
///
/// Pass empty slices for guardians / pending_owner_pubkey when not relevant.
fn make_full_record(
    email_hash: [u8; 32],
    owner_pubkey: [u8; 33],
    nonce: u64,
    timelock_blocks: u64,
    guardians: &[u8],
    guardian_threshold: u64,
    pending_owner_pubkey: &[u8],
) -> Bytes {
    AgentRecord::new_builder()
        .email_hash(mol_byte32(email_hash))
        .identity_commitment(mol_byte32([0u8; 32]))
        .owner_pubkey(mol_bytes_vec(&owner_pubkey))
        .timelock_blocks(mol_uint64(timelock_blocks))
        .nonce(mol_uint64(nonce))
        .guardians(mol_bytes_vec(guardians))
        .guardian_threshold(mol_uint64(guardian_threshold))
        .pending_owner_pubkey(mol_bytes_vec(pending_owner_pubkey))
        .build()
        .as_bytes()
}

/// Convenience wrapper: no guardian / pending fields (Phase 1/2 style).
fn make_record(email_hash: [u8; 32], owner_pubkey: [u8; 33], nonce: u64) -> Bytes {
    make_full_record(email_hash, owner_pubkey, nonce, 2880, &[], 0, &[])
}

fn setup() -> (Context, OutPoint, Script) {
    let mut context = Context::default();

    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_lock = context
        .build_script(&always_success_out_point, Bytes::new())
        .expect("always_success script");

    let agent_type_bin = std::fs::read(AGENT_TYPE_BIN)
        .expect("agent-type binary not found — run `make build` first");
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
#[test]
fn test_registration() {
    let (mut context, agent_type_out_point, always_success_lock) = setup();

    let agent_type_script = context
        .build_script(&agent_type_out_point, Bytes::new())
        .expect("agent_type script");

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
    let bad_record = make_record([1u8; 32], [3u8; 33], 5); // nonce unchanged

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

/// Rotation that changes email_hash (immutable). Should fail (ERROR_IMMUTABLE_FIELD = 5).
#[test]
fn test_rotation_immutable_field_changed() {
    let (mut context, agent_type_out_point, always_success_lock) = setup();

    let agent_type_script = context
        .build_script(&agent_type_out_point, Bytes::new())
        .expect("agent_type script");

    let old_record = make_record([1u8; 32], [2u8; 33], 0);
    let bad_record = make_record([9u8; 32], [2u8; 33], 1); // email_hash changed

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

//
// agent-type dispatches on (pending_in.is_empty(), pending_out.is_empty()):
//   (true,  true)  → key rotation
//   (true,  false) → initiate recovery: nonce unchanged, pending_out == 33 bytes
//   (false, true)  → execute/cancel:   nonce + 1
//   (false, false) → invalid

/// Initiate recovery: pending goes from empty → 33 bytes, nonce unchanged. Should pass.
#[test]
fn test_initiate_recovery_valid() {
    let (mut context, agent_type_out_point, always_success_lock) = setup();

    let agent_type_script = context
        .build_script(&agent_type_out_point, Bytes::new())
        .expect("agent_type script");

    // Two guardian pubkey hashes (20 bytes each), threshold = 2.
    let guardians = [7u8; 40];
    let guardian_threshold = 2u64;

    let input_record = make_full_record(
        [1u8; 32],
        [2u8; 33],
        5,
        2880,
        &guardians,
        guardian_threshold,
        &[], // no pending
    );
    // Output: same nonce, pending_owner_pubkey set to a 33-byte candidate key.
    let output_record = make_full_record(
        [1u8; 32],
        [2u8; 33],
        5,
        2880,
        &guardians,
        guardian_threshold,
        &[4u8; 33], // recovery candidate key
    );

    let cell_output = make_agent_output(always_success_lock, agent_type_script);
    let input_cell = context.create_cell(cell_output.clone(), input_record);

    let tx = TransactionBuilder::default()
        .input(CellInput::new(input_cell, 0))
        .output(cell_output)
        .output_data(output_record.pack())
        .build();

    let tx = context.complete_tx(tx);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("initiate recovery should succeed");
}

/// Initiate recovery with nonce incremented. Should fail (ERROR_INVALID_NONCE = 4).
///
/// During initiate, the nonce must stay the same — the clock only advances at execute.
#[test]
fn test_initiate_recovery_nonce_changed() {
    let (mut context, agent_type_out_point, always_success_lock) = setup();

    let agent_type_script = context
        .build_script(&agent_type_out_point, Bytes::new())
        .expect("agent_type script");

    let input_record = make_full_record([1u8; 32], [2u8; 33], 5, 2880, &[7u8; 20], 1, &[]);
    let bad_record = make_full_record(
        [1u8; 32], [2u8; 33], 6, 2880, &[7u8; 20], 1, &[4u8; 33], // nonce bumped — wrong
    );

    let cell_output = make_agent_output(always_success_lock, agent_type_script);
    let input_cell = context.create_cell(cell_output.clone(), input_record);

    let tx = TransactionBuilder::default()
        .input(CellInput::new(input_cell, 0))
        .output(cell_output)
        .output_data(bad_record.pack())
        .build();

    let tx = context.complete_tx(tx);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect_err("should fail: nonce must not change during initiate");
}

/// Initiate recovery with pending_owner_pubkey that is not 33 bytes. Should fail
/// (ERROR_INVALID_RECOVERY = 6).
#[test]
fn test_initiate_recovery_wrong_pending_size() {
    let (mut context, agent_type_out_point, always_success_lock) = setup();

    let agent_type_script = context
        .build_script(&agent_type_out_point, Bytes::new())
        .expect("agent_type script");

    let input_record = make_full_record([1u8; 32], [2u8; 33], 5, 2880, &[7u8; 20], 1, &[]);
    let bad_record = make_full_record(
        [1u8; 32], [2u8; 33], 5, 2880, &[7u8; 20], 1, &[4u8; 20], // 20 bytes, not 33
    );

    let cell_output = make_agent_output(always_success_lock, agent_type_script);
    let input_cell = context.create_cell(cell_output.clone(), input_record);

    let tx = TransactionBuilder::default()
        .input(CellInput::new(input_cell, 0))
        .output(cell_output)
        .output_data(bad_record.pack())
        .build();

    let tx = context.complete_tx(tx);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect_err("should fail: pending_owner_pubkey must be exactly 33 bytes");
}

/// Execute recovery: pending goes from 33 bytes → empty, nonce increments. Should pass.
///
/// This covers both "execute" (new owner takes over) and "cancel" (owner retains key)
/// from agent-type's perspective — both result in pending going to empty with nonce+1.
#[test]
fn test_execute_recovery_valid() {
    let (mut context, agent_type_out_point, always_success_lock) = setup();

    let agent_type_script = context
        .build_script(&agent_type_out_point, Bytes::new())
        .expect("agent_type script");

    // Input: recovery is in progress (pending set).
    let input_record = make_full_record([1u8; 32], [2u8; 33], 5, 2880, &[7u8; 20], 1, &[4u8; 33]);
    // Output: recovery resolved, pending cleared, nonce bumped.
    let output_record = make_full_record(
        [1u8; 32],
        [4u8; 33],
        6,
        2880,
        &[7u8; 20],
        1,
        &[], // new owner, nonce 5→6
    );

    let cell_output = make_agent_output(always_success_lock, agent_type_script);
    let input_cell = context.create_cell(cell_output.clone(), input_record);

    let tx = TransactionBuilder::default()
        .input(CellInput::new(input_cell, 0))
        .output(cell_output)
        .output_data(output_record.pack())
        .build();

    let tx = context.complete_tx(tx);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("execute recovery should succeed");
}

/// Execute recovery with nonce unchanged. Should fail (ERROR_INVALID_NONCE = 4).
#[test]
fn test_execute_recovery_nonce_unchanged() {
    let (mut context, agent_type_out_point, always_success_lock) = setup();

    let agent_type_script = context
        .build_script(&agent_type_out_point, Bytes::new())
        .expect("agent_type script");

    let input_record = make_full_record([1u8; 32], [2u8; 33], 5, 2880, &[7u8; 20], 1, &[4u8; 33]);
    let bad_record = make_full_record(
        [1u8; 32],
        [4u8; 33],
        5,
        2880,
        &[7u8; 20],
        1,
        &[], // nonce unchanged — wrong
    );

    let cell_output = make_agent_output(always_success_lock, agent_type_script);
    let input_cell = context.create_cell(cell_output.clone(), input_record);

    let tx = TransactionBuilder::default()
        .input(CellInput::new(input_cell, 0))
        .output(cell_output)
        .output_data(bad_record.pack())
        .build();

    let tx = context.complete_tx(tx);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect_err("should fail: nonce must increment on execute");
}

/// Build a since value encoding a relative block number.
///
/// CKB since field layout:
///   bit 63    = 1 → relative
///   bits 62-61 = 00 → block number metric
///   bits 55-0  = value
fn relative_block_since(blocks: u64) -> u64 {
    (0b10u64 << 62) | (blocks & 0x00FF_FFFF_FFFF_FFFF)
}

fn setup_recovery_lock() -> (Context, OutPoint) {
    let mut context = Context::default();
    let bin = std::fs::read(RECOVERY_LOCK_BIN)
        .expect("recovery-lock binary not found — run `make build` first");
    let out_point = context.deploy_cell(Bytes::from(bin));
    (context, out_point)
}

/// Timelock satisfied: since encodes a relative block count >= timelock_blocks. Should pass.
///
/// recovery-lock reads since from the input, checks it is relative-block-number format,
/// and compares to timelock_blocks in the AgentRecord. CKB nodes enforce since at
/// consensus; the script enforces it here so a since=0 tx cannot bypass the lock.
#[test]
fn test_recovery_lock_timelock_satisfied() {
    let (mut context, out_point) = setup_recovery_lock();

    // args = blake160(owner_pubkey) = 20 bytes of zeros for this test.
    let args = Bytes::from(vec![0u8; 20]);
    let lock_script = context
        .build_script(&out_point, args)
        .expect("recovery-lock script");

    // timelock_blocks = 100; we will satisfy it with since = exactly 100 blocks.
    let timelock_blocks = 100u64;
    let cell_data = make_full_record([1u8; 32], [2u8; 33], 5, timelock_blocks, &[], 0, &[]);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64)
            .lock(lock_script.clone())
            .build(),
        cell_data,
    );

    // since = relative block 100 (exactly meets the threshold).
    let since = relative_block_since(timelock_blocks);
    let input = CellInput::new(input_out_point, since);

    let output = CellOutput::new_builder()
        .capacity(900u64)
        .lock(lock_script)
        .build();

    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(Bytes::new().pack())
        .build();

    let tx = context.complete_tx(tx);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("timelock satisfied: should pass");
}

/// Timelock not met: since is below timelock_blocks. Should fail (ERROR_TIMELOCK_NOT_MET = 4).
#[test]
fn test_recovery_lock_timelock_not_met() {
    let (mut context, out_point) = setup_recovery_lock();

    let args = Bytes::from(vec![0u8; 20]);
    let lock_script = context
        .build_script(&out_point, args)
        .expect("recovery-lock script");

    let timelock_blocks = 100u64;
    let cell_data = make_full_record([1u8; 32], [2u8; 33], 5, timelock_blocks, &[], 0, &[]);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64)
            .lock(lock_script.clone())
            .build(),
        cell_data,
    );

    // since = only 50 blocks — not enough.
    let since = relative_block_since(50);
    let input = CellInput::new(input_out_point, since);

    let output = CellOutput::new_builder()
        .capacity(900u64)
        .lock(lock_script)
        .build();

    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(Bytes::new().pack())
        .build();

    let tx = context.complete_tx(tx);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect_err("should fail: timelock not met");
}

/// Wrong since format: absolute block number instead of relative. Should fail.
///
/// Absolute since has bit 63 = 0. recovery-lock checks since >> 62 == 0b10.
#[test]
fn test_recovery_lock_wrong_since_format() {
    let (mut context, out_point) = setup_recovery_lock();

    let args = Bytes::from(vec![0u8; 20]);
    let lock_script = context
        .build_script(&out_point, args)
        .expect("recovery-lock script");

    let cell_data = make_full_record([1u8; 32], [2u8; 33], 5, 100, &[], 0, &[]);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64)
            .lock(lock_script.clone())
            .build(),
        cell_data,
    );

    // Absolute block number 100 — bit 63 = 0, so since >> 62 = 0 ≠ 0b10.
    let since: u64 = 100;
    let input = CellInput::new(input_out_point, since);

    let output = CellOutput::new_builder()
        .capacity(900u64)
        .lock(lock_script)
        .build();

    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(Bytes::new().pack())
        .build();

    let tx = context.complete_tx(tx);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect_err("should fail: since must be relative block number");
}

// ── Agent-lock guardian (M-of-N) tests ──────────────────────────────────────

fn blake160(data: &[u8]) -> [u8; 20] {
    let mut hasher = Blake2bVar::new(32).unwrap();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).unwrap();
    let mut result = [0u8; 20];
    result.copy_from_slice(&out[..20]);
    result
}

fn setup_agent_lock() -> (Context, OutPoint, OutPoint) {
    let mut context = Context::default();
    let agent_lock_bin = std::fs::read(AGENT_LOCK_BIN)
        .expect("agent-lock binary not found — run `make build` first");
    let agent_lock_out_point = context.deploy_cell(Bytes::from(agent_lock_bin));
    let agent_type_bin = std::fs::read(AGENT_TYPE_BIN)
        .expect("agent-type binary not found — run `make build` first");
    let agent_type_out_point = context.deploy_cell(Bytes::from(agent_type_bin));
    (context, agent_lock_out_point, agent_type_out_point)
}

/// Build guardian witness: [0x01][sig1 (98)][sig2 (98)]...[sigM (98)]
/// Each sig block: [recovery_id (1)][r+s (64)][compressed_pubkey (33)]
fn build_guardian_witness(tx_hash: &[u8; 32], keys: &[SecretKey]) -> Bytes {
    let secp = Secp256k1::new();
    let msg = Message::from_digest_slice(tx_hash).unwrap();
    let mut witness = vec![0x01u8]; // guardian path marker

    for key in keys {
        let sig = secp.sign_ecdsa_recoverable(&msg, key);
        let (recovery_id, compact) = sig.serialize_compact();
        let pubkey = key.public_key(&secp).serialize(); // 33 bytes compressed

        witness.push(recovery_id.to_i32() as u8);
        witness.extend_from_slice(&compact); // 64 bytes r+s
        witness.extend_from_slice(&pubkey);  // 33 bytes
    }
    Bytes::from(witness)
}

/// 2-of-3 guardian recovery: two valid guardian sigs out of three registered. Should pass.
#[test]
fn test_agent_lock_guardian_2_of_3() {
    let (mut context, agent_lock_out_point, agent_type_out_point) = setup_agent_lock();
    let secp = Secp256k1::new();
    let mut rng = thread_rng();

    // Generate 3 guardian keys.
    let guardian_keys: Vec<SecretKey> = (0..3)
        .map(|_| SecretKey::new(&mut rng))
        .collect();
    let guardian_hashes: Vec<[u8; 20]> = guardian_keys
        .iter()
        .map(|k| blake160(&k.public_key(&secp).serialize()))
        .collect();

    // Owner key for lock.args.
    let owner_key = SecretKey::new(&mut rng);
    let owner_pubkey = owner_key.public_key(&secp).serialize();
    let owner_hash = blake160(&owner_pubkey);

    // Guardians field: 3 packed blake160 hashes = 60 bytes.
    let guardians: Vec<u8> = guardian_hashes.iter().flat_map(|h| h.iter().copied()).collect();

    let cell_data = make_full_record(
        [1u8; 32], owner_pubkey, 5, 2880, &guardians, 2, &[],
    );

    let agent_lock = context
        .build_script(&agent_lock_out_point, Bytes::from(owner_hash.to_vec()))
        .expect("agent-lock script");
    let agent_type = context
        .build_script(&agent_type_out_point, Bytes::new())
        .expect("agent-type script");

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64)
            .lock(agent_lock.clone())
            .type_(Some(agent_type.clone()).pack())
            .build(),
        cell_data,
    );

    // Output: initiate recovery (pending set, nonce unchanged).
    let output_data = make_full_record(
        [1u8; 32], owner_pubkey, 5, 2880, &guardians, 2, &[4u8; 33],
    );

    let tx = TransactionBuilder::default()
        .input(CellInput::new(input_out_point, 0))
        .output(
            CellOutput::new_builder()
                .capacity(900u64)
                .lock(agent_lock.clone())
                .type_(Some(agent_type).pack())
                .build(),
        )
        .output_data(output_data.pack())
        .cell_dep(
            CellDep::new_builder()
                .out_point(agent_lock_out_point)
                .dep_type(DepType::Code)
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(agent_type_out_point)
                .dep_type(DepType::Code)
                .build(),
        )
        .build();

    // Sign with guardians 0 and 1 (2-of-3).
    let tx = context.complete_tx(tx);
    let tx_hash: [u8; 32] = tx.hash().raw_data().to_vec().try_into().unwrap();
    let witness_data = build_guardian_witness(&tx_hash, &[guardian_keys[0], guardian_keys[1]]);

    let witness = WitnessArgs::new_builder()
        .lock(Some(witness_data).pack())
        .build();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness.as_bytes().pack()])
        .build();

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("2-of-3 guardian sigs should pass");
}

/// 1-of-3 when threshold is 2. Should fail (ERROR_INSUFFICIENT_GUARDIAN_SIGS = 6).
#[test]
fn test_agent_lock_guardian_insufficient_sigs() {
    let (mut context, agent_lock_out_point, agent_type_out_point) = setup_agent_lock();
    let secp = Secp256k1::new();
    let mut rng = thread_rng();

    let guardian_keys: Vec<SecretKey> = (0..3)
        .map(|_| SecretKey::new(&mut rng))
        .collect();
    let guardian_hashes: Vec<[u8; 20]> = guardian_keys
        .iter()
        .map(|k| blake160(&k.public_key(&secp).serialize()))
        .collect();

    let owner_key = SecretKey::new(&mut rng);
    let owner_pubkey = owner_key.public_key(&secp).serialize();
    let owner_hash = blake160(&owner_pubkey);

    let guardians: Vec<u8> = guardian_hashes.iter().flat_map(|h| h.iter().copied()).collect();

    let cell_data = make_full_record(
        [1u8; 32], owner_pubkey, 5, 2880, &guardians, 2, &[],
    );

    let agent_lock = context
        .build_script(&agent_lock_out_point, Bytes::from(owner_hash.to_vec()))
        .expect("agent-lock script");
    let agent_type = context
        .build_script(&agent_type_out_point, Bytes::new())
        .expect("agent-type script");

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64)
            .lock(agent_lock.clone())
            .type_(Some(agent_type.clone()).pack())
            .build(),
        cell_data,
    );

    let output_data = make_full_record(
        [1u8; 32], owner_pubkey, 5, 2880, &guardians, 2, &[4u8; 33],
    );

    let tx = TransactionBuilder::default()
        .input(CellInput::new(input_out_point, 0))
        .output(
            CellOutput::new_builder()
                .capacity(900u64)
                .lock(agent_lock.clone())
                .type_(Some(agent_type).pack())
                .build(),
        )
        .output_data(output_data.pack())
        .cell_dep(
            CellDep::new_builder()
                .out_point(agent_lock_out_point)
                .dep_type(DepType::Code)
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(agent_type_out_point)
                .dep_type(DepType::Code)
                .build(),
        )
        .build();

    // Only 1 guardian sig — threshold is 2.
    let tx = context.complete_tx(tx);
    let tx_hash: [u8; 32] = tx.hash().raw_data().to_vec().try_into().unwrap();
    let witness_data = build_guardian_witness(&tx_hash, &[guardian_keys[0]]);

    let witness = WitnessArgs::new_builder()
        .lock(Some(witness_data).pack())
        .build();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness.as_bytes().pack()])
        .build();

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect_err("should fail: only 1 of 2 required guardian sigs");
}

/// Non-guardian key signs. Should fail even if threshold is 1.
#[test]
fn test_agent_lock_guardian_wrong_key() {
    let (mut context, agent_lock_out_point, agent_type_out_point) = setup_agent_lock();
    let secp = Secp256k1::new();
    let mut rng = thread_rng();

    let guardian_key = SecretKey::new(&mut rng);
    let guardian_hash = blake160(&guardian_key.public_key(&secp).serialize());

    let impostor_key = SecretKey::new(&mut rng);

    let owner_key = SecretKey::new(&mut rng);
    let owner_pubkey = owner_key.public_key(&secp).serialize();
    let owner_hash = blake160(&owner_pubkey);

    let cell_data = make_full_record(
        [1u8; 32], owner_pubkey, 5, 2880, &guardian_hash, 1, &[],
    );

    let agent_lock = context
        .build_script(&agent_lock_out_point, Bytes::from(owner_hash.to_vec()))
        .expect("agent-lock script");
    let agent_type = context
        .build_script(&agent_type_out_point, Bytes::new())
        .expect("agent-type script");

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64)
            .lock(agent_lock.clone())
            .type_(Some(agent_type.clone()).pack())
            .build(),
        cell_data,
    );

    let output_data = make_full_record(
        [1u8; 32], owner_pubkey, 5, 2880, &guardian_hash, 1, &[4u8; 33],
    );

    let tx = TransactionBuilder::default()
        .input(CellInput::new(input_out_point, 0))
        .output(
            CellOutput::new_builder()
                .capacity(900u64)
                .lock(agent_lock.clone())
                .type_(Some(agent_type).pack())
                .build(),
        )
        .output_data(output_data.pack())
        .cell_dep(
            CellDep::new_builder()
                .out_point(agent_lock_out_point)
                .dep_type(DepType::Code)
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(agent_type_out_point)
                .dep_type(DepType::Code)
                .build(),
        )
        .build();

    // Sign with impostor key — not in the guardian list.
    let tx = context.complete_tx(tx);
    let tx_hash: [u8; 32] = tx.hash().raw_data().to_vec().try_into().unwrap();
    let witness_data = build_guardian_witness(&tx_hash, &[impostor_key]);

    let witness = WitnessArgs::new_builder()
        .lock(Some(witness_data).pack())
        .build();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness.as_bytes().pack()])
        .build();

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect_err("should fail: signer is not a registered guardian");
}
