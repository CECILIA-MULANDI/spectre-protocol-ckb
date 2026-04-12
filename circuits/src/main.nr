use SHA256::sha256_var;
use zkemail::{dkim::RSAPubkey, headers::email_address::get_email_address, Sequence};

global KEY_LIMBS_2048: u32 = 18;

/// Private inputs:
///   - email: raw email address as bytes (hidden from verifier)
/// Public inputs:
///   - email_hash: SHA256 of the email, pre-stored on the Aztec contract
///   - new_public_key: the recovery key(wallet key) to authorize (bound to proof to prevent front-running)
///   - nonce: replay protection -- must match the nonce stored in the Aztec contract
///
/// The circuit hashes the private email and asserts it matches the public email_hash.
/// Since new_public_key is a public input, it's baked into the proof -- any attempt to
/// substitute a different key after proof generation will cause verification to fail.

// cap email to this to have fixed size at compile time
global MAX_EMAIL_HEADER_LENGTH: u32 = 2048;
fn main(
    // --Public inputs
    pubkey: pub RSAPubkey<KEY_LIMBS_2048>,
    email_hash: pub [u8; 32],
    new_public_key: pub Field,
    nonce: pub Field,
    // --Private inputs
    header: BoundedVec<u8, MAX_EMAIL_HEADER_LENGTH>,
    signature: [Field; KEY_LIMBS_2048],
    from_header_sequence: Sequence,
    from_address_sequence: Sequence,
) {
    // 1.verify the DKIM signature
    let _ = pubkey.verify_dkim_signature(header, signature);
    // 2.Extract the FROM address
    let from = comptime { "from".as_bytes() };
    let from_address = get_email_address(header, from_header_sequence, from_address_sequence, from);
    let hashed_email = sha256_var(from_address.storage(), from_address.len() as u32);
    assert(hashed_email == email_hash, "This is not the correct hash");
    assert(new_public_key != 0, "new_public key must be set");
    assert(nonce != 0, "Nonce must be set")
}

// // Tests
// // "user@gmail.com" as ASCII bytes, zero-padded to 32 bytes
// global TEST_EMAIL: [u8; 32] = [
//     0x75, 0x73, 0x65, 0x72, 0x40, 0x67, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0, 0, 0, 0,
//     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
// ];

// // SHA256(TEST_EMAIL) -- precomputed off-chain
// global TEST_EMAIL_HASH: [u8; 32] = [
//     0x7a, 0x7c, 0x45, 0x0c, 0x3c, 0x4b, 0xd0, 0xe2, 0x6a, 0xb4, 0xd7, 0x4d, 0x56, 0xe0, 0xf5, 0x7d,
//     0x7e, 0xaf, 0xc7, 0xdc, 0x3f, 0x07, 0xab, 0x4b, 0x34, 0xe6, 0xbe, 0x8c, 0xfe, 0xb7, 0xb2, 0x40,
// ];

// // Last byte flipped (0x40 -> 0x50) to produce a hash that won't match
// global FAILING_TEST_EMAIL_HASH: [u8; 32] = [
//     0x7a, 0x7c, 0x45, 0x0c, 0x3c, 0x4b, 0xd0, 0xe2, 0x6a, 0xb4, 0xd7, 0x4d, 0x56, 0xe0, 0xf5, 0x7d,
//     0x7e, 0xaf, 0xc7, 0xdc, 0x3f, 0x07, 0xab, 0x4b, 0x34, 0xe6, 0xbe, 0x8c, 0xfe, 0xb7, 0xb2, 0x50,
// ];

// #[test]
// fn test_valid_email() {
//     main(TEST_EMAIL, TEST_EMAIL_HASH, 0)
// }

// #[test(should_fail_with = "This is not the correct hash")]
// fn test_invalid_email() {
//     main(TEST_EMAIL, FAILING_TEST_EMAIL_HASH, 1)
// }
