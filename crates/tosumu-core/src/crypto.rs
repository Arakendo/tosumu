// Cryptographic operations: key derivation, page AEAD.
//
// Source of truth: DESIGN.md §8.
//
// Key hierarchy:
//   DEK (32-byte OsRng) → HKDF-SHA256 → page_key, header_mac_key, audit_key
//
// Page frame (§5.3):
//   [nonce 12][page_version 8][ciphertext ...][tag 16]
//   AAD = pgno (u64 LE) || page_version (u64 LE)
//
// NOTE: page_type is not included in AAD for MVP+1. The design specifies it
// but page_type lives inside the ciphertext, creating a chicken-and-egg issue.
// Stage 6 may add a plaintext page_type field to the frame to resolve this.

use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use chacha20poly1305::aead::{Aead, Payload};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{Result, TosumError};
use crate::format::{
    PAGE_SIZE, PAGE_PLAINTEXT_SIZE, NONCE_SIZE, TAG_SIZE,
    PAGE_VERSION_OFFSET, PAGE_VERSION_SIZE, CIPHERTEXT_OFFSET,
};

/// Generate a fresh 32-byte DEK from the OS random source.
pub fn generate_dek() -> [u8; 32] {
    let mut dek = [0u8; 32];
    getrandom::getrandom(&mut dek).expect("getrandom failed — OS RNG unavailable");
    dek
}

/// Generate a random 12-byte nonce for page encryption.
pub fn random_nonce() -> [u8; 12] {
    let mut n = [0u8; 12];
    getrandom::getrandom(&mut n).expect("getrandom failed — OS RNG unavailable");
    n
}

/// Derive the three HKDF subkeys from the DEK.
///
/// Returns `(page_key, header_mac_key, audit_key)`.
pub fn derive_subkeys(dek: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(None, dek);

    let mut page_key = [0u8; 32];
    let mut header_mac_key = [0u8; 32];
    let mut audit_key = [0u8; 32];

    hk.expand(b"tosumu/v1/page", &mut page_key)
        .expect("HKDF expand: output length is valid");
    hk.expand(b"tosumu/v1/header-mac", &mut header_mac_key)
        .expect("HKDF expand: output length is valid");
    hk.expand(b"tosumu/v1/audit", &mut audit_key)
        .expect("HKDF expand: output length is valid");

    (page_key, header_mac_key, audit_key)
}

/// Encrypt `plaintext` (PAGE_PLAINTEXT_SIZE bytes) into a full PAGE_SIZE frame.
///
/// Frame layout:
///   [0..12]   nonce (random)
///   [12..20]  page_version (LE u64)
///   [20..4080] ciphertext
///   [4080..4096] auth tag
pub fn encrypt_page(
    page_key: &[u8; 32],
    pgno: u64,
    page_version: u64,
    plaintext: &[u8; PAGE_PLAINTEXT_SIZE],
) -> Result<[u8; PAGE_SIZE]> {
    let nonce = random_nonce();
    let aad = make_aad(pgno, page_version);

    let cipher = ChaCha20Poly1305::new(page_key.into());
    let ciphertext = cipher
        .encrypt(
            nonce.as_slice().into(),
            Payload { msg: plaintext.as_slice(), aad: &aad },
        )
        .map_err(|_| TosumError::EncryptFailed)?;

    // ciphertext from aead crate = plaintext_len + tag
    debug_assert_eq!(ciphertext.len(), PAGE_PLAINTEXT_SIZE + TAG_SIZE);

    let mut frame = [0u8; PAGE_SIZE];
    frame[0..NONCE_SIZE].copy_from_slice(&nonce);
    frame[PAGE_VERSION_OFFSET..PAGE_VERSION_OFFSET + PAGE_VERSION_SIZE]
        .copy_from_slice(&page_version.to_le_bytes());
    frame[CIPHERTEXT_OFFSET..].copy_from_slice(&ciphertext);
    Ok(frame)
}

/// Decrypt a PAGE_SIZE frame. Returns `(plaintext_buf, page_version)`.
pub fn decrypt_page(
    page_key: &[u8; 32],
    pgno: u64,
    frame: &[u8; PAGE_SIZE],
) -> Result<([u8; PAGE_PLAINTEXT_SIZE], u64)> {
    let nonce: [u8; NONCE_SIZE] = frame[0..NONCE_SIZE].try_into().unwrap();
    let page_version = u64::from_le_bytes(
        frame[PAGE_VERSION_OFFSET..PAGE_VERSION_OFFSET + PAGE_VERSION_SIZE]
            .try_into()
            .unwrap(),
    );
    let aad = make_aad(pgno, page_version);
    // ciphertext_with_tag is everything after the plaintext header fields
    let ciphertext_with_tag = &frame[CIPHERTEXT_OFFSET..];

    let cipher = ChaCha20Poly1305::new(page_key.into());
    let plaintext = cipher
        .decrypt(
            nonce.as_slice().into(),
            Payload { msg: ciphertext_with_tag, aad: &aad },
        )
        .map_err(|_| TosumError::AuthFailed { pgno: Some(pgno) })?;

    debug_assert_eq!(plaintext.len(), PAGE_PLAINTEXT_SIZE);
    let mut out = [0u8; PAGE_PLAINTEXT_SIZE];
    out.copy_from_slice(&plaintext);
    Ok((out, page_version))
}

// ── private ───────────────────────────────────────────────────────────────────

fn make_aad(pgno: u64, page_version: u64) -> [u8; 16] {
    let mut aad = [0u8; 16];
    aad[0..8].copy_from_slice(&pgno.to_le_bytes());
    aad[8..16].copy_from_slice(&page_version.to_le_bytes());
    aad
}
