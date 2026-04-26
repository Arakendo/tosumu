// Cryptographic operations: key derivation, page AEAD.
//
// Source of truth: DESIGN.md §8.
//
// Key hierarchy:
//   DEK (32-byte OsRng) → HKDF-SHA256 → page_key, header_mac_key, audit_key
//
// Page frame (§5.3):
//   [nonce 12][page_version 8][page_type 1][reserved 3][ciphertext ...][tag 16]
//   AAD = pgno (u64 LE) || page_version (u64 LE) || page_type (u8)

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{Result, TosumuError};
use crate::format::{
    CIPHERTEXT_OFFSET, FILE_HEADER_PLAIN_LEN, KEYSLOT_SIZE, NONCE_SIZE, PAGE_FRAME_TYPE_OFFSET,
    PAGE_PLAINTEXT_SIZE, PAGE_SIZE, PAGE_VERSION_OFFSET, PAGE_VERSION_SIZE, TAG_SIZE,
};

/// Generate a fresh 32-byte DEK from the OS random source.
pub fn generate_dek() -> Result<[u8; 32]> {
    let mut dek = [0u8; 32];
    getrandom::getrandom(&mut dek).map_err(|_| TosumuError::RngFailed)?;
    Ok(dek)
}

/// Generate a random 12-byte nonce for page encryption.
pub fn random_nonce() -> Result<[u8; 12]> {
    let mut n = [0u8; 12];
    getrandom::getrandom(&mut n).map_err(|_| TosumuError::RngFailed)?;
    Ok(n)
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
///   [0..12]    nonce (random)
///   [12..20]   page_version (LE u64)
///   [20]       page_type (plaintext, bound as AAD)
///   [21..24]   reserved (zero)
///   [24..4080] ciphertext
///   [4080..4096] auth tag
pub fn encrypt_page(
    page_key: &[u8; 32],
    pgno: u64,
    page_version: u64,
    page_type: u8,
    plaintext: &[u8; PAGE_PLAINTEXT_SIZE],
) -> Result<[u8; PAGE_SIZE]> {
    let nonce = random_nonce()?;
    let aad = make_aad(pgno, page_version, page_type);

    let cipher = ChaCha20Poly1305::new(page_key.into());
    let ciphertext = cipher
        .encrypt(
            nonce.as_slice().into(),
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| TosumuError::EncryptFailed)?;

    if ciphertext.len() != PAGE_PLAINTEXT_SIZE + TAG_SIZE {
        return Err(TosumuError::EncryptFailed);
    }

    let mut frame = [0u8; PAGE_SIZE];
    frame[0..NONCE_SIZE].copy_from_slice(&nonce);
    frame[PAGE_VERSION_OFFSET..PAGE_VERSION_OFFSET + PAGE_VERSION_SIZE]
        .copy_from_slice(&page_version.to_le_bytes());
    frame[PAGE_FRAME_TYPE_OFFSET] = page_type;
    // reserved bytes [21..24] remain zero
    frame[CIPHERTEXT_OFFSET..].copy_from_slice(&ciphertext);
    Ok(frame)
}

/// Decrypt a PAGE_SIZE frame. Returns `(plaintext_buf, page_version)`.
pub fn decrypt_page(
    page_key: &[u8; 32],
    pgno: u64,
    frame: &[u8; PAGE_SIZE],
) -> Result<([u8; PAGE_PLAINTEXT_SIZE], u64)> {
    let nonce: [u8; NONCE_SIZE] =
        frame[0..NONCE_SIZE]
            .try_into()
            .map_err(|_| TosumuError::Corrupt {
                pgno,
                reason: "bad nonce length",
            })?;
    let page_version = u64::from_le_bytes(
        frame[PAGE_VERSION_OFFSET..PAGE_VERSION_OFFSET + PAGE_VERSION_SIZE]
            .try_into()
            .map_err(|_| TosumuError::Corrupt {
                pgno,
                reason: "bad page_version length",
            })?,
    );
    let page_type = frame[PAGE_FRAME_TYPE_OFFSET];
    let aad = make_aad(pgno, page_version, page_type);
    // ciphertext_with_tag is everything after the plaintext header fields
    let ciphertext_with_tag = &frame[CIPHERTEXT_OFFSET..];

    let cipher = ChaCha20Poly1305::new(page_key.into());
    let plaintext = cipher
        .decrypt(
            nonce.as_slice().into(),
            Payload {
                msg: ciphertext_with_tag,
                aad: &aad,
            },
        )
        .map_err(|_| TosumuError::AuthFailed { pgno: Some(pgno) })?;

    if plaintext.len() != PAGE_PLAINTEXT_SIZE {
        return Err(TosumuError::Corrupt {
            pgno,
            reason: "decrypted page has wrong length",
        });
    }
    let mut out = [0u8; PAGE_PLAINTEXT_SIZE];
    out.copy_from_slice(&plaintext);
    Ok((out, page_version))
}

// ── private ───────────────────────────────────────────────────────────────────

fn make_aad(pgno: u64, page_version: u64, page_type: u8) -> [u8; 17] {
    let mut aad = [0u8; 17];
    aad[0..8].copy_from_slice(&pgno.to_le_bytes());
    aad[8..16].copy_from_slice(&page_version.to_le_bytes());
    aad[16] = page_type;
    aad
}

// ── Passphrase / Argon2id KEK derivation (§8.6.1) ────────────────────────────

/// Default Argon2id parameters (OWASP 2024 interactive recommendation).
/// m=65536 KiB (64 MiB), t=3 iterations, p=1 lane.
pub const ARGON2_M_COST: u32 = 65_536;
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 1;

fn read_kdf_u32(kdf_params: &[u8; 32], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&kdf_params[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

/// Derive a 32-byte KEK from a passphrase + 16-byte per-slot salt via Argon2id.
///
/// `kdf_params` encodes [m_cost u32 LE][t_cost u32 LE][p_cost u32 LE][version u32 LE]
/// in the first 16 bytes (matching the keyslot `kdf_params` field).
/// If all zeros, the default parameters are used.
pub fn derive_passphrase_kek(
    passphrase: &str,
    salt: &[u8; 16],
    kdf_params: &[u8; 32],
) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let (m, t, p) = if kdf_params[..16].iter().all(|&b| b == 0) {
        (ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)
    } else {
        let m = read_kdf_u32(kdf_params, 0);
        let t = read_kdf_u32(kdf_params, 4);
        let p = read_kdf_u32(kdf_params, 8);
        (m, t, p)
    };

    let params = Params::new(m, t, p, Some(32))
        .map_err(|_| TosumuError::InvalidArgument("invalid Argon2id parameters"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut kek = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut kek)
        .map_err(|_| TosumuError::InvalidArgument("Argon2id hashing failed"))?;
    Ok(kek)
}

/// Pack the Argon2id parameters into the 32-byte `kdf_params` keyslot field.
pub fn pack_kdf_params(m: u32, t: u32, p: u32) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[0..4].copy_from_slice(&m.to_le_bytes());
    buf[4..8].copy_from_slice(&t.to_le_bytes());
    buf[8..12].copy_from_slice(&p.to_le_bytes());
    buf[12..16].copy_from_slice(&0x13u32.to_le_bytes()); // Argon2 version 0x13
    buf
}

// ── DEK wrap / unwrap (§8.7) ──────────────────────────────────────────────────

/// AAD for DEK wrapping: `"tosumu/v1/wrap" || slot_index (u16 LE) || dek_id (u64 LE) || kind (u8)`
fn wrap_aad(slot_index: u16, dek_id: u64, kind: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(14 + 2 + 8 + 1);
    aad.extend_from_slice(b"tosumu/v1/wrap");
    aad.extend_from_slice(&slot_index.to_le_bytes());
    aad.extend_from_slice(&dek_id.to_le_bytes());
    aad.push(kind);
    aad
}

/// Wrap a 32-byte DEK with the given KEK.
///
/// Returns `(nonce [u8; 12], wrapped [u8; 48])` where `wrapped` = 32-byte ciphertext + 16-byte tag.
pub fn wrap_dek(
    kek: &[u8; 32],
    dek: &[u8; 32],
    slot_index: u16,
    dek_id: u64,
    kind: u8,
) -> Result<([u8; 12], [u8; 48])> {
    let nonce = random_nonce()?;
    let aad = wrap_aad(slot_index, dek_id, kind);
    let cipher = ChaCha20Poly1305::new(kek.into());
    let ct = cipher
        .encrypt(
            nonce.as_slice().into(),
            Payload {
                msg: dek.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| TosumuError::EncryptFailed)?;
    debug_assert_eq!(ct.len(), 48);
    let mut wrapped = [0u8; 48];
    wrapped.copy_from_slice(&ct);
    Ok((nonce, wrapped))
}

/// Unwrap a 32-byte DEK.  Returns `WrongKey` if the AEAD tag fails.
pub fn unwrap_dek(
    kek: &[u8; 32],
    nonce: &[u8; 12],
    wrapped: &[u8; 48],
    slot_index: u16,
    dek_id: u64,
    kind: u8,
) -> Result<[u8; 32]> {
    let aad = wrap_aad(slot_index, dek_id, kind);
    let cipher = ChaCha20Poly1305::new(kek.into());
    let pt = cipher
        .decrypt(
            nonce.as_slice().into(),
            Payload {
                msg: wrapped.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| TosumuError::WrongKey)?;
    debug_assert_eq!(pt.len(), 32);
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&pt);
    Ok(dek)
}

// ── Key check value (KCV) (§8.7) ─────────────────────────────────────────────

/// Known plaintext for KCV: 16 zero bytes.
const KCV_KNOWN_PT: [u8; 16] = [0u8; 16];
/// Fixed nonce for KCV computation (deterministic; nonce reuse is intentional here
/// because the key is the variable — we're using AEAD as a KDF check, not for secrecy).
const KCV_NONCE: [u8; 12] = [0u8; 12];
const KCV_AAD: &[u8] = b"tosumu/v1/kcv";

/// Compute the 32-byte KCV for a KEK.
///
/// KCV = ChaCha20-Poly1305(key=KEK, nonce=0, msg=[0u8;16], aad="tosumu/v1/kcv")
/// Result = 16-byte ciphertext || 16-byte tag = 32 bytes.
pub fn compute_kcv(kek: &[u8; 32]) -> [u8; 32] {
    let cipher = ChaCha20Poly1305::new(kek.into());
    let ct = cipher
        .encrypt(
            KCV_NONCE.as_slice().into(),
            Payload {
                msg: &KCV_KNOWN_PT,
                aad: KCV_AAD,
            },
        )
        .expect("KCV encryption: ChaCha20-Poly1305 over fixed inputs cannot fail");
    debug_assert_eq!(ct.len(), 32);
    let mut kcv = [0u8; 32];
    kcv.copy_from_slice(&ct);
    kcv
}

/// Verify that `kcv` matches the expected KCV for `kek`.
/// Returns `WrongKey` if they do not match.
pub fn verify_kcv(kek: &[u8; 32], kcv: &[u8; 32]) -> Result<()> {
    let cipher = ChaCha20Poly1305::new(kek.into());
    cipher
        .decrypt(
            KCV_NONCE.as_slice().into(),
            Payload {
                msg: kcv.as_slice(),
                aad: KCV_AAD,
            },
        )
        .map_err(|_| TosumuError::WrongKey)?;
    Ok(())
}

// ── Header MAC (§8.5) ─────────────────────────────────────────────────────────

type HmacSha256 = Hmac<Sha256>;

/// Compute the 32-byte HMAC-SHA256 over the header plain region and keyslot region.
///
/// Input: `page0[0..FILE_HEADER_PLAIN_LEN]` || `page0[KEYSLOT_REGION_OFFSET..+keyslot_count*KEYSLOT_SIZE]`
pub fn compute_header_mac(
    header_mac_key: &[u8; 32],
    page0: &[u8; PAGE_SIZE],
    keyslot_count: usize,
) -> [u8; 32] {
    use crate::format::KEYSLOT_REGION_OFFSET;
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(header_mac_key)
        .expect("HMAC: key length is always valid for SHA-256");
    mac.update(&page0[..FILE_HEADER_PLAIN_LEN]);
    let ks_end = KEYSLOT_REGION_OFFSET + keyslot_count * KEYSLOT_SIZE;
    mac.update(&page0[KEYSLOT_REGION_OFFSET..ks_end]);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Verify that the 32-byte header MAC in `page0[OFF_HEADER_MAC]` is correct.
/// Returns `AuthFailed { pgno: None }` if it does not match.
pub fn verify_header_mac(
    header_mac_key: &[u8; 32],
    page0: &[u8; PAGE_SIZE],
    keyslot_count: usize,
    expected_mac: &[u8; 32],
) -> Result<()> {
    use crate::format::KEYSLOT_REGION_OFFSET;
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(header_mac_key)
        .expect("HMAC: key length is always valid for SHA-256");
    mac.update(&page0[..FILE_HEADER_PLAIN_LEN]);
    let ks_end = KEYSLOT_REGION_OFFSET + keyslot_count * KEYSLOT_SIZE;
    mac.update(&page0[KEYSLOT_REGION_OFFSET..ks_end]);
    mac.verify_slice(expected_mac)
        .map_err(|_| TosumuError::AuthFailed { pgno: None })
}

// ── Recovery key (§8.6.2) ────────────────────────────────────────────────────

/// Number of random bytes in a recovery secret (160 bits = 20 bytes).
const RECOVERY_SECRET_BYTES: usize = 20;

/// Generate a random recovery secret and return it as an uppercase Base32 string
/// (32 characters, no padding, grouped 4×8 for readability).
///
/// The raw bytes are used as high-entropy key material; Argon2id is not needed
/// (the entropy already exceeds a passphrase by orders of magnitude).
pub fn generate_recovery_secret() -> String {
    use data_encoding::BASE32_NOPAD;
    let mut secret = [0u8; RECOVERY_SECRET_BYTES];
    getrandom::getrandom(&mut secret).expect("getrandom failed");
    let encoded = BASE32_NOPAD.encode(&secret);
    // Group into 4 blocks of 8 for readability: XXXXXXXX-XXXXXXXX-…
    encoded
        .as_bytes()
        .chunks(8)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

/// Decode a recovery string (with or without dashes) to raw bytes,
/// then derive a 32-byte KEK via HKDF-SHA256.
///
/// High-entropy input → HKDF is sufficient; no Argon2id needed.
pub fn derive_recovery_kek(recovery_str: &str) -> Result<[u8; 32]> {
    use data_encoding::BASE32_NOPAD;
    // Strip dashes and whitespace, uppercase.
    let clean: String = recovery_str
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();

    let raw = BASE32_NOPAD
        .decode(clean.as_bytes())
        .map_err(|_| TosumuError::WrongKey)?;

    if raw.len() != RECOVERY_SECRET_BYTES {
        return Err(TosumuError::WrongKey);
    }

    let hk = Hkdf::<Sha256>::new(None, &raw);
    let mut kek = [0u8; 32];
    hk.expand(b"tosumu/v1/recovery-kek", &mut kek)
        .expect("HKDF expand: output length is valid");
    Ok(kek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{
        KEYSLOT_KIND_PASSPHRASE, KEYSLOT_REGION_OFFSET, OFF_HEADER_MAC, PAGE_VERSION_OFFSET,
    };

    // ── HKDF KAT ─────────────────────────────────────────────────────────────

    #[test]
    fn kat_hkdf_subkeys_are_deterministic_and_distinct() {
        let dek = [0x42u8; 32];
        let (pk1, hk1, ak1) = derive_subkeys(&dek);
        let (pk2, hk2, ak2) = derive_subkeys(&dek);
        assert_eq!(pk1, pk2);
        assert_eq!(hk1, hk2);
        assert_eq!(ak1, ak2);
        // All three subkeys must be distinct
        assert_ne!(pk1, hk1);
        assert_ne!(pk1, ak1);
        assert_ne!(hk1, ak1);
    }

    #[test]
    fn kat_hkdf_known_vector() {
        // Different DEKs must produce different page_keys.
        let (pk_a, _, _) = derive_subkeys(&[0u8; 32]);
        let (pk_b, _, _) = derive_subkeys(&[1u8; 32]);
        assert_ne!(
            pk_a, pk_b,
            "HKDF must produce different outputs for different DEKs"
        );
        // Output must be non-trivial (not all zeros with a zero DEK).
        assert_ne!(
            pk_a, [0u8; 32],
            "HKDF page_key must not be all-zeros for a zero DEK"
        );
    }

    // ── Page AEAD KAT ─────────────────────────────────────────────────────────

    #[test]
    fn kat_aead_roundtrip() {
        use crate::format::PAGE_TYPE_LEAF;
        let dek = [0x11u8; 32];
        let (page_key, _, _) = derive_subkeys(&dek);
        let mut plaintext = [0u8; PAGE_PLAINTEXT_SIZE];
        plaintext[0] = 0xDE;
        plaintext[1] = 0xAD;
        let frame = encrypt_page(&page_key, 42, 7, PAGE_TYPE_LEAF, &plaintext).unwrap();
        let (pt2, version) = decrypt_page(&page_key, 42, &frame).unwrap();
        assert_eq!(pt2, plaintext);
        assert_eq!(version, 7);
    }

    #[test]
    fn kat_aead_wrong_pgno_rejected() {
        use crate::format::PAGE_TYPE_LEAF;
        let dek = [0x22u8; 32];
        let (page_key, _, _) = derive_subkeys(&dek);
        let plaintext = [0u8; PAGE_PLAINTEXT_SIZE];
        let frame = encrypt_page(&page_key, 1, 0, PAGE_TYPE_LEAF, &plaintext).unwrap();
        // Decrypting with a different pgno must fail (AAD mismatch).
        assert!(decrypt_page(&page_key, 2, &frame).is_err());
    }

    #[test]
    fn kat_aead_tampered_nonce_rejected() {
        use crate::format::PAGE_TYPE_LEAF;
        let dek = [0x33u8; 32];
        let (page_key, _, _) = derive_subkeys(&dek);
        let plaintext = [0u8; PAGE_PLAINTEXT_SIZE];
        let mut frame = encrypt_page(&page_key, 1, 0, PAGE_TYPE_LEAF, &plaintext).unwrap();
        frame[0] ^= 0xFF; // flip first nonce byte
        assert!(decrypt_page(&page_key, 1, &frame).is_err());
    }

    #[test]
    fn kat_aead_tampered_page_version_rejected() {
        use crate::format::PAGE_TYPE_LEAF;
        let dek = [0x44u8; 32];
        let (page_key, _, _) = derive_subkeys(&dek);
        let plaintext = [0u8; PAGE_PLAINTEXT_SIZE];
        let mut frame = encrypt_page(&page_key, 1, 5, PAGE_TYPE_LEAF, &plaintext).unwrap();
        // Flip a bit in the page_version field — AAD mismatch must cause auth failure.
        frame[PAGE_VERSION_OFFSET] ^= 0x01;
        assert!(decrypt_page(&page_key, 1, &frame).is_err());
    }

    #[test]
    fn kat_aead_tampered_page_type_rejected() {
        use crate::format::{PAGE_FRAME_TYPE_OFFSET, PAGE_TYPE_INTERNAL, PAGE_TYPE_LEAF};
        let dek = [0x55u8; 32];
        let (page_key, _, _) = derive_subkeys(&dek);
        let plaintext = [0u8; PAGE_PLAINTEXT_SIZE];
        let mut frame = encrypt_page(&page_key, 1, 0, PAGE_TYPE_LEAF, &plaintext).unwrap();
        // Change the plaintext page_type byte in the frame header — AAD mismatch.
        frame[PAGE_FRAME_TYPE_OFFSET] = PAGE_TYPE_INTERNAL;
        assert!(decrypt_page(&page_key, 1, &frame).is_err());
    }

    // ── DEK wrap / unwrap KAT ─────────────────────────────────────────────────

    #[test]
    fn kat_dek_wrap_unwrap_roundtrip() {
        let kek = [0xABu8; 32];
        let dek = [0xCDu8; 32];
        let (nonce, wrapped) = wrap_dek(&kek, &dek, 0, 1, KEYSLOT_KIND_PASSPHRASE).unwrap();
        let recovered = unwrap_dek(&kek, &nonce, &wrapped, 0, 1, KEYSLOT_KIND_PASSPHRASE).unwrap();
        assert_eq!(recovered, dek);
    }

    #[test]
    fn kat_dek_unwrap_wrong_kek_rejected() {
        let kek = [0xABu8; 32];
        let bad_kek = [0xACu8; 32];
        let dek = [0xCDu8; 32];
        let (nonce, wrapped) = wrap_dek(&kek, &dek, 0, 1, KEYSLOT_KIND_PASSPHRASE).unwrap();
        let err =
            unwrap_dek(&bad_kek, &nonce, &wrapped, 0, 1, KEYSLOT_KIND_PASSPHRASE).unwrap_err();
        assert!(matches!(err, crate::error::TosumuError::WrongKey));
    }

    #[test]
    fn kat_dek_unwrap_wrong_slot_index_rejected() {
        let kek = [0x33u8; 32];
        let dek = [0x44u8; 32];
        let (nonce, wrapped) = wrap_dek(&kek, &dek, 0, 1, KEYSLOT_KIND_PASSPHRASE).unwrap();
        // Different slot_index changes the AAD → tag mismatch
        let err = unwrap_dek(&kek, &nonce, &wrapped, 1, 1, KEYSLOT_KIND_PASSPHRASE).unwrap_err();
        assert!(matches!(err, crate::error::TosumuError::WrongKey));
    }

    // ── KCV KAT ───────────────────────────────────────────────────────────────

    #[test]
    fn kat_kcv_verify_correct_kek() {
        let kek = [0x55u8; 32];
        let kcv = compute_kcv(&kek);
        verify_kcv(&kek, &kcv).expect("correct KEK must verify KCV");
    }

    #[test]
    fn kat_kcv_reject_wrong_kek() {
        let kek = [0x55u8; 32];
        let bad_kek = [0x56u8; 32];
        let kcv = compute_kcv(&kek);
        let err = verify_kcv(&bad_kek, &kcv).unwrap_err();
        assert!(matches!(err, crate::error::TosumuError::WrongKey));
    }

    #[test]
    fn kat_kcv_is_deterministic() {
        let kek = [0x77u8; 32];
        assert_eq!(compute_kcv(&kek), compute_kcv(&kek));
    }

    // ── Header MAC KAT ────────────────────────────────────────────────────────

    #[test]
    fn kat_header_mac_roundtrip() {
        let dek = [0x88u8; 32];
        let (_, hmk, _) = derive_subkeys(&dek);
        let mut page0 = [0u8; PAGE_SIZE];
        // Place some sentinel data in header and keyslot region
        page0[0] = 0x54; // 'T'
        page0[KEYSLOT_REGION_OFFSET] = 0x01; // sentinel kind
        let mac = compute_header_mac(&hmk, &page0, 1);
        // Store in page0 at OFF_HEADER_MAC
        page0[OFF_HEADER_MAC..OFF_HEADER_MAC + 32].copy_from_slice(&mac);
        let mut stored = [0u8; 32];
        stored.copy_from_slice(&page0[OFF_HEADER_MAC..OFF_HEADER_MAC + 32]);
        verify_header_mac(&hmk, &page0, 1, &stored).expect("header MAC must verify");
    }

    #[test]
    fn kat_header_mac_tampered_keyslot_rejected() {
        let dek = [0x99u8; 32];
        let (_, hmk, _) = derive_subkeys(&dek);
        let mut page0 = [0u8; PAGE_SIZE];
        let mac = compute_header_mac(&hmk, &page0, 1);
        // Tamper one byte in the keyslot region
        page0[KEYSLOT_REGION_OFFSET + 5] ^= 0xFF;
        let err = verify_header_mac(&hmk, &page0, 1, &mac).unwrap_err();
        assert!(matches!(
            err,
            crate::error::TosumuError::AuthFailed { pgno: None }
        ));
    }

    // ── Argon2id KAT ─────────────────────────────────────────────────────────
    //
    // Use fast params (m=4096 KiB, t=1, p=1) in tests to avoid 64 MiB allocations.
    const TEST_ARGON2_PARAMS: [u8; 32] = {
        let mut p = [0u8; 32];
        let m = 4096u32.to_le_bytes();
        let t = 1u32.to_le_bytes();
        let pa = 1u32.to_le_bytes();
        let v = 0x13u32.to_le_bytes();
        p[0] = m[0];
        p[1] = m[1];
        p[2] = m[2];
        p[3] = m[3];
        p[4] = t[0];
        p[5] = t[1];
        p[6] = t[2];
        p[7] = t[3];
        p[8] = pa[0];
        p[9] = pa[1];
        p[10] = pa[2];
        p[11] = pa[3];
        p[12] = v[0];
        p[13] = v[1];
        p[14] = v[2];
        p[15] = v[3];
        p
    };

    #[test]
    fn kat_argon2id_is_deterministic() {
        let salt = [0xAAu8; 16];
        let kek1 = derive_passphrase_kek("hunter2", &salt, &TEST_ARGON2_PARAMS).unwrap();
        let kek2 = derive_passphrase_kek("hunter2", &salt, &TEST_ARGON2_PARAMS).unwrap();
        assert_eq!(kek1, kek2);
    }

    #[test]
    fn kat_argon2id_different_salt_gives_different_kek() {
        let salt1 = [0x01u8; 16];
        let salt2 = [0x02u8; 16];
        let kek1 = derive_passphrase_kek("same", &salt1, &TEST_ARGON2_PARAMS).unwrap();
        let kek2 = derive_passphrase_kek("same", &salt2, &TEST_ARGON2_PARAMS).unwrap();
        assert_ne!(kek1, kek2);
    }

    // ── Recovery key KATs ────────────────────────────────────────────────────

    #[test]
    fn kat_recovery_key_roundtrip() {
        let secret = generate_recovery_secret();
        // Must be 4 groups of 8 chars separated by dashes = 35 chars total.
        let parts: Vec<&str> = secret.split('-').collect();
        assert_eq!(parts.len(), 4, "expected 4 dash-separated groups");
        assert!(
            parts.iter().all(|p| p.len() == 8),
            "each group must be 8 chars"
        );

        // Derive KEK from the generated secret — must not fail.
        let kek = derive_recovery_kek(&secret).unwrap();
        assert_ne!(kek, [0u8; 32]);
    }

    #[test]
    fn kat_recovery_kek_is_deterministic() {
        // Fixed 20-byte secret encoded as Base32.
        let secret = "AAAAAAAAAAAAAAAA-AAAAAAAAAAAAAAAA"; // 32 Base32 chars = 20 bytes
        let kek1 = derive_recovery_kek(secret).unwrap();
        let kek2 = derive_recovery_kek(secret).unwrap();
        assert_eq!(kek1, kek2);
        assert_ne!(kek1, [0u8; 32]);
    }

    #[test]
    fn kat_recovery_kek_different_secrets_differ() {
        let s1 = "AAAAAAAAAAAAAAAA-AAAAAAAAAAAAAAAA";
        let s2 = "BBBBBBBBBBBBBBBB-BBBBBBBBBBBBBBBB";
        let kek1 = derive_recovery_kek(s1).unwrap();
        let kek2 = derive_recovery_kek(s2).unwrap();
        assert_ne!(kek1, kek2);
    }

    #[test]
    fn kat_recovery_kek_ignores_dashes_and_case() {
        let with_dashes = "AAAAAAAAAAAAAAAA-AAAAAAAAAAAAAAAA";
        let without = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let _lower = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // won't parse — wrong length
        let kek1 = derive_recovery_kek(with_dashes).unwrap();
        let kek2 = derive_recovery_kek(without).unwrap();
        assert_eq!(kek1, kek2, "dashes must be stripped before decoding");
        // lowercase letters should also be accepted
        let lower_nodash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let kek3 = derive_recovery_kek(lower_nodash).unwrap();
        assert_eq!(kek1, kek3);
    }

    #[test]
    fn kat_recovery_kek_bad_base32_returns_wrong_key() {
        assert!(matches!(
            derive_recovery_kek("not-valid-base32!!!"),
            Err(crate::error::TosumuError::WrongKey)
        ));
    }
}
