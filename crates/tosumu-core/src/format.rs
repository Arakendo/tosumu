// On-disk format constants and layout definitions.
//
// Source of truth: DESIGN.md §5. This file enforces those numbers at compile time.

/// Page size in bytes. Fixed at database creation.
pub const PAGE_SIZE: usize = 4096;

/// File magic: first 8 bytes of page 0.
pub const MAGIC: &[u8; 8] = b"TOSUMUv0";

/// Current format version written by this engine.
pub const FORMAT_VERSION: u16 = 1;
/// Oldest engine that can open files we write.
pub const MIN_READER_VERSION: u16 = 1;

// ── Page frame layout (§5.3) ──────────────────────────────────────────────────

pub const NONCE_SIZE: usize = 12;
pub const PAGE_VERSION_OFFSET: usize = NONCE_SIZE;                     // 12
pub const PAGE_VERSION_SIZE: usize = 8;
/// Offset of the plaintext `page_type` byte in the frame header.
pub const PAGE_FRAME_TYPE_OFFSET: usize = NONCE_SIZE + PAGE_VERSION_SIZE; // 20
/// Reserved bytes after `page_type` (pad to 4-byte alignment before ciphertext).
pub const PAGE_FRAME_RESERVED_SIZE: usize = 3;
/// Offset where ciphertext (+ tag) begins.
pub const CIPHERTEXT_OFFSET: usize =
    NONCE_SIZE + PAGE_VERSION_SIZE + 1 + PAGE_FRAME_RESERVED_SIZE;    // 24
pub const TAG_SIZE: usize = 16;
/// Plaintext bytes available inside one page frame.
pub const PAGE_PLAINTEXT_SIZE: usize = PAGE_SIZE - CIPHERTEXT_OFFSET - TAG_SIZE;
// 4096 - 24 - 16 = 4056

// ── Slotted page layout (§5.4) ────────────────────────────────────────────────

/// PageHeader occupies the first 22 bytes of the decrypted page body.
pub const PAGE_HEADER_SIZE: usize = 22;
/// Size of one slot entry: { offset: u16, length: u16 }.
pub const SLOT_SIZE: usize = 4;
/// Available bytes for the slot array + heap combined.
pub const PAGE_BODY_USABLE: usize = PAGE_PLAINTEXT_SIZE - PAGE_HEADER_SIZE; // 4038

/// Maximum live record size (key + value bytes, not including record header).
/// Records larger than this are rejected with InvalidArgument.
pub const RECORD_MAX_KV: usize = PAGE_BODY_USABLE / 2 - 5; // 5 = record overhead

// Page type discriminants.
pub const PAGE_TYPE_LEAF: u8 = 1;
pub const PAGE_TYPE_INTERNAL: u8 = 2;
pub const PAGE_TYPE_OVERFLOW: u8 = 3;
pub const PAGE_TYPE_FREE: u8 = 4;

// Record type bytes (first byte of each record in the heap).
pub const RECORD_LIVE: u8 = 0x01;
pub const RECORD_TOMBSTONE: u8 = 0x02;

// ── File header layout (§5.2) ─────────────────────────────────────────────────

/// Byte length of the plaintext file header (fields before header_mac).
pub const FILE_HEADER_PLAIN_LEN: usize = 104;
pub const FILE_HEADER_MAC_SIZE: usize = 32;
/// Total size of the structured header (magic through header_mac).
pub const FILE_HEADER_SIZE: usize = FILE_HEADER_PLAIN_LEN + FILE_HEADER_MAC_SIZE; // 136

// Offsets within page 0 (all LE integers).
pub const OFF_MAGIC: usize = 0;          // [u8; 8]
pub const OFF_FORMAT_VERSION: usize = 16; // u16
pub const OFF_PAGE_SIZE: usize = 18;      // u16
pub const OFF_MIN_READER_VERSION: usize = 20; // u16
pub const OFF_FLAGS: usize = 22;          // u16  bit0=reserved(1), bit1=has_keyslots
pub const OFF_PAGE_COUNT: usize = 24;     // u64
pub const OFF_FREELIST_HEAD: usize = 32;  // u64
pub const OFF_ROOT_PAGE: usize = 40;      // u64  (B+ tree root, Stage 2)
pub const OFF_WAL_CHECKPOINT_LSN: usize = 48; // u64
pub const OFF_DEK_ID: usize = 56;         // u64
pub const OFF_DEK_KAT: usize = 64;        // [u8; 16]
pub const OFF_KEYSLOT_COUNT: usize = 80;  // u16
pub const OFF_KEYSLOT_REGION_PAGES: usize = 82; // u16
// [84..104] reserved, zero
pub const OFF_HEADER_MAC: usize = 104;    // [u8; 32]
// [136..4096] keyslot region + padding

// ── Keyslot layout (§8.7) ─────────────────────────────────────────────────────

/// One keyslot is 256 bytes. Stage 1 embeds slot 0 at offset FILE_HEADER_SIZE in page 0.
pub const KEYSLOT_SIZE: usize = 256;
pub const KEYSLOT_REGION_OFFSET: usize = FILE_HEADER_SIZE; // 136

// Offsets within one keyslot.
pub const KS_OFF_KIND: usize = 0;         // u8: 0=Empty,1=Sentinel,2=Passphrase,...
pub const KS_OFF_VERSION: usize = 1;      // u8
pub const KS_OFF_FLAGS: usize = 2;        // u16
pub const KS_OFF_CREATED_UNIX: usize = 4; // u32
pub const KS_OFF_DEK_ID: usize = 8;       // u64
pub const KS_OFF_SALT: usize = 16;        // [u8; 16]
pub const KS_OFF_KDF_PARAMS: usize = 32;  // [u8; 32]
pub const KS_OFF_TPM_POLICY: usize = 64;  // [u8; 32]
pub const KS_OFF_WRAP_NONCE: usize = 96;  // [u8; 12]
pub const KS_OFF_WRAPPED_DEK: usize = 108; // [u8; 48]  — first 32 bytes = DEK for Sentinel
pub const KS_OFF_KCV: usize = 156;        // [u8; 32] — AEAD over known-plaintext under KEK
// [188..256] reserved, zero-filled

pub const KEYSLOT_KIND_EMPTY: u8 = 0;
pub const KEYSLOT_KIND_SENTINEL: u8 = 1;
pub const KEYSLOT_KIND_PASSPHRASE: u8 = 2;
pub const KEYSLOT_KIND_RECOVERY_KEY: u8 = 3;

/// Maximum number of keyslots in the keyslot region (stage 4b).
pub const MAX_KEYSLOTS: usize = 8;

// ── Compile-time layout assertions ────────────────────────────────────────────

const _: () = assert!(PAGE_SIZE == 4096);
const _: () = assert!(PAGE_SIZE.is_power_of_two());
const _: () = assert!(PAGE_PLAINTEXT_SIZE == 4056);
const _: () = assert!(FILE_HEADER_SIZE + KEYSLOT_SIZE <= PAGE_SIZE);
const _: () = assert!(FILE_HEADER_SIZE + MAX_KEYSLOTS * KEYSLOT_SIZE <= PAGE_SIZE);
const _: () = assert!(PAGE_HEADER_SIZE + SLOT_SIZE < PAGE_PLAINTEXT_SIZE);

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Read a u16 (LE) from a byte slice at the given offset.
pub fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(buf[offset..offset + 2].try_into().unwrap())
}

/// Read a u64 (LE) from a byte slice at the given offset.
pub fn read_u64(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap())
}

/// Write a u16 (LE) into a byte slice at the given offset.
pub fn write_u16(buf: &mut [u8], offset: usize, v: u16) {
    buf[offset..offset + 2].copy_from_slice(&v.to_le_bytes());
}

/// Write a u64 (LE) into a byte slice at the given offset.
pub fn write_u64(buf: &mut [u8], offset: usize, v: u64) {
    buf[offset..offset + 8].copy_from_slice(&v.to_le_bytes());
}

/// Validate the magic bytes in a page-0 buffer.
pub fn check_magic(buf: &[u8]) -> bool {
    buf.get(OFF_MAGIC..OFF_MAGIC + 8) == Some(&MAGIC[..])
}
