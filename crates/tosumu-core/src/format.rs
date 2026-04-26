// On-disk format constants and layout definitions.
//
// Source of truth: DESIGN.md §5. This file enforces those numbers at compile time.

/// Page size in bytes. Fixed at database creation.
pub const PAGE_SIZE: usize = 4096;

/// File magic: first 8 bytes of page 0. Bytes 8..16 are NUL-reserved padding.
/// The full checked region is `page0[0..MAGIC_LEN]` where [8..16] must be zero.
pub const MAGIC: &[u8; 8] = b"TOSUMUv0";
/// Total magic region length: 8-byte tag + 8 zero bytes = 16 bytes.
pub const MAGIC_LEN: usize = 16;

/// Current format version written by this engine.
pub const FORMAT_VERSION: u16 = 1;
/// Oldest engine that can open files we write.
pub const MIN_READER_VERSION: u16 = 1;

// ── Page frame layout (§5.3) ──────────────────────────────────────────────────

pub const NONCE_SIZE: usize = 12;
pub const PAGE_VERSION_OFFSET: usize = NONCE_SIZE; // 12
pub const PAGE_VERSION_SIZE: usize = 8;
/// Offset of the plaintext `page_type` byte in the frame header.
pub const PAGE_FRAME_TYPE_OFFSET: usize = NONCE_SIZE + PAGE_VERSION_SIZE; // 20
/// Reserved bytes after `page_type` (pad to 4-byte alignment before ciphertext).
pub const PAGE_FRAME_RESERVED_SIZE: usize = 3;
/// Offset where ciphertext (+ tag) begins.
pub const CIPHERTEXT_OFFSET: usize = NONCE_SIZE + PAGE_VERSION_SIZE + 1 + PAGE_FRAME_RESERVED_SIZE; // 24
pub const TAG_SIZE: usize = 16;
/// Plaintext bytes available inside one page frame.
pub const PAGE_PLAINTEXT_SIZE: usize = PAGE_SIZE - CIPHERTEXT_OFFSET - TAG_SIZE;
// 4096 - 24 - 16 = 4056

// ── Slotted page layout (§5.4) ────────────────────────────────────────────────

/// PageHeader occupies the first 22 bytes of the decrypted page body.
pub const PAGE_HEADER_SIZE: usize = 22;
/// Size of one slot entry: { offset: u16, length: u16 }.
pub const SLOT_SIZE: usize = 4;

// Offsets within the decrypted page plaintext (page header fields).
pub const PAGE_OFF_TYPE: usize = 0; // u8:  page type discriminant
pub const PAGE_OFF_FLAGS: usize = 1; // u8:  per-page flags (reserved, zero for now)
pub const PAGE_OFF_SLOT_COUNT: usize = 2; // u16: number of live + tombstone slot entries
pub const PAGE_OFF_FREE_START: usize = 4; // u16: first free byte offset (grows up from header)
pub const PAGE_OFF_FREE_END: usize = 6; // u16: first used heap byte offset (grows down)
                                        // [8..10]  fragmented_bytes u16 — wasted bytes from in-place tombstoning
                                        // [10..14] reserved (two u16 fields, zero)
pub const PAGE_OFF_LEFTMOST: usize = 14; // u64: dual-purpose:
                                         //      leaf  → pgno of next leaf in chain (0 = tail)
                                         //      internal → pgno of leftmost child
                                         // [22]     first byte of the slot array / heap body

/// Available bytes for the slot array + heap combined.
pub const PAGE_BODY_USABLE: usize = PAGE_PLAINTEXT_SIZE - PAGE_HEADER_SIZE; // 4034

/// Maximum live record size (key + value bytes, not including record header).
/// Records larger than this are rejected with InvalidArgument.
/// Accounts for: one slot entry (SLOT_SIZE) + record header bytes (5).
pub const RECORD_MAX_KV: usize = PAGE_BODY_USABLE / 2 - SLOT_SIZE - 5;

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
pub const OFF_MAGIC: usize = 0; // [u8; 16] = 8-byte tag + 8-byte NUL padding
pub const OFF_FORMAT_VERSION: usize = 16; // u16
pub const OFF_PAGE_SIZE: usize = 18; // u16
pub const OFF_MIN_READER_VERSION: usize = 20; // u16
pub const OFF_FLAGS: usize = 22; // u16  bit0=reserved(1), bit1=has_keyslots
pub const OFF_PAGE_COUNT: usize = 24; // u64
pub const OFF_FREELIST_HEAD: usize = 32; // u64
pub const OFF_ROOT_PAGE: usize = 40; // u64  (B+ tree root, Stage 2)
pub const OFF_WAL_CHECKPOINT_LSN: usize = 48; // u64
pub const OFF_DEK_ID: usize = 56; // u64
pub const OFF_DEK_KAT: usize = 64; // [u8; 16]
pub const OFF_KEYSLOT_COUNT: usize = 80; // u16
/// Number of data-pages after page 0 that hold the keyslot region.
/// Format v1 MVP: always 0 — keyslots are embedded in page 0 starting at
/// KEYSLOT_REGION_OFFSET. This field is written as 0 and must be treated as
/// "no external keyslot pages" (not "no keyslots exist"). Future formats may
/// spill keyslots into dedicated overflow pages and increment this counter.
pub const OFF_KEYSLOT_REGION_PAGES: usize = 82; // u16
                                                // [84..104] reserved, zero
pub const OFF_HEADER_MAC: usize = 104; // [u8; 32]
                                       // [136..4096] keyslot region (format v1: up to MAX_KEYSLOTS embedded here)

// ── Keyslot layout (§8.7) ─────────────────────────────────────────────────────

/// One keyslot is 256 bytes.
/// Format v1 MVP: all keyslots are embedded in page 0 starting at
/// KEYSLOT_REGION_OFFSET. Later formats may move them to dedicated pages.
pub const KEYSLOT_SIZE: usize = 256;
pub const KEYSLOT_REGION_OFFSET: usize = FILE_HEADER_SIZE; // 136

// Offsets within one keyslot.
pub const KS_OFF_KIND: usize = 0; // u8: 0=Empty,1=Sentinel,2=Passphrase,...
pub const KS_OFF_VERSION: usize = 1; // u8
pub const KS_OFF_FLAGS: usize = 2; // u16
pub const KS_OFF_CREATED_UNIX: usize = 4; // u32
pub const KS_OFF_DEK_ID: usize = 8; // u64
pub const KS_OFF_SALT: usize = 16; // [u8; 16]
pub const KS_OFF_KDF_PARAMS: usize = 32; // [u8; 32]
pub const KS_OFF_TPM_POLICY: usize = 64; // [u8; 32]
pub const KS_OFF_WRAP_NONCE: usize = 96; // [u8; 12]
pub const KS_OFF_WRAPPED_DEK: usize = 108; // [u8; WRAPPED_DEK_SIZE] — for Sentinel: first DEK_SIZE bytes = plaintext DEK
pub const KS_OFF_KCV: usize = 156; // [u8; 32] — AEAD over known-plaintext under KEK
                                   // [188..256] reserved, zero-filled

/// Raw DEK length in bytes.
pub const DEK_SIZE: usize = 32;
/// AEAD-wrapped DEK length: DEK_SIZE bytes ciphertext + 16-byte Poly1305 tag.
pub const WRAPPED_DEK_SIZE: usize = DEK_SIZE + 16; // 48

pub const KEYSLOT_KIND_EMPTY: u8 = 0;
pub const KEYSLOT_KIND_SENTINEL: u8 = 1;
pub const KEYSLOT_KIND_PASSPHRASE: u8 = 2;
pub const KEYSLOT_KIND_RECOVERY_KEY: u8 = 3;
pub const KEYSLOT_KIND_KEYFILE: u8 = 4;

/// Maximum number of keyslots in the keyslot region (stage 4b).
pub const MAX_KEYSLOTS: usize = 8;

// ── Compile-time layout assertions ────────────────────────────────────────────

const _: () = assert!(PAGE_SIZE == 4096);
const _: () = assert!(PAGE_SIZE.is_power_of_two());
const _: () = assert!(MAGIC_LEN == 16);
const _: () = assert!(OFF_FORMAT_VERSION == MAGIC_LEN);
const _: () = assert!(OFF_HEADER_MAC + FILE_HEADER_MAC_SIZE == FILE_HEADER_SIZE);
const _: () = assert!(OFF_KEYSLOT_COUNT + 2 <= FILE_HEADER_PLAIN_LEN);
const _: () = assert!(OFF_DEK_KAT + 16 <= FILE_HEADER_PLAIN_LEN);
const _: () = assert!(CIPHERTEXT_OFFSET + PAGE_PLAINTEXT_SIZE + TAG_SIZE == PAGE_SIZE);
const _: () = assert!(PAGE_PLAINTEXT_SIZE == 4056);
const _: () = assert!(KS_OFF_WRAPPED_DEK + WRAPPED_DEK_SIZE <= KEYSLOT_SIZE);
const _: () = assert!(KEYSLOT_REGION_OFFSET + KEYSLOT_SIZE <= PAGE_SIZE);
const _: () = assert!(KEYSLOT_REGION_OFFSET + MAX_KEYSLOTS * KEYSLOT_SIZE <= PAGE_SIZE);
const _: () = assert!(FILE_HEADER_SIZE + MAX_KEYSLOTS * KEYSLOT_SIZE <= PAGE_SIZE);
const _: () = assert!(PAGE_HEADER_SIZE + SLOT_SIZE < PAGE_PLAINTEXT_SIZE);

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Read a u16 (LE) from a byte slice at the given offset.
///
/// # Panics
/// Panics if `offset + 2 > buf.len()`. Callers must only use this on
/// fixed, in-bounds offsets from trusted format constants.
pub(crate) fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(buf[offset..offset + 2].try_into().unwrap())
}

/// Read a u64 (LE) from a byte slice at the given offset.
///
/// # Panics
/// Panics if `offset + 8 > buf.len()`. Callers must only use this on
/// fixed, in-bounds offsets from trusted format constants.
pub(crate) fn read_u64(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap())
}

/// Write a u16 (LE) into a byte slice at the given offset.
///
/// # Panics
/// Panics if `offset + 2 > buf.len()`.
pub(crate) fn write_u16(buf: &mut [u8], offset: usize, v: u16) {
    buf[offset..offset + 2].copy_from_slice(&v.to_le_bytes());
}

/// Write a u64 (LE) into a byte slice at the given offset.
///
/// # Panics
/// Panics if `offset + 8 > buf.len()`.
pub(crate) fn write_u64(buf: &mut [u8], offset: usize, v: u64) {
    buf[offset..offset + 8].copy_from_slice(&v.to_le_bytes());
}

/// Validate the magic bytes and zero-padding in a page-0 buffer.
///
/// Checks `page0[0..8] == MAGIC` and `page0[8..16] == [0; 8]`.
pub(crate) fn check_magic(buf: &[u8]) -> bool {
    buf.get(OFF_MAGIC..OFF_MAGIC + 8) == Some(&MAGIC[..])
        && buf.get(OFF_MAGIC + 8..OFF_MAGIC + MAGIC_LEN) == Some(&[0u8; 8][..])
}
