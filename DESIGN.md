# tosumu — Design Document

**Status:** Draft v0.1
**Project type:** Academic / learning
**Language:** Rust (stable)
**Target:** Single-file, single-process, embedded, page-based, authenticated-encrypted key/value store with an eventual toy SQL layer.

> **Name.** `tosumu` (written `to-su-mu`) is a conlang word meaning *knowledge-organization device* — literally "database." Components: `to` (knowledge / information) + `su` (organized structure) + `mu` (object / device). See §17.
>
> **Published at** https://github.com/Arakendo/tosumu. Dual-licensed MIT OR Apache-2.0. This is a public learning project: the crypto and storage design are documented, but neither has been independently reviewed or audited. Do not use `tosumu` to protect real secrets — see [`SECURITY.md`](SECURITY.md).

---

## 1. Goals and non-goals

### 1.1 Goals

- Learn, hands-on, how real embedded storage engines are built: pages, records, B+ trees, WAL, crash recovery.
- Produce a **small, finishable** engine. Correctness and clarity beat performance.
- Apply **per-page authenticated encryption** (AEAD) as a first-class concern, not a bolt-on.
- Be testable: deterministic, fuzzable, property-checkable.
- Be a single binary + a library crate.

### 1.2 Non-goals

- SQL completeness. No joins, no planner, no optimizer beyond trivial.
- Multi-process access. Single process, single writer.
- Networked / client-server operation.
- Feature parity with SQLite. We are *inspired by* SQLite, not cloning it.
- High performance. We will measure it, but we will not chase it.
- Portability exotica. Little-endian, 64-bit, POSIX-or-Windows file semantics.
- Advanced indexing (FSTs, full-text search, vector/embedding search, fuzzy matching). See §18 for why these are out of scope and how to use specialized tools if you need them.
- **Becoming a relational database.** Tosumu is a KV store with an optional relational layer — not a relational database with a KV implementation detail. PK/FK constraints, row encoding, and schema validation live above `tosumu-core` in separate crates (`tosumu-table`, `tosumu-constraints`). The pager never learns what a "customer" is.

### 1.3 Explicit "out of scope until proven necessary"

- Multiple tables / schemas (Stage 5 only).
- Secondary indexes (Stage 5+).
- Concurrency beyond single writer + multiple readers (Stage 6+, maybe).
- Compression.
- Replication.

---

## 2. Guiding principles

1. **Finishable by a mortal.** Every stage must produce something runnable and testable on its own.
2. **On-disk format is sacred.** The file format is documented before it is coded. Every byte has a reason.
3. **Crypto binds structure.** AEAD AAD must cover anything that would be dangerous to swap, reorder, or roll back.
4. **No silent corruption.** Any integrity failure surfaces as a typed error. Never "just a weird byte."
5. **Types over comments.** Layout is expressed in `#[repr(C)]` structs and enums, not prose.
6. **Tests before cleverness.** Property tests and fuzzers land with the module they test.
7. **Declarative intent, imperative mechanics.** Queries, migrations, validation, and provenance express *what* is intended — as plans, ASTs, and typed declarations. The storage engine, pager, and crypto layer express *how* — pages, fsyncs, and AEAD operations. These layers do not leak into each other. A page does not understand a query. A migration plan does not perform I/O. The line between them is the most important architectural boundary in the system.

---

## 3. Technology choices

| Concern | Choice | Why |
|---|---|---|
| Language | Rust (stable, edition 2021) | Layout control + memory safety + crypto ecosystem. |
| Byte layout | `bytemuck` (primary) or `zerocopy` | Safe zero-copy cast of page bytes to typed headers. |
| Errors | `thiserror` | Typed, non-panicking error surface. |
| AEAD | `chacha20poly1305` (primary), `aes-gcm` (alt) | Audited RustCrypto crates. ChaCha20-Poly1305 chosen by default: constant-time on all CPUs, no AES-NI dependency. |
| RNG | `rand_core::OsRng` | OS CSPRNG for key/nonce salts. |
| KDF | `argon2` | Password → master key. |
| Logging | `tracing` + `tracing-subscriber` | Structured, level-filtered. |
| Testing | `proptest`, built-in `#[test]`, `cargo fuzz` (libFuzzer) | Property + fuzz coverage of decoders. |
| Benches | `criterion` | Only used for "is this obviously terrible?" checks. |
| CLI | `clap` (derive) | Standard, minimal. |

No async. The engine is synchronous. If we ever want async, we wrap at the edges.

---

## 4. Architecture overview

```
┌─────────────────────────────────────────────┐
│                    CLI                      │   bin/tosumu
├─────────────────────────────────────────────┤
│              Query layer (Stage 5)          │   parser, executor
├─────────────────────────────────────────────┤
│                  B+ Tree                    │   btree.rs
├─────────────────────────────────────────────┤
│         Transaction / WAL manager           │   wal.rs, txn.rs
├─────────────────────────────────────────────┤
│                   Pager                     │   pager.rs  (cache, dirty set)
├─────────────────────────────────────────────┤
│            Crypto layer (AEAD)              │   crypto.rs (transparent to pager)
├─────────────────────────────────────────────┤
│              File I/O + Page                │   page.rs, io.rs
└─────────────────────────────────────────────┘
```

Each layer only talks to the one directly below it. The crypto layer sits **between** the pager's cache and the file I/O: cached pages are plaintext; on-disk pages are ciphertext. Page numbers and versions are bound as AAD.

---

## 5. On-disk format

### 5.1 File layout

```
┌──────────────────┐  offset 0
│  File header     │  page 0  (partially plaintext; see §8)
├──────────────────┤
│  Page 1          │
├──────────────────┤
│  Page 2          │
├──────────────────┤
│      ...         │
└──────────────────┘
```

- Page size: **4096 bytes**, fixed at creation, stored in header.
- All integers little-endian.
- All offsets are byte offsets within a page unless stated otherwise.
- Every page after the header is either: leaf, internal, overflow, free, or WAL (WAL lives in a separate file in early stages — see §7).

### 5.2 File header (page 0)

Fixed layout. Plaintext fields are readable without any key so we can refuse to open wrong-version files, and so a user can enumerate which **key protectors** are configured before attempting to unlock.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 16 | `magic` | ASCII `"TOSUMUv0\0......."` — 8 bytes of tag + NUL + 7 reserved bytes, zero-padded |
| 16 | 2 | `format_version` | what this file *is* (see §13) |
| 18 | 2 | `page_size` | 4096 |
| 20 | 2 | `min_reader_version` | lowest engine `format_version` allowed to open this file (see §13.1) |
| 22 | 2 | `flags` | bit 0 = encrypted; bit 1 = has keyslots |
| 24 | 8 | `page_count` | total pages including header |
| 32 | 8 | `freelist_head` | page number or 0 |
| 40 | 8 | `root_page` | B+ tree root (Stage 2) |
| 48 | 8 | `wal_checkpoint_lsn` | last durable LSN |
| 56 | 8 | `dek_id` | monotonic id of the currently-active DEK (for rotation, Stage 4b+) |
| 64 | 16 | `dek_kat` | AEAD of a fixed known-plaintext under the DEK; cheap wrong-DEK detection |
| 80 | 2 | `keyslot_count` | number of protector slots present (0 if unencrypted) |
| 82 | 2 | `keyslot_region_pages` | how many pages after page 0 hold the keyslot region |
| 84 | 20 | reserved | zero-filled |
| 104 | 32 | `header_mac` | HMAC-SHA256 over bytes `0..104` **and** the full keyslot region, using `header_mac_key` |
| 136 | ... | reserved / zero | pads to end of page 0 |

Everything after page 0 and the **keyslot region** uses the page frame in §5.3. The keyslot region (§8.7) is plaintext structured data, not encrypted pages, but it is covered by `header_mac`.

### 5.3 Page frame (encrypted pages)

```
┌─────────────────────────────────────────┐
│ nonce         (12 bytes, plaintext)     │
│ page_version  (8 bytes,  plaintext)     │  ← monotonic per page; also bound as AAD
│ ciphertext    (page_size - 12 - 8 - 16) │
│ auth_tag      (16 bytes)                │
└─────────────────────────────────────────┘
```

- AEAD: ChaCha20-Poly1305.
- **AAD** = `page_number (u64 LE) || page_version (u64 LE) || page_type (u8)`.
- Binding page number prevents an attacker from swapping ciphertext blobs between slots.
- Binding page version prevents rollback of a **single** page to an older valid ciphertext.
- Nonce strategy: **random 96-bit nonce per write**. With Poly1305's 2^32 safe-use limit per key, we're effectively unbounded for an engine at this scale; we still track a `page_version` for per-page rollback protection.

> **Known limitation — consistent multi-page rollback.** Per-page `page_version` does *not* prevent an attacker from rolling back *several* pages to a mutually consistent earlier snapshot. Detecting that requires either a global LSN bound into every page's AAD, a Merkle root stored in the header, or a checkpoint-signed manifest. This is explicitly deferred. Stage 6 or later may introduce a global LSN in the AAD; it is a non-goal for Stages 1–5. Future-us: do not feel clever about `page_version` beyond what it actually does.

> **Nonce strategy — future option.** `random 96-bit` is simple and safe for our write volumes. If operational reasoning becomes annoying (e.g. during crash/WAL replay analysis), the migration target is `random_prefix (64 bits) || monotonic_counter (32 bits)` per key. Documented here so we don't rediscover it at 2am.

When encryption is disabled (`flags bit 0 = 0`), the entire 4096 bytes is the plaintext page body. The nonce/version/tag fields are absent, and a CRC32C in the page header provides integrity only (see §15 Q4). This mode exists for Stages 1–3.

### 5.4 Slotted page (leaf data pages)

Inside the plaintext page body for leaf pages:

```
┌───────────────────────┐  offset 0
│ page header (fixed)   │
├───────────────────────┤
│ slot array (grows →)  │
│        ...            │
│                       │
│        ...            │
│ record heap (← grows) │
└───────────────────────┘  offset page_body_size
```

Page header (fixed, `#[repr(C)]`):

| Size | Field |
|---|---|
| 1 | `page_type` (1=leaf, 2=internal, 3=overflow, 4=free) |
| 1 | `flags` |
| 2 | `slot_count` |
| 2 | `free_start` (end of slot array) |
| 2 | `free_end` (start of heap, growing down) |
| 2 | `fragmented_bytes` (see §5.4.1) |
| 4 | reserved |
| 8 | `rightmost_child` or `next_leaf` depending on type |

#### 5.4.1 Fragmentation and compaction policy

`fragmented_bytes` is the count of bytes inside the record heap that are no longer referenced by any live slot (produced by deletes and in-place shrinks). Compaction rewrites the heap to reclaim this space.

Policy:

- A page is **eligible for compaction** when `fragmented_bytes >= page_body_size / 4`.
- Compaction is triggered **lazily on write**: before an insert/update that would otherwise fail with `OutOfSpace`, the pager tries compacting the target page first. No background sweeper.
- Compaction is a full heap rewrite: copy live records to a scratch buffer in slot order, reset `free_end`, rewrite slots, zero `fragmented_bytes`.
- Stage 1 may **skip `fragmented_bytes` entirely** and recompute live/dead bytes on demand during compaction. Tracking it in the header is a Stage 2+ optimization, not a Stage 1 requirement. (See §12.2.)

#### 5.4.2 Value size cap (Stage 1)

Stage 1 rejects any record where `key_len + value_len + record_overhead > page_body_size / 2` with `InvalidArgument`. This defers overflow pages cleanly to Stage 2 without the record encoder having to care. The cap is relaxed in Stage 2 when overflow chains land.

Slot entry: `{ offset: u16, length: u16 }`.

Record encoding (Stage 1, single table):
- `key_len: varint`
- `value_len: varint`
- `key_bytes`
- `value_bytes`

Records larger than some threshold (e.g. `page_body_size / 4`) spill to overflow pages via a chain. Not implemented until Stage 2.

### 5.5 Internal page (B+ tree, Stage 2)

Same slotted layout, slot payload is `{ separator_key, child_page_no: u64 }`. A dedicated `rightmost_child` lives in the page header.

### 5.6 Free page

A free page's body is a single `next_free: u64`. Linked list rooted at `freelist_head` in the file header.

---

## 6. Pager

### 6.1 Responsibilities

- Allocate / free pages.
- Read a page: decrypt, verify AAD, cache.
- Write a page: bump version, encrypt, enqueue for flush.
- Maintain a bounded in-memory cache of plaintext pages.
- Track dirty pages for the current transaction.
- Hand out **typed views** into cached pages; never raw pointers.

### 6.2 API sketch

```rust
pub struct Pager { /* ... */ }

pub struct PageRef<'a>    { /* &immutable view */ }
pub struct PageRefMut<'a> { /* &mut view, marks dirty on drop */ }

impl Pager {
    pub fn open(path: &Path, key: Option<&Key>) -> Result<Self>;
    pub fn get(&self, pgno: u64) -> Result<PageRef<'_>>;
    pub fn get_mut(&self, pgno: u64) -> Result<PageRefMut<'_>>;
    pub fn allocate(&self, page_type: PageType) -> Result<u64>;
    pub fn free(&self, pgno: u64) -> Result<()>;
    pub fn flush(&self) -> Result<()>;   // called by txn commit
    pub fn close(self) -> Result<()>;
}
```

Interior mutability via `RefCell` / `parking_lot::Mutex` depending on concurrency stage. Single-writer assumption keeps this honest.

> **Risk — borrow-checker fight.** Returning `PageRef<'_>` / `PageRefMut<'_>` tied to `&self` with interior mutability often collapses into lifetime pain once the B+ tree starts holding references into two pages at once (e.g. during a split). **Fallback design if this gets ugly:** switch to a handle-based API where `get` / `get_mut` return an owned `PageHandle(u64, Generation)` and all reads/writes go through short-lived closures:
>
> ```rust
> pager.with_page(pgno, |view| { ... })?;
> pager.with_page_mut(pgno, |view| { ... })?;
> ```
>
> This trades some ergonomics for zero lifetime gymnastics and is the known escape hatch. Decision deferred until Stage 2 actually needs cross-page references.

### 6.3 Cache

- Fixed-size LRU (`N` frames, e.g. 256).
- Plaintext only.
- Dirty pages cannot be evicted until flushed.

---

## 7. Transactions & WAL

### 7.1 Model

- **Single writer**, multiple logical readers (Stage 3+).
- Explicit `begin / commit / rollback`.
- Durability on commit: WAL fsync'd before returning.

### 7.2 WAL format (append-only, separate file `tosumu.wal`)

Each record:

```
┌─────────────┬──────────┬───────────┬────────┐
│ lsn (u64)   │ type (u8)│ payload   │ crc32c │
└─────────────┴──────────┴───────────┴────────┘
```

Record types:
- `Begin { txn_id }`
- `PageWrite { pgno, new_page_version, ciphertext_blob }` — full-page physical logging, Stage 3.
- `Commit { txn_id }`
- `Checkpoint { up_to_lsn }`

Physical logging (full page images) is chosen over logical logging for simplicity and because it composes cleanly with per-page AEAD: the WAL stores encrypted page frames identical to the ones that will land in the main file.

### 7.3 Recovery

On open:
1. Read file header, verify MAC.
2. Scan WAL from `wal_checkpoint_lsn` forward.
3. For every committed transaction, replay `PageWrite` records into the main file.
4. Discard records belonging to uncommitted transactions.
5. Advance checkpoint, truncate WAL.

Torn-write safety: a `PageWrite` is only applied if its CRC and AEAD tag both verify.

---

## 8. Cryptography

### 8.1 Threat model

**In scope:**
- Attacker with read/write access to the database file at rest.
- Attacker attempting page swap, page rollback, page reorder, truncation, or bit-flipping.
- Attacker attempting to detect *whether* a page changed (limited; sizes and access patterns leak — see out of scope).

**Out of scope:**
- Attacker with memory access to the running process.
- Side channels (cache timing, power).
- Traffic analysis of file modification patterns.
- Plaintext recovery from swap / hibernation files.

### 8.2 Key hierarchy (envelope encryption)

tosumu uses standard **envelope encryption**: page data is encrypted with a random per-database **DEK**, and the DEK is wrapped by one or more **KEKs**, each produced by a **protector** (passphrase, recovery key, TPM, …). Unlocking = "a protector releases a KEK, the KEK unwraps the DEK."

```
      protector (passphrase / recovery key / TPM / …)
                         │  produces
                         ▼
                        KEK
                         │  unwraps (AEAD)
                         ▼
                        DEK  ─────┐
                         │       │ HKDF (§8.3)
                 ┌───────┴───────┐
                 ▼                ▼
             page_key       header_mac_key
```

Properties this buys us (all deliberately):

- **Changing a passphrase rewrites one keyslot, not the database.**
- **Recovery = an extra protector**, not a whole parallel crypto scheme.
- **TPM is just another protector**, pluggable behind the same trait.
- **DEK rotation is possible** without page rewrite— sort of. See §8.8 for the honest caveat.

### 8.3 Keys

- **DEK** (`[u8; 32]`): generated from `OsRng` at `init`. Never leaves memory in plaintext. Persisted only as wrapped blobs in keyslots.
- From the DEK, derive two subkeys via HKDF-SHA256 with fixed info strings:
  - `page_key`   = `HKDF(DEK, info = "tosumu/v1/page")`
  - `header_mac_key` = `HKDF(DEK, info = "tosumu/v1/header-mac")`
- Each **protector** produces a 32-byte **KEK** used to AEAD-wrap the DEK into a keyslot.
- All in-memory keys live in `Zeroizing<[u8; 32]>`. Dropped keys are wiped.

### 8.4 Page AEAD

- Algorithm: ChaCha20-Poly1305.
- Key: `page_key` (derived from DEK, see §8.3).
- Nonce: 96-bit random, stored plaintext in the page frame.
- AAD: `pgno || page_version || page_type` (see §5.3).
- On decrypt failure: typed error `CorruptPage { pgno }`. No partial reads.

### 8.5 Header MAC

- The file header and keyslot region are not encrypted (we need `magic`, `format_version`, `page_size`, and protector metadata readable *before* anything is unlocked).
- Integrity via HMAC-SHA256 with `header_mac_key`, covering bytes `0..104` of page 0 **plus every byte of the keyslot region** (§8.7). This closes protector-downgrade / slot-tampering attacks.
- The MAC can only be verified *after* a protector unwraps the DEK, so wrong-protector detection is strong: wrong passphrase → DEK wrap tag fails **or** MAC mismatch → refuse to open.

### 8.6 Protectors

Every unlock path is a `KeyProtector`. Multiple protectors can coexist; any one of them can unlock the database.

```rust
pub trait KeyProtector {
    /// Given on-disk metadata and any user-supplied secret,
    /// derive the 32-byte KEK for this protector.
    fn derive_kek(
        &self,
        meta: &ProtectorMetadata,
        input: &ProtectorInput,
    ) -> Result<Zeroizing<[u8; 32]>>;
}
```

Initial protector types:

| Kind | Stage | Notes |
|---|---|---|
| `Passphrase` | 4a | Argon2id over passphrase + per-slot salt. |
| `RecoveryKey` | 4b | 256-bit random secret, shown to user once at init; encoded as a groups-of-6 Base32 string. |
| `Keyfile` | 4b (optional) | Raw 32 bytes read from a file path. |
| `Tpm` | 4c | Platform-backed; seals KEK to a TPM policy. Feature-flagged, not required to build tosumu. |
| `TpmPlusPin` | 4c | Combines a TPM-sealed secret with a user PIN through Argon2id. |

Protectors live behind a trait object; the storage engine never sees protector-specific fields.

### 8.7 Keyslot region (on-disk)

The keyslot region is a contiguous run of `keyslot_region_pages` pages immediately after page 0. It is a flat array of fixed-size **keyslots**. Non-populated slots are zeroed and marked `Empty`.

One keyslot (256 bytes, exact layout TBD during Stage 4a):

| Size | Field | Notes |
|---|---|---|
| 1 | `kind` | 0=Empty, 1=Passphrase, 2=RecoveryKey, 3=Keyfile, 4=Tpm, 5=TpmPlusPin |
| 1 | `version` | protector format version |
| 2 | `flags` | e.g. "requires PIN", "recovery-only" |
| 4 | `created_unix` | u32 seconds since epoch, for rotation diagnostics |
| 8 | `dek_id` | which DEK generation this slot wraps (§8.8) |
| 16 | `salt` | per-slot salt for KDF-based protectors |
| 32 | `kdf_params` | Argon2id params: m, t, p, version (packed) |
| 32 | `tpm_policy` | opaque to the core crate; interpreted by `TpmProtector` |
| 12 | `wrap_nonce` | ChaCha20-Poly1305 nonce for wrapping the DEK |
| 48 | `wrapped_dek` | 32-byte DEK ciphertext + 16-byte tag |
| 32 | `kek_kcv` | AEAD tag over a fixed known-plaintext under this KEK; enables "is this the right passphrase" without touching the DEK |
| 68 | reserved | zero-filled; accommodates future protector fields without a format bump |

AAD for DEK wrapping: `"tosumu/v1/wrap" || slot_index (u16 LE) || dek_id (u64 LE) || kind (u8)`. This binds each wrapped DEK to its slot and generation so an attacker cannot swap wrapped blobs between slots or replay an old slot from a previous rotation.

#### 8.7.1 Policy metadata

Slot `flags` expresses lightweight local policy, authenticated by `header_mac`:

- `recovery_only` — slot may only unlock if passphrase/TPM slots have failed N times (enforced by the CLI, not cryptographically).
- `require_pin` — TPM slot insists on a PIN.
- `created_by_rotation` — slot was added as part of a KEK rotation and is safe to retire after confirmation.

This is policy, not cryptography. It is documented as such.

### 8.8 Rotation

- **KEK rotation (cheap).** Re-wrap the DEK under a new KEK, write the result into a new keyslot (or overwrite the target slot), update `header_mac`. No page rewrite.
- **DEK rotation (expensive).** Generate a new DEK, bump `dek_id`, re-encrypt every page. Provided as a single `tosumu rekey` operation; runs offline. Stage 4b deliverable only if time permits — otherwise Stage 6.
- Per-page AAD does **not** currently include `dek_id`. A page encrypted under a previous DEK is distinguishable only by AEAD failure under the new DEK. That's adequate for a full-file rekey that runs to completion atomically (via WAL), but it is *not* adequate for incremental/online rekey. Called out so we don't quietly assume otherwise.

### 8.9 Nonce reuse risk

Random 96-bit nonces have a birthday bound around 2^48 encryptions per key before collision probability becomes meaningful. Acceptable for a toy engine. Documented so future-us doesn't re-derive it at 2am.

### 8.10 Known limitations (explicit)

- **Consistent multi-page rollback** is not detected. See §5.3.
- **DEK/KEK split does not protect against a compromised running process.** If malware can read process memory, it has the DEK. Envelope encryption protects *at rest*, not *at runtime*.
- **TPM protector does not imply remote attestation.** Sealing to a TPM policy proves "this machine in this state" locally; it says nothing to a remote verifier. Not a goal.
- **Recovery key secrecy is the user's problem.** If the recovery string is stored next to the database file, the recovery protector adds zero security. Documented in the CLI output at init time.

### 8.11 What is *not* protected

- The *existence* and *size* of the database.
- The number of pages.
- Which pages changed between two snapshots (access pattern leakage).
- The order and timing of writes.
- Anything readable from process memory while the database is open.

These are called out explicitly so the threat model is honest.

---

## 9. Error model

One top-level `Error` enum via `thiserror`. Variants include:

- `Io(std::io::Error)`
- `Corrupt { pgno: u64, reason: &'static str }`
- `AuthFailed { pgno: Option<u64> }`
- `WrongKey`
- `NoProtectorAccepted` — tried every configured protector, none produced a valid DEK
- `ProtectorUnavailable(&'static str)` — e.g. TPM not present on this machine
- `KeyslotTampered { slot: u16 }` — header MAC mismatch localized to keyslot region
- `VersionMismatch { found: u16, expected: u16 }`
- `NewerFormat { found: u16, supported_max: u16 }` — file is from a newer engine; refuse to open
- `MigrationRequired { from: u16, to: u16 }` — returned by `open_read_only` and by `open` when `auto_migrate = false`
- `MigrationFailed { step: &'static str, reason: String }`
- `OutOfSpace`
- `TxnConflict`
- `InvalidArgument(&'static str)`

No `unwrap` / `panic` on user-controlled input paths. Panics are reserved for "the programmer wrote a bug" invariants.

---

## 10. Programmer footguns and API guardrails

A storage engine's correctness is only half the battle. The other half is preventing programmers (including future-you) from misusing the API in ways that create application bugs. This section documents common footguns and the design guardrails that prevent them.

**Design principle:** *Make the safe path shorter than the dangerous path.*

### 10.1 Transaction footguns

| Footgun | Problem | Guardrail |
|---------|---------|-----------|
| **Implicit writes without transaction clarity** | Programmer calls `put()` ten times and assumes they commit together. They don't. Disaster in a cardigan. | Explicit transaction scope: `db.transaction(\|tx\| { tx.put(k1, v1)?; tx.put(k2, v2)?; Ok(()) })?;` Stage 1 can auto-commit individual operations; Stage 3+ requires transactions for multi-operation atomicity. |
| **Forgetting to commit** | Opens transaction, does work, forgets commit, wonders why reality disagrees. | Rollback on drop with debug warning. `impl Drop for Transaction { fn drop(&mut self) { if !self.finished { #[cfg(debug_assertions)] warn!("Transaction dropped without commit"); } } }` |
| **Nested transaction confusion** | Starts transaction inside transaction and expects magic. | **Stage 3 decision:** Either reject nested transactions with `TxnAlreadyOpen` error, or support savepoints explicitly (`tx.savepoint()?`). No ambiguous "sure buddy" behavior. |
| **Long-running transactions** | Holds locks, prevents checkpoints, grows WAL, annoys everyone. | Expose transaction age and dirty-page count in debug API. Stage 6+ may add configurable limits with `TxnTooLong` error. |

### 10.2 Context and lifetime footguns

| Footgun | Problem | Guardrail |
|---------|---------|-----------|
| **Long-lived context / session** | A database handle accumulates cache state, stale reads, open transactions, leaked resources. | Separate types: `Database` (shared engine handle, multi-thread safe), `Session` (short-lived user interaction, single-thread), `Transaction` (scoped mutation). Example: `let mut session = db.session()?; session.transaction(\|tx\| ...)?;` |
| **Thread misuse** | Shares mutable state across threads and expects peace. | Type system enforces safety. `Transaction` is `!Send` if it holds thread-local state. Write access is single-owner by design. |
| **Using disposed/closed handle** | Common in managed ecosystems; handle used after `close()` called. | Rust ownership: `db.close(self)` consumes the handle. Compiler prevents use-after-close. No runtime checks needed. |

### 10.3 Query and API footguns

| Footgun | Problem | Guardrail |
|---------|---------|-----------|
| **Read-your-writes ambiguity** | Does a read inside a transaction see uncommitted writes? Unclear behavior breaks expectations. | **Guaranteed and documented:** Reads inside a transaction always see uncommitted writes from that transaction. Test: `tx.put(k, v1)?; assert_eq!(tx.get(k)?, Some(v1));` |
| **Autocommit surprise** | Some DBs autocommit every statement. Some don't. Programmers learn through pain. | Explicit: Stage 1 operations are auto-committed (no WAL yet). Stage 3+ requires `db.transaction()` for multi-operation atomicity. Single operations can use `db.auto_commit().put(k, v)?` for clarity. |
| **Scan order assumptions** | Stage 1 scan is insertion/page order; Stage 2 scan becomes key order. Silent behavior change breaks users. | Honest API names: `scan_physical()` (Stage 1, page order), `scan_by_key()` (Stage 2+, sorted), `scan_by_insert_order()` if needed. Never let "scan" mean whatever the engine happens to do today. |

### 10.4 Migration footguns

| Footgun | Problem | Guardrail |
|---------|---------|-----------|
| **Auto-migrating on read-only open** | User inspects a file, accidentally mutates it. Tiny horror show. | `open_read_only()` never migrates. Returns `MigrationRequired { from, to }` error if file is old format. Already designed in §13. |
| **Silent destructive migration** | Migrations that lose data or change semantics must not be automatic. | Require explicit `db.migrate()` call. Heavy migrations (§13) use copy-and-swap, preserving `.pre-v{N}.bak` backup. Light migrations may be automatic only if lossless and append-only. |
| **No backup before migration** | User migrates, migration corrupts file, no backup exists. | Heavy migrations (§13) always create `.pre-v{N}.bak` before mutation. Documented in migration output: "Backup saved to data.tsm.pre-v2.bak" |

### 10.5 Encryption and key footguns

| Footgun | Problem | Guardrail |
|---------|---------|-----------|
| **Wrong key treated as corruption** | User types wrong passphrase, gets generic "corrupted database" error. Bad UX. | Separate errors: `WrongKey` (keyslot unlock failed, try again), `AuthFailed { pgno }` (page AEAD failed, actual corruption), `KeyslotTampered` (header MAC mismatch). Already designed in §9. |
| **Recovery key shown once, user ignores it** | Recovery keys displayed once, never recorded. Users become raccoons near reflective foil. | Require confirmation: CLI prompts "Type word 3 and word 7 of the recovery key to continue." Can't proceed without proving they recorded it. |
| **Key rotation misunderstood** | KEK rotation is cheap (rewrites 8 keyslots). DEK rotation is expensive (rewrites entire DB). Programmers mix them up. | Separate commands: `tosumu rekey-kek --old-pass X --new-pass Y` (fast, < 1 sec) and `tosumu rekey-dek` (slow, rewrites all pages). Doc explains cost difference. |

### 10.6 File and system footguns

| Footgun | Problem | Guardrail |
|---------|---------|-----------|
| **Copying DB without WAL** | User copies `data.tsm` but not `data.tsm.wal`, then complains about missing recent writes. | `tosumu backup <src> <dest>` is the blessed path (Stage 3+). Copies both `.tsm` and `.wal` atomically. Warning in `open()` if WAL exists but is older than expected: "WAL file may be stale or from a previous copy." |
| **Opening same DB twice** | Single-writer means locks matter. Two processes open same file = corruption. | Exclusive file lock (POSIX `flock()`, Windows `LockFileEx`) acquired in `Database::open()`. Second open returns `Io(ErrorKind::WouldBlock)` with message "Database is already open by another process." |
| **Editing files externally** | People will hex edit. You invited this with `tosumu hex`, the little chaos menu item. | `tosumu verify` catches tampering (checksum/AEAD failures). Docs say manual edits void reality. Stage 4+ AEAD ensures any byte-level tampering is detected on page load. |

### 10.7 Rust API footguns

| Footgun | Problem | Guardrail |
|---------|---------|-----------|
| **Returning references into cached pages** | API returns `&[u8]` pointing into page cache. Page evicted, reference dangles. Borrow-checker nightmare. | Closure-based API (fallback): `db.with_value(key, \|value\| { ... })?` or copy-out API: `db.get(key)? -> Option<Vec<u8>>`. Stage 1 uses copy-out for simplicity. Stage 5+ may offer zero-copy reads for long-running read transactions. |
| **Panic on malformed input** | Decoder panics when fed corrupted bytes. Violates "no silent corruption" principle. | Every decoder returns `Result<T, Error::Corrupt>`. Panics reserved for internal invariants (`debug_assert!`). Fuzz targets (§11.5) enforce this. |
| **Generic cleverness too early** | Making everything generic before anything works. The deadliest Rust footgun. | Boring concrete structs until Stage 2 or 3. `Page` is `Page`, not `Page<S: Storage, C: Codec>`. Generic APIs introduced only when third use case appears. |

### 10.8 Summary table

Quick reference for API design reviews:

| Footgun category | Core guardrail |
|------------------|----------------|
| Forgot transaction | `db.transaction(\|tx\| ...)` ergonomic API |
| Long-lived context | `Session` / `Transaction` scoped types |
| Scan order assumption | Separate `scan_physical()` vs `scan_by_key()` |
| Copy without WAL | First-class `backup` command |
| Wrong key confusion | Distinct `WrongKey` vs `AuthFailed` errors |
| Auto destructive migration | Explicit `migrate()` only |
| Nested transaction ambiguity | Reject or support savepoints explicitly |
| Returning stale references | Closure API or copy-out; no dangling `&[u8]` |
| External file editing | `verify` command + AEAD detect tampering |
| Opening DB twice | Exclusive file lock, clear error message |

**Review cadence:** Before each stage release, audit new public APIs against this list. If a new API introduces a footgun, either redesign the API or document the sharp edge explicitly with examples.

---

## 11. Testing strategy

Testing is a first-class concern. A storage engine is only as good as the confidence that it won't corrupt data, and confidence comes from systematic, repeatable, adversarial testing. This section is normative: every module ships with its tests, and every stage gate includes test requirements.

### 11.1 Testing philosophy

- **No untested code paths.** If a function can return an error, there's a test that triggers it.
- **Property tests > example tests.** Arbitrary inputs catch edge cases humans don't think of.
- **Fuzz everything that touches bytes.** Decoders, parsers, and crypto boundaries get fuzz targets.
- **Crash safety is not optional.** Stage 3's `CrashFs` harness runs on every commit after WAL lands.
- **Tests document behavior.** A test name like `test_compaction_preserves_slot_order` is a spec.
- **Realistic, not exhaustive.** This is a learning project. We aim for *high confidence*, not formal proof.

### 11.2 Test categories and organization

Tests live in three places:

| Location | What lives there | Run by |
|---|---|---|
| `crates/*/src/**/*.rs` (inline `#[cfg(test)]`) | Unit tests, doc tests, small property tests. | `cargo test` |
| `tests/*.rs` | Integration tests that exercise the public API across module boundaries. | `cargo test` |
| `fuzz/fuzz_targets/*.rs` | `cargo-fuzz` / libFuzzer targets. | `cargo fuzz run <target>` (manual, not CI) |

### 11.3 Unit tests (inline, per-module)

Standard `#[cfg(test)]` modules in each `.rs` file. Cover:

- **Happy paths.** Basic functionality works.
- **Boundary conditions.** Empty inputs, maximum sizes, alignment edges.
- **Error paths.** Every `Result<_, Error>` return has a test that produces `Err`.
- **Documented invariants.** If a comment says "slot offsets must be ascending," there's a test that violates it and expects a specific error.

**Examples by module:**

- `page.rs` unit tests:
  - `test_slotted_page_layout_roundtrip` — write slots, read them back.
  - `test_slot_insert_at_capacity_fails` — page full → `OutOfSpace`.
  - `test_overlapping_slots_rejected` — malformed page → `Corrupt`.
  - `test_fragmentation_tracking` — delete record → `fragmented_bytes` updated correctly.
- `record.rs` unit tests:
  - `test_varint_encode_decode` — round-trip LEB128 for `0, 1, 127, 128, u64::MAX`.
  - `test_record_with_empty_key` — zero-length keys are legal.
  - `test_record_exceeding_page_size_rejected` — size cap enforced.
- `pager.rs` unit tests:
  - `test_allocate_returns_sequential_pages` — first three allocations return `1, 2, 3`.
  - `test_free_page_reused` — allocate, free, allocate → same page number.
  - `test_dirty_page_not_evicted` — LRU can't evict a dirty page before flush.
  - `test_double_free_panics` — internal invariant; debug_assert caught in tests.

### 11.4 Property tests (`proptest`)

Property tests generate hundreds or thousands of random inputs and assert invariants hold. Ship with the module they test (same `#[cfg(test)]` block or in `tests/`).

**Core properties to test:**

| Module | Property | Generator |
|---|---|---|
| `page.rs` | Encode then decode = identity | Arbitrary `Vec<(key, value)>` that fits in a page |
| `page.rs` | Compaction preserves all records | Random sequence of `insert/delete`, then compact |
| `record.rs` | Varint round-trip for all `u64` | `proptest::num::u64::ANY` |
| `btree.rs` | Tree height is `O(log n)` | Arbitrary insert sequence, check `max_depth <= c * log2(record_count)` |
| `btree.rs` | All keys in sorted iterator order | Insert random keys, iterate, assert sorted |
| `btree.rs` | Tree invariants after deletes | Insert N, delete random subset, check child pointers + key ordering |
| `wal.rs` | Replay is idempotent | Write records, replay, replay again → same final state |
| `crypto.rs` | Decrypt(Encrypt(plaintext)) = plaintext | Arbitrary page bodies + random nonces |

**Shrinking is critical.** When a property test fails, `proptest` shrinks the input to a minimal failing case. That's gold for debugging.

**Example skeleton:**

```rust
#[cfg(test)]
mod proptests {
    use proptest::prelude::*;
    
    proptest! {
        #[test]
        fn page_encode_decode_roundtrip(records in arb_record_vec(1..20)) {
            let mut page = Page::new_leaf();
            for (k, v) in &records { page.insert(k, v)?; }
            
            let bytes = page.to_bytes();
            let page2 = Page::from_bytes(&bytes)?;
            
            for (k, v) in records {
                prop_assert_eq!(page2.get(&k)?, Some(v));
            }
        }
    }
}
```

### 11.5 Fuzz targets (`cargo fuzz`)

Fuzzing is continuous property testing with coverage-guided mutation. Targets live in `fuzz/fuzz_targets/`. Each is a small `fn` that takes `&[u8]` and must not panic.

**Required fuzz targets (one per stage):**

- **Stage 1:** `fuzz_page_decode` — feed arbitrary 4 KB blobs to the page decoder. Must return `Ok(page)` or `Err(Corrupt)`, never panic.
- **Stage 2:** `fuzz_btree_operations` — parse a bytestream as a sequence of `Insert(k,v) | Delete(k) | Get(k)` ops. Tree must stay consistent.
- **Stage 3:** `fuzz_wal_replay` — arbitrary WAL file → replay must not panic, only `Err(Corrupt)`.
- **Stage 4:** `fuzz_aead_frame` — feed arbitrary ciphertext blobs to the AEAD unwrap. Must return `Ok` or `AuthFailed`, never panic or leak plaintext.
- **Stage 4:** `fuzz_keyslot_parse` — arbitrary keyslot region bytes. Must not panic.

**Corpus management:** Seed each target with a few valid examples (checked into `fuzz/corpus/<target>/`). After finding a crash, add the minimized input as a regression test.

**CI integration:** Fuzz targets are **not** run in CI (too slow). They run manually before each stage release: `cargo fuzz run <target> -- -max_total_time=300` (5 min per target). Findings block release.

### 11.6 Integration tests (`tests/*.rs`)

Integration tests exercise the public API as a user would. They test cross-module interactions, not implementation details.

**Test file structure:**

```
tests/
├── stage1_storage.rs         # init, put, get, scan, reopen
├── stage2_btree.rs            # inserts/deletes with tree, range scans
├── stage3_transactions.rs     # begin/commit/rollback, crash recovery
├── stage4_encryption.rs       # encrypted DB open/close, protector unlock
├── stage4_keyslots.rs         # multiple protectors, rotation
├── fixtures/
│   ├── v1_unencrypted.tsm     # known-good DB from Stage 1
│   ├── v2_with_btree.tsm      # known-good DB from Stage 2
│   └── v3_encrypted.tsm       # known-good encrypted DB
└── common/
    └── mod.rs                 # shared test utilities
```

**Example tests:**

```rust
// tests/stage1_storage.rs
#[test]
fn test_reopen_preserves_data() {
    let path = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    {
        let db = Database::create(&path).unwrap();
        db.put(b"key1", b"value1").unwrap();
        db.close().unwrap();
    }
    {
        let db = Database::open(&path).unwrap();
        assert_eq!(db.get(b"key1").unwrap(), Some(b"value1".to_vec()));
    }
}

#[test]
fn test_scan_returns_keys_in_insertion_order() {
    // Stage 1 has no B+ tree; scan is page order, which is insertion order
    let db = Database::create_temp().unwrap();
    db.put(b"zebra", b"z").unwrap();
    db.put(b"apple", b"a").unwrap();
    let keys: Vec<_> = db.scan().unwrap().map(|(k,_)| k).collect();
    assert_eq!(keys, vec![b"zebra", b"apple"]);
}
```

### 11.7 Crash simulation (`CrashFs` harness)

**Goal:** Prove that recovery is correct for every possible crash point during a transaction.

**Implementation (Stage 3):** A `CrashFs` struct wraps `std::fs::File` and intercepts `write()`, `flush()`, `sync_all()`. It maintains a log of pending operations and can:

- Truncate a write at byte N (simulates partial write).
- Drop the last M bytes of a region marked durable (simulates fsync lie).
- Reorder queued writes (simulates out-of-order completion).
- Inject a "crash" at an arbitrary point in a test, then reopen the DB and verify consistency.

**Test structure:**

```rust
#[test]
fn test_recovery_after_commit_interrupted() {
    let fs = CrashFs::new();
    let db = Database::open_with_fs(&fs, "test.tsm").unwrap();
    
    db.begin().unwrap();
    db.put(b"k1", b"v1").unwrap();
    
    // Inject crash during commit WAL fsync
    fs.crash_after_next_sync();
    let _ = db.commit(); // may fail
    drop(db);
    
    // Recovery: DB must either have the committed write or not, never partial
    let db2 = Database::open_with_fs(&fs, "test.tsm").unwrap();
    let val = db2.get(b"k1").unwrap();
    assert!(val == Some(b"v1".to_vec()) || val == None);
}
```

**Coverage target:** Crash at every await point in the commit path (10–20 injection sites). All must leave the DB consistent.

### 11.8 Known-answer tests (KATs) — crypto

KATs prevent accidental changes to cryptographic constructions. Each one specifies:

- Fixed inputs (plaintext, key, nonce, AAD).
- Expected ciphertext and auth tag.
- If output changes, the test fails → forces explicit acknowledgment in a commit.

**Required KATs:**

- Page AEAD: one plaintext page → fixed `page_key` → check ciphertext and tag.
- HKDF subkey derivation: fixed DEK → check that `page_key` and `header_mac_key` match known values.
- Argon2id KEK derivation: fixed passphrase + salt → check KEK output.
- DEK wrapping: fixed DEK + KEK → check wrapped blob + tag.
- Header MAC: fixed header bytes + known `header_mac_key` → check HMAC output.

KATs live in `crypto.rs` as unit tests with hardcoded hex constants.

### 11.9 Fixtures and golden files

Golden files are checked-in database files with known contents. They serve two purposes:

1. **Regression:** Load a v1 DB, verify it still opens and returns expected data.
2. **Migration testing:** Start with a `v1_unencrypted.tsm`, run migration, verify output matches `v2_expected.tsm`.

**Fixture naming convention:**

```
tests/fixtures/
├── v1_empty.tsm                # Format v1, no records
├── v1_with_3_records.tsm       # Format v1, 3 known key/value pairs
├── v2_btree_100_keys.tsm       # Format v2, 100 sequential keys
├── v4_encrypted_passphrase.tsm # Format v4, encrypted, passphrase = "test"
└── golden_outputs/
    └── after_v1_to_v2_migration.tsm
```

Fixtures are **small** (< 100 KB each), committed with Git LFS if they grow.

**Test example:**

```rust
#[test]
fn test_open_v1_fixture() {
    let db = Database::open("tests/fixtures/v1_with_3_records.tsm").unwrap();
    assert_eq!(db.get(b"key1").unwrap(), Some(b"val1".to_vec()));
    assert_eq!(db.get(b"key2").unwrap(), Some(b"val2".to_vec()));
    assert_eq!(db.get(b"key3").unwrap(), Some(b"val3".to_vec()));
}
```

### 11.10 Stage-specific acceptance tests

Every stage has a checklist of acceptance tests that must pass before the stage is marked "done." These are integration tests + manual CLI invocations.

**Stage 1 acceptance:**

- `cargo test --workspace` passes (all unit + integration tests).
- `tosumu init test.tsm && tosumu put test.tsm k1 v1 && tosumu get test.tsm k1` returns `v1`.
- `tosumu dump test.tsm` pretty-prints the header and page 1.
- `tosumu verify test.tsm` exits 0.
- Proptest for page encode/decode runs 10,000 cases without failure.
- Fuzz `fuzz_page_decode` for 5 minutes without finding a panic.

**Stage 2 acceptance:**

- Stage 1 tests still pass.
- Insert 10,000 sequential keys, verify tree height ≤ 5.
- Delete 5,000 random keys, verify remaining 5,000 are retrievable.
- Range scan returns keys in sorted order.

**Stage 3 acceptance:**

- All prior tests pass.
- `CrashFs` tests: inject crash at 20 commit-path sites → recovery always consistent.
- WAL replay fuzz target runs 5 min clean.

**Stage 4 acceptance:**

- All prior tests pass.
- Open encrypted DB with wrong passphrase → `WrongKey` (not panic, not partial plaintext).
- KATs for all crypto constructions pass.
- Rotate KEK → old passphrase fails, new passphrase succeeds.
- Add recovery key, delete passphrase slot → recovery key unlocks.

### 11.11 Performance and regression testing

Performance is **not** a primary goal, but catastrophic regressions are worth catching.

**What to track (starting Stage 2):**

- Throughput: inserts/sec for sequential keys (baseline: ~10K/sec on reference hardware).
- Latency: p50/p99 for `get` on a 100K-key DB (baseline: <100μs / <500μs).
- File size: DB with 10K × (32-byte key + 128-byte value) (baseline: <5 MB).

**Tooling:** `criterion` benchmarks in `benches/`. Run manually before releases; commit results to `benches/results/`. No CI gating (too noisy).

**Regression policy:** A 2× slowdown or file-size bloat is a blocker. A 10% change is noted but not a blocker.

### 11.12 Test coverage

**Target: line coverage ≥ 80% in `tosumu-core`.** This is realistic for a solo project without being a chore.

**How:**

- Run `cargo tarpaulin` or `cargo llvm-cov` locally before each stage release.
- Uncovered lines are either:
  - Unreachable (debug assertions, internal panics) — mark with `// coverage:ignore`.
  - Missing tests — add them.

**No CI gating on coverage.** Coverage is a diagnostic, not a gate. Human judgment is required.

### 11.13 What is *not* tested

Honest list of what this testing strategy does not cover:

- **Concurrency bugs** — Stage 1–5 are single-writer; no race-condition testing until Stage 6.
- **Long-running soak tests** — no 72-hour stress tests, no multi-TB database tests.
- **Formal verification** — no proof that the B+ tree implementation is correct. We trust testing + review.
- **Side-channel resistance** — no power analysis, no cache-timing tests. Out of scope per §8.1.
- **Platform-specific behavior** — Windows and Linux CI, but no BSD, no 32-bit, no ARM-specific tests.
- **Adversarial cryptanalysis** — RustCrypto primitives are trusted. Our *composition* is tested, not broken.

This is acceptable for a learning project. Document it so we don't quietly assume otherwise.

---

## 12. Roadmap (stages)

The roadmap is expressed two ways: **MVP increments** (smallest shippable deltas, §12.0) and **stages** (broader phases, §12.1+). Use the MVP framing to decide what to build next; use the stage framing to plan releases.

### 12.0 MVP increments

Each MVP is the smallest possible thing that proves **one new capability works end-to-end**. Every increment ships a runnable binary with tests. No MVP is "internal-only" — if nobody can use it, it doesn't count.

**Rule:** No MVP builds on an unproven foundation. If MVP+N is flaky, fix it before starting MVP+(N+1).

#### MVP 0 — "It stores bytes" *(one afternoon)*

The absolute minimum. Proves the I/O path works, the data round-trips, and the project actually compiles into something useful.

- Single-file store using a flat append-only log (no pages, no format, no nothing).
- In-memory `HashMap<Vec<u8>, Vec<u8>>` rebuilt on open by replaying the log.
- CLI: `tosumu put <path> <k> <v>`, `tosumu get <path> <k>`, `tosumu scan <path>`.
- No durability guarantees beyond `fsync` on close. No crash safety.
- Tests: put/get round-trip, reopen returns same data, empty file opens cleanly.

**Proves:** the project exists. Binary runs. Data survives a clean close.
**Demo:** `tosumu put db.log hello world && tosumu get db.log hello` prints `world`.
**Explicitly not there:** no page format, no B+ tree, no encryption, no crash safety.

#### MVP +1 — "It has a real format" *(Stage 1 storage)*

Replace the append-only log with the real on-disk format from §5: file header, 4 KB pages, slotted layout, freelist.

- File header with magic `TOSUMUv0`, `format_version`, `min_reader_version`.
- Slotted leaf pages (§5.4). Linear scan across all leaf pages for `get`/`scan`.
- Freelist for page reuse after delete.
- CLI: `init`, `put`, `get`, `scan`, `stat`, `delete`.
- Property tests for page encode/decode round-trip.

**Proves:** on-disk format works. Pages are a real concept. Reopen is deterministic.
**Demo:** `tosumu init db.tsm && tosumu put db.tsm k v && tosumu stat db.tsm` shows 1 record, 1 page.
**Explicitly not there:** no B+ tree (linear scan only), no WAL, no encryption.

#### MVP +2 — "It's inspectable" *(Stage 1 debug trio)*

The debug tooling from §12.3. Without it, debugging MVP+3 onward is guesswork.

- `tosumu dump <path> [--page N]` — pretty-print header and page contents.
- `tosumu hex <path> --page N` — raw hex+ASCII dump with annotations.
- `tosumu verify <path>` — walk every page, report anomalies, exit non-zero on any.
- Fuzz target: `fuzz_page_decode` — arbitrary 4 KB blobs must not panic.

**Proves:** "no silent corruption" principle (§2.4) works end-to-end.
**Demo:** Hand-edit a byte in a page with a hex editor → `tosumu verify` reports it.
**Explicitly not there:** no interactive viewer (that's MVP+7).

#### MVP +3 — "It scales past linear scan" *(Stage 2 B+ tree)*

Replace linear scan with a B+ tree index. Enables range scans in sorted order.

- Internal pages, splits, lazy deletes (merge in MVP+6 if needed).
- Overflow pages for large values (records exceeding §5.4.2 cap).
- `scan_by_key()` returns keys in sorted order; `scan_physical()` stays for debugging.
- Property tests: tree height O(log n), sorted iteration, invariants after random insert/delete.
- Fuzz target: `fuzz_btree_operations`.

**Proves:** the engine behaves like a real database for lookups.
**Demo:** Insert 10K random keys, range scan `[k500..k600]` returns 100 sorted results.
**Explicitly not there:** no transactions, no crash safety.

#### MVP +4 — "It survives a crash" *(Stage 3 WAL)*

Transactions and Write-Ahead Log. First real durability guarantee.

- `db.transaction(|tx| { ... })` API (§10.1 footgun guardrail).
- WAL file (`.wal` sidecar) with physical/full-page logging.
- Recovery on open: replay WAL, roll forward committed transactions.
- `CrashFs` harness (§11.7) injects crashes at every commit-path site.
- Fuzz target: `fuzz_wal_replay`.
- CLI: `tosumu backup <src> <dest>` copies `.tsm` + `.wal` atomically (§10.6 footgun).

**Proves:** durability. Power loss during commit leaves DB consistent.
**Demo:** Run `CrashFs` test — inject crash at 20 sites, every recovery is consistent.
**Explicitly not there:** no encryption, no multi-reader concurrency.

#### MVP +5 — "It's encrypted" *(Stage 4a — single protector)*

One protector (passphrase), full crypto stack working end-to-end. This is the biggest single leap in the plan.

- Page AEAD (ChaCha20-Poly1305, §8.2) with AAD binding (§8.4).
- DEK generated at init, HKDF-derived `page_key` and `header_mac_key` (§8.3).
- One keyslot, passphrase protector via Argon2id (§8.6.1).
- Header MAC covers keyslot region (§8.7).
- KATs (§11.8) for AEAD, HKDF, DEK-wrap, header MAC.
- `tosumu verify` extended: check keyslot `kek_kcv` and page AEAD tags.
- Error model: `WrongKey` vs `AuthFailed { pgno }` are distinct (§10.5 footgun).
- Fuzz targets: `fuzz_aead_frame`, `fuzz_keyslot_parse`.

**Proves:** encryption works. Wrong passphrase is distinguishable from corruption.
**Demo:** `tosumu init --encrypt db.tsm` → passphrase prompt → insert data → reopen with wrong passphrase → `WrongKey` error (not panic, not partial plaintext).
**Explicitly not there:** no recovery key, no key rotation, no TPM.

#### MVP +6 — "Key management works" *(Stage 4b — multiple protectors)*

Multiple protectors, recovery key, cheap KEK rotation.

- Up to 8 keyslots. Any one can unlock.
- **RecoveryKey** protector with one-time Base32 display at init (§10.5 footgun: require confirmation).
- Optional **Keyfile** protector.
- CLI: `tosumu protector add|remove|list`.
- `tosumu rekey-kek` (fast — rewraps DEK only).
- `tosumu rekey-dek` (slow — rewrites all pages; may slip to MVP+10).
- Tests: protector-swap attack must fail (§8.7 AAD binding).

**Proves:** real-world key management scenarios work. Lost passphrase doesn't mean lost data.
**Demo:** Add recovery key, delete passphrase slot, unlock with recovery key.
**Explicitly not there:** no TPM, no mobile key storage.

#### MVP +7 — "It's interactively inspectable" *(Stage 2–4 TUI viewer)*

Interactive TUI viewer (§12.4). Can slot in any time after MVP+2, but most valuable after MVP+5 when encrypted DB inspection becomes interesting.

- `tosumu view <path>` — ratatui + crossterm TUI.
- Views: file header, page list, page detail, B+ tree structure, WAL records, verification.
- Encrypted DB views (after MVP+5): protector summary, keyslot detail, per-page auth status.
- Keyboard navigation, colorized output, watch mode, read-only.

**Proves:** the "storage engine autopsy table" aesthetic (§12.4).
**Demo:** `tosumu view db.tsm` → navigate pages → see B+ tree visually → spot corrupt page highlighted red.
**Explicitly not there:** no write operations, no query builder, no remote connections.

#### MVP +8 — "It speaks SQL (toy)" *(Stage 5 query layer)*

Minimal query layer. Proves the engine supports relational-style workloads.

- Parser for `CREATE TABLE`, `INSERT`, `SELECT ... WHERE key = ?`.
- System catalog page: `(rootpage, name)` entries per table.
- Single-column primary key. No joins, no planner, no optimizer.
- CLI: `tosumu sql <path> "SELECT * FROM users WHERE id = 42"`.

**Proves:** the storage engine is a real foundation for query languages.
**Demo:** `CREATE TABLE users (id, name); INSERT INTO users VALUES (1, 'alice'); SELECT * FROM users WHERE id = 1`.
**Explicitly not there:** no joins, no GROUP BY, no aggregates, no transactions over SQL (use library API).

#### MVP +9 — "Multiple readers" *(Stage 6 — MVCC snapshots)*

Multi-reader concurrency without blocking writes.

- MVCC snapshot by LSN (read transactions see a fixed point-in-time view).
- Single writer, multiple concurrent readers.
- Secondary indexes (additional B+ trees mapping `(secondary_key, primary_key)`).
- `VACUUM` command — reclaim space from deleted records.
- Benchmarks vs SQLite on toy workloads (§11.11).

**Proves:** real concurrency works. Read-heavy workloads don't block writers.
**Demo:** 10 reader threads scanning while 1 writer inserts — no contention, no stale errors.
**Explicitly not there:** no multi-writer, no distributed concurrency.

#### MVP +10 — "It runs on mobile" *(Stage 7 — iOS/Android)*

Per §19, mobile support with hardware-backed key storage.

- **MVP +10a:** C FFI layer (`tosumu-ffi`) with Swift/Kotlin bindings.
- **MVP +10b:** iOS wrapper with `IosKeychainProtector` (Secure Enclave).
- **MVP +10c:** Android wrapper with `AndroidKeystoreProtector` (Keystore API).

**Proves:** the engine is portable to constrained platforms with hardware crypto.
**Demo:** iOS demo app reads/writes encrypted tosumu DB with biometric unlock.
**Explicitly not there:** no iCloud sync, no cross-device replication, no web assembly target.

#### MVP increment summary table

| MVP | Ships | Proves | Maps to stage |
|-----|-------|--------|---------------|
| 0 | Append-only log, in-memory index | I/O works, binary runs | pre-Stage 1 |
| +1 | Slotted pages, file header, freelist | On-disk format works | Stage 1 storage |
| +2 | `dump` / `hex` / `verify`, fuzz page decode | No silent corruption | Stage 1 debug |
| +3 | B+ tree, range scans, overflow pages | Real DB lookups | Stage 2 |
| +4 | Transactions, WAL, `CrashFs` | Durability | Stage 3 |
| +5 | Passphrase-encrypted DB, KATs | Crypto works end-to-end | Stage 4a |
| +6 | Multiple protectors, recovery key, KEK rotation | Key management works | Stage 4b |
| +7 | TUI viewer (`tosumu view`) | Interactive inspection | Stage 2–4 crosscut |
| +8 | Toy SQL (`CREATE TABLE`, `SELECT`) | Real query foundation | Stage 5 |
| +9 | MVCC readers, secondary indexes, `VACUUM` | Concurrency | Stage 6 |
| +10 | iOS/Android FFI, Keychain/Keystore | Mobile portability | Stage 7 |

**How to use this table:**

- Pick the next MVP you haven't finished. Don't skip.
- If an MVP slips, split it further (e.g., MVP+4a = WAL write, MVP+4b = WAL replay, MVP+4c = `CrashFs`).
- Each MVP gets a Git tag: `v0.0.mvp0`, `v0.1.mvp1`, etc. A release note describes what the MVP proved.
- A stage (§12.1+) is done when its constituent MVPs are done.

---

### 12.1 Stage-based roadmap

Stages are the broader framing: each stage ends with a tagged release and a short write-up.

### Stage 1 — Storage only *(finishable in a weekend)*
- File header, page allocation, freelist.
- Slotted page leaf layout.
- Single implicit "table."
- CLI: `init`, `put <k> <v>`, `get <k>`, `scan`, `stat`, plus the debug trio in §12.3.
- **No encryption, no WAL, no B+ tree yet.** Linear scan across leaf pages.
- Property tests for page + record codec.
- **Reference:** See `REFERENCES.md` for LruCache (page cache eviction pattern) and RingBuffer (optional WAL buffering).

#### 12.2 Stage 1 simplifications (explicit)

To keep Stage 1 actually finishable, the following are **deliberately not built** and must not be smuggled in:

- `fragmented_bytes` is not tracked — recompute on demand if a compaction is ever triggered.
- No overflow pages. Records exceeding the §5.4.2 cap are rejected.
- No readers-plural — `open` takes an exclusive lock on the file.
- No varint debate: **LEB128**, unsigned, for both `key_len` and `value_len`. Decision closed.
- No background anything. All work happens on the calling thread.

#### 12.3 Stage 1 debug tooling (ships with Stage 1, not later)

Debugging a storage engine without visibility is a recipe for learned helplessness. These CLI subcommands are part of Stage 1's definition of done:

- `tosumu dump <path> [--page N]` — pretty-print the file header and/or a single page: type, slot count, free_start/free_end, and each slot's `{offset, length, key_preview}`.
- `tosumu hex <path> --page N` — raw hex+ASCII dump of one page, 16 bytes per line, with header-field annotations for page 0.
- `tosumu verify <path>` — walk every page, check page-type consistency, slot bounds (`offset + length <= page_body_size`), freelist reachability, and (Stage 4+) AEAD tag + header MAC. Report every anomaly, exit non-zero on any.

#### 12.4 Viewer evolution (Stage 2+, optional but recommended)

The CLI inspection tools in §12.3 are the foundation. Once they work, an **interactive viewer** becomes a force multiplier for debugging, learning, and demonstrating tosumu. This section documents the staged viewer evolution so we don't accidentally build "Datagrip Junior" before the database works.

**Stage 2–3: TUI viewer (terminal UI)**

An interactive terminal UI using `ratatui` + `crossterm`:

```bash
tosumu view <path>
```

**Views to implement:**

- **File header view** — all header fields, flags, version info, page count
- **Page list** — scrollable list of all pages with type, usage, status
- **Page detail** — drill into a specific page: slots, records, freelist pointers
- **B+ tree structure** — visual tree with internal/leaf nodes, key ranges (Stage 2+)
- **WAL records** — list of WAL entries with LSN, type, affected pages (Stage 3+)
- **Verification view** — live validation results, anomalies highlighted

**Why TUI, not GUI:**

- Works over SSH, no X11/Wayland needed
- Faster to implement than Electron/Tauri
- Fits the "storage engine autopsy table" aesthetic
- No accidental frontend team

**Stage 4+: Encrypted DB inspection**

Once encryption lands, the viewer becomes a differentiator. Most encrypted storage tools are black boxes or "hex dumps wearing a trench coat." tosumu's viewer shows:

```bash
tosumu view encrypted.tsm --unlock
```

**Additional views for encrypted DBs:**

- **Protector summary** — list configured protectors (passphrase, recovery key, TPM, keyfile), their metadata, creation times
- **Keyslot detail** — per-slot status (active, empty, stale), `dek_id`, KDF params, flags
- **Header MAC status** — verified / mismatch / not yet unlocked
- **Per-page auth status** — green/red indicator for each page's AEAD tag
- **Corruption report** — which pages failed auth, whether it's localized or widespread
- **Encrypted vs plaintext summary** — page count breakdown, encrypted data size

**Why this matters:**

> A viewer turns `tosumu` from "trust me, it stores bytes" into:
> 
> "Look, here are the bytes, their structure, and whether the database believes them."

This aligns with tosumu's core principle: **no silent corruption**. The viewer makes that principle visible.

**Later (Stage 7+): Web/Desktop viewer**

Eventually, a graphical viewer:

- Rust backend + TypeScript frontend via `napi-rs`
- Or local HTTP server (axum/actix) with browser UI
- Or Tauri desktop app

But **not before Stage 6 is complete**. That path leads to "I built a database and accidentally became a frontend team."

**Command naming convention:**

- `tosumu inspect <path>` — quick summary (file header, page count, flags)
- `tosumu dump <path>` — text output (pages, records, structured)
- `tosumu hex <path> --page N` — raw byte dump
- `tosumu view <path>` — interactive TUI (Stage 2+)
- `tosumu verify <path>` — validation with exit code (Stage 1)

**Deliverable per stage:**

- **Stage 1:** CLI inspection tools only (`inspect`, `dump`, `hex`, `verify`)
- **Stage 2–3:** TUI viewer optional but recommended (implement `view` subcommand)
- **Stage 4:** Extend TUI viewer with encrypted DB views (protectors, keyslots, auth status)
- **Stage 7+:** Web/desktop viewer if time permits

**Acceptance criteria for TUI viewer (Stage 2+):**

- Runs in any terminal (Windows Terminal, iTerm2, kitty, etc.)
- Keyboard navigation (arrow keys, vim bindings optional)
- Handles large databases (pagination, lazy loading)
- Real-time refresh (watch mode: `tosumu view --watch`)
- Colorized output (ANSI colors for status, errors, warnings)
- Quit without corrupting terminal state

**Non-goals:**

- No write operations in the viewer (read-only, inspection only)
- No query builder / SQL editor (that's Stage 5's CLI, not the viewer)
- No connection pooling / multi-database management (single file at a time)
- No remote connections (local files only, security boundary is clear)

### Stage 2 — B+ tree index
- Internal pages, splits, merges (lazy deletes ok).
- Overflow pages for large values.
- Replace linear scan with tree walk.
- Property tests for tree invariants.
- **Reference:** See `REFERENCES.md` for BPlusTree (node splitting, leaf links, rebalancing algorithms).

### Stage 3 — Transactions + WAL
- `begin/commit/rollback`.
- WAL with physical logging.
- Recovery on open.
- `CrashFs` harness and crash tests.

### Stage 4 — Encryption

Split into three sub-stages because key management is its own discipline and cramming it into one stage is how toy projects quietly die.

#### Stage 4a — envelope encryption (one protector)
- Enable the page frame in §5.3 unconditionally for new encrypted databases.
- Generate a random DEK at `init`.
- Derive `page_key` and `header_mac_key` from DEK via HKDF (§8.3).
- One protector: **passphrase** (Argon2id). One keyslot.
- Keyslot region layout (§8.7), header MAC covers it.
- KATs for AEAD, HKDF info strings, and DEK-wrap AAD.
- CLI: `tosumu init --encrypt`, `tosumu open` prompts for passphrase.
- **`tosumu verify` extended** to check every keyslot's `kek_kcv` once unlocked, and the `dek_kat` field.

#### Stage 4b — multiple protectors + recovery + rotation
- Multiple keyslots; any one can unlock.
- **RecoveryKey** protector with one-time Base32 display at init.
- Optional **Keyfile** protector.
- CLI: `tosumu protector add|remove|list`, `tosumu rekey-kek` (cheap; rewraps DEK).
- `tosumu rekey-dek` (expensive full-file DEK rotation) — stretch; slips to Stage 6 if time is short.
- Tests: wrong-protector rejection, protector-swap attack (attacker swaps two wrapped blobs → must fail due to AAD binding, §8.7), header-MAC-covers-slot-region attack.

#### Stage 4c — TPM-backed protector (optional, feature-flagged)
- `tpm` Cargo feature. Core crate builds and passes all tests without it.
- `TpmProtector` seals a KEK to a TPM policy.
- `TpmPlusPinProtector` combines TPM-sealed secret + user PIN through Argon2id.
- Platform: Windows TBS or Linux `/dev/tpmrm0` via `tss-esapi` crate; pick one, document, move on.
- **Non-goal:** remote attestation, network key escrow, OS credential vault integration.

### Stage 5 — Toy query layer
- Parser for `CREATE TABLE`, `INSERT`, `SELECT ... WHERE key = ?`.
- Multiple tables → each table is a (rootpage, name) entry in a system catalog page.
- Still single-column primary key, no joins.

### Stage 6 — Stretch
- Multi-reader concurrency (MVCC snapshot by LSN).
- **Secondary indexes** — additional B+ trees mapping `(secondary_key, primary_key)`. Think `CREATE INDEX idx ON users(email)` for relational-style lookups. Not full-text, not fuzzy, not vectors (see §18).
- `VACUUM` — reclaim space from deleted records and rebuild indexes.
- Benchmarks vs SQLite on toy workloads, purely for humility.
- Explicit non-goals for Stage 6: no FSTs, no full-text search, no vector search, no spatial indexes. See §18 for why.
- **Optional optimization:** See `REFERENCES.md` for BloomFilter (per-page negative lookups to skip pages during scans).

---

## 13. Format evolution and migration policy

Humans are terrible migration engines. The file format will change; the engine’s job is to detect that, do the safe thing automatically, and refuse loudly when the safe thing is not possible. This section is normative: every format change must declare which category it belongs to and which rules apply.

### 13.1 Version fields

Two distinct `u16`s live in the header:

- **`format_version`** — what the file *is*. Bumped by every on-disk format change.
- **`min_reader_version`** — the lowest engine `format_version` that is permitted to open this file. A conservative writer sets this equal to `format_version`; a writer that knows a change is backwards-compatible may set it lower.

The engine itself has a `SUPPORTED_FORMAT` constant. Open rules:

| File's `format_version` | File's `min_reader_version` | Engine behavior |
|---|---|---|
| `== SUPPORTED_FORMAT` | any ≤ `SUPPORTED_FORMAT` | Open normally. |
| `< SUPPORTED_FORMAT` | any | Eligible for migration (§13.3). |
| `> SUPPORTED_FORMAT` | `≤ SUPPORTED_FORMAT` | Open **read-only**, print warning. |
| `> SUPPORTED_FORMAT` | `> SUPPORTED_FORMAT` | Refuse with `NewerFormat`. |

This lets us ship forward-compatible additions (e.g. a new optional header field) without immediately invalidating older binaries.

### 13.2 Migration categories

Every migration declares exactly one category. The category determines whether it runs automatically, whether a full rewrite is required, and how crash safety is guaranteed.

| Category | Examples | Auto on open? | Rewrite cost |
|---|---|---|---|
| **Metadata-only** | New optional header field with default; reserved flag becomes meaningful. | Yes | O(1) |
| **Keyslot-metadata** | New protector kind; per-slot field extension within reserved space. | Yes | O(keyslots) |
| **Page-local rewrite** | Slotted-page header layout tweak; freelist encoding change. | **No** (explicit) | O(pages) |
| **Index rebuild** | B+ tree node format change; new order or comparator. | **No** (explicit) | O(records), drops+rebuilds tree |
| **Full logical export/import** | Any change the other categories can’t express. | **No** (explicit) | O(records), new file |
| **Crypto-structural** | AAD composition change; DEK-wrap scheme change. | **No** (explicit) | Varies; often full rewrite |

Rule of thumb: **if it touches every page, it is not automatic**.

### 13.3 Policy

- **Safe automatic migrations happen on open.** Metadata-only and keyslot-metadata categories upgrade transparently, inside a transaction, and update `format_version` + `min_reader_version` before returning.
- **Destructive or long-running migrations require an explicit call.** Page-local, index rebuild, logical export/import, and crypto-structural migrations are performed only by `Database::migrate(path, opts)` or `tosumu migrate`.
- `open_read_only` **never** migrates.
- Every migration is **idempotent**: detects whether it has already run (via `format_version`) and is safe to re-invoke.
- Every migration ships with its own test: starting from a checked-in fixture file of the pre-migration format, open/migrate/verify must produce the expected post-migration fixture.

### 13.4 Crash-safety model

Two implementation strategies are permitted. Each migration declares which it uses.

**A. Copy-and-swap (default for heavy migrations).**
1. Write new file next to the original: `app.db.migrating`.
2. fsync the new file and its directory.
3. Rename `app.db` → `app.db.pre-v{N}.bak` (or delete if `--no-backup`).
4. Rename `app.db.migrating` → `app.db`.
5. fsync the directory.

On crash at any step, the original file is intact and an orphan `.migrating` file is cleaned up at next open.

**B. In-place via WAL (only for metadata-only / keyslot-metadata).**
1. Begin transaction.
2. Patch header and/or keyslot region.
3. Commit (WAL fsync first).

In-place is only permitted for migrations whose entire delta fits in a single transaction and touches no data pages.

### 13.5 Backups

- Automatic migrations **always** write a `.pre-v{N}.bak` next to the file before the first page changes, unless `--no-backup` is passed.
- `tosumu backup <path>` is a first-class command and is implicitly invoked before any explicit migration.
- The engine refuses to delete a `.bak` file. That’s the user’s call.

### 13.6 Migration trait and registry

Migrations are explicit structs implementing a common trait. No if-branch soup in `open()`.

A migration is not done when it runs. It is done when it **proves** the result is structurally valid, the expected changes happened, and unrelated data is unchanged.

```rust
pub trait FormatMigration: Send + Sync {
    const FROM: u16;
    const TO: u16;
    const CATEGORY: MigrationCategory;

    /// Produces a human-readable plan before any data is touched.
    /// Called by `inspect()` and `--dry-run`; must have no side effects.
    fn plan(&self, db: &Database) -> MigrationPlan;

    /// Runs precondition checks: exclusive lock held, WAL clean, free space
    /// sufficient, backup written if required. Returns `PreflightFailed` with
    /// a structured reason if any check fails.
    fn preflight(&self, db: &Database) -> Result<()>;

    /// Applies the migration. Called only after `preflight` returns `Ok`.
    fn apply(&self, ctx: &mut MigrationCtx) -> Result<()>;

    /// Verifies the result. Must check:
    ///   - structural validity (page MACs, freelist consistency)
    ///   - expected changes happened (format_version updated, new fields present)
    ///   - unrelated data is unchanged (spot-check or full verify depending on category)
    fn verify(&self, db: &Database) -> Result<VerificationReport>;
}

inventory::collect!(&'static dyn FormatMigration);
```

The engine builds a migration **chain** at open time: it walks registered migrations and verifies there is exactly one path from `file.format_version` to `SUPPORTED_FORMAT`. Ambiguous or missing links fail fast with a descriptive error.

`VerificationReport` mirrors `MigrationPlan` structure: it is a typed value, not a boolean. It contains counts of pages checked, any anomalies found, whether verification passed, and whether any data was unrecoverable.

### 13.7 Library API

```rust
impl Database {
    /// Auto-applies migrations in categories allowed by `opts.auto_migrate_policy`
    /// (default: metadata-only + keyslot-metadata). Heavier categories return
    /// `MigrationRequired`.
    pub fn open(path: &Path, opts: OpenOptions) -> Result<Database>;

    /// Never migrates. Returns `MigrationRequired` if the file is older.
    pub fn open_read_only(path: &Path) -> Result<Database>;

    /// Explicit migration runner. Applies every queued migration up to
    /// `SUPPORTED_FORMAT`, with backup and post-validation. No-op if already current.
    pub fn migrate(path: &Path, opts: MigrateOptions) -> Result<MigrationReport>;

    /// Dry-run: report what migrating this file would do, without touching it.
    pub fn inspect(path: &Path) -> Result<MigrationPlan>;
}
```

`MigrationPlan` includes: current `format_version`, target `format_version`, ordered list of migration steps with category and estimated rewrite cost, whether a backup will be created, and whether unlock (passphrase / TPM) will be required.

`plan.explain()` produces human-readable output. Example for a two-step upgrade:

```
tosumu migration plan

  Current format: 2
  Target format:  4

  Steps:
    2 → 3  Add page_lsn to page header
           Type:     full rewrite
           Backup:   required
           Verifier: page + btree + wal

    3 → 4  Add keyslot flags
           Type:     metadata-only
           Backup:   optional
           Verifier: header_mac

  Safety:
    exclusive lock required
    WAL must be clean
    estimated output size: 48 MB
    backup: data.tsm.pre-v3.bak

  Can migrate? yes
```

`--dry-run` calls `plan()` on every pending migration and prints this output without opening the file for write. It explicitly answers:
- Can migrate? yes/no (with reason if no)
- What will change?
- Will it rewrite the file?
- Is backup required?
- What validation runs after?

### 13.8 Key-management migrations

Key-management changes are **keyslot-metadata** migrations almost by construction, because the DEK/KEK split (§8) was designed so rotation rewrites the header, not the pages. Covered operations, all automatic-eligible:

- Rotate a KEK (rewrap DEK under a new protector-derived KEK).
- Add/remove a protector slot.
- Extend per-slot reserved bytes when a new protector version lands.

Exceptions that are **not** automatic:

- Full DEK rotation (§8.8) — crypto-structural, rewrites every page.
- AAD composition change — crypto-structural.

Crypto operations are exposed as **separate, named commands** rather than buried inside `migrate`. Hiding a full database rewrite behind "change password" builds user trust issues.

| Command | Category | Cost | What it does |
|---------|----------|------|--------------|
| `rekey-kek` | Keyslot-metadata | O(keyslots) | Rewrap DEK under new KEK; header rewrite only |
| `rekey-dek` | Crypto-structural | O(pages) | Generate new DEK, rewrite every page |
| `migrate-crypto` | Crypto-structural | O(pages) | Full crypto migration plan (AAD change, scheme upgrade) |

`rekey-dek` and `migrate-crypto` always require a full migration plan, backup, and post-verification. Neither runs automatically.

### 13.9 Schema migrations (Stage 5+)

Format migrations (§13.1–8) change how bytes are laid out. Schema migrations change what the bytes *mean*. They are a separate, higher-layer concern and live in the query crate.

Sketch:

```rust
db.migrate_schema([
    schema::create_table("users", &[...]),
    schema::add_column("users", "email", Type::Text),
    schema::backfill("users", |row| { /* user logic */ }),
])?;
```

Rules inherited from §13.3:
- Purely additive steps (new table, new nullable column) are automatic-eligible.
- Data-transforming steps require an explicit callback and explicit invocation.
- Destructive steps (drop column/table) refuse to run under `open()` — `migrate_schema` only.

A system catalog page tracks applied schema migration ids (monotonic integers). Re-running is a no-op.

### 13.10 CLI surface

Added in Stage 1 (even before any migrations exist), so the commands are muscle memory by the time they matter:

```
tosumu migrate <path>              # apply all pending migrations, with backup
tosumu migrate --dry-run <path>    # print MigrationPlan, touch nothing
tosumu migrate --no-backup <path>  # skip the .bak; refuses on destructive categories
tosumu inspect <path>              # format_version, min_reader_version, protectors
tosumu backup <path>               # explicit snapshot via copy-and-fsync
tosumu verify <path>               # already defined §12.3; also checks version fields
tosumu rekey-kek <path>            # fast: rewrap DEK under new KEK; header only
tosumu rekey-dek <path>            # slow: new DEK, rewrite every page
tosumu migrate-crypto <path>       # full crypto migration plan (AAD/scheme change)
```

`rekey-kek` is fast and automatic-eligible. `rekey-dek` and `migrate-crypto` always print a plan first and require explicit confirmation.

### 13.11 Formal rule set

Every migration in Tosumu follows these seven rules without exception:

```
1. Never auto-migrate read-only opens.
2. Never destructive-migrate without backup (unless --no-backup is explicit).
3. Always dry-run possible (plan() has no side effects).
4. Always verify after migration (verify() is not optional).
5. Always store migration history (§13.12).
6. Always distinguish migration category:
   metadata-only / page-local / index-rebuild / full-rewrite / crypto-structural.
7. Always leave the old database recoverable unless backup is explicitly disabled.
```

Additionally:

- No automatic **downgrade**. Ever. Downgrading is "use the backup."
- No partial migration on open. Either the whole auto-eligible chain applies, or none of it does.
- No silent destructive behavior. Any migration that touches more than metadata requires explicit opt-in.

### 13.12 Migration history

The database stores a migration log on a **system metadata page** (Page 1, once system pages exist in Stage 3+). Not just `format_version` — a full record of what ran, when, and by which engine.

```
migration_history
-----------------
from_version    u16
to_version      u16
name            text   ("AddPageLsn", "AddKeyslotFlags", ...)
kind            text   ("FullRewrite", "MetadataOnly", ...)
started_at      u64    (Unix timestamp, wall clock)
completed_at    u64
engine_version  text   (semver string of the tosumu binary)
pre_hash        [u8; 32]  (BLAKE3 hash of file before migration)
post_hash       [u8; 32]  (BLAKE3 hash of file after migration)
status          text   ("completed" | "rolled_back" | "partial")
backup_path     text   (path to .bak file, if any)
```

This lives in a reserved region of the system page, capped at N entries. On overflow, oldest entries roll off. Entries are read-only after write — no in-place update.

`tosumu inspect <path>` includes the migration history in its output. This is what "the result is explainable" looks like at the format layer.

### 13.13 Page-level migration receipts

For page-touching migrations (page-local rewrite, full rewrite, crypto-structural), the migration engine emits **per-page receipts** during execution:

```rust
pub struct PageReceipt {
    pub page_id: u32,
    pub old_hash: [u8; 32],
    pub new_hash: [u8; 32],
    pub migration: &'static str,   // e.g. "v2_to_v3_add_page_lsn"
}
```

Receipts are:
- **Written to a `.receipts` sidecar file** alongside the database during migration.
- **Used by `verify()` in the same migration** to cross-check that every touched page's new hash matches expectations.
- **Not retained indefinitely** — the sidecar is cleaned up after successful verification. If migration fails or `verify()` finds a mismatch, the sidecar remains for forensic inspection.

The sidecar filename is `<db>.migration-receipts`. If a receipts file exists at open time, the engine warns: a previous migration either failed or was interrupted. The receipts file is never silently deleted.

---

## 14. Repository layout

```
Database/
├── Cargo.toml                 (workspace)
├── DESIGN.md                  (this file)
├── README.md
├── SECURITY.md
├── LICENSE-MIT
├── LICENSE-APACHE
├── .gitignore
├── .github/
│   └── workflows/
│       └── ci.yml
├── crates/
│   ├── tosumu-core/           (library: pager, btree, wal, crypto)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── error.rs
│   │       ├── page.rs
│   │       ├── record.rs
│   │       ├── pager.rs
│   │       ├── wal.rs
│   │       ├── btree.rs
│   │       └── crypto.rs
│   └── tosumu-cli/            (binary, produces `tosumu` executable)
│       ├── Cargo.toml
│       └── src/main.rs
├── fuzz/                      (cargo-fuzz targets, added in Stage 1.5)
└── tests/                     (integration tests, CrashFs harness)
```

Workspace so Stage 5's query crate can slot in cleanly without bloating the core crate.

---

## 15. Open questions

These are tracked here, not silently deferred.

1. **Page size.** 4 KB is the obvious default. Do we want to make it configurable at `init` time for experimentation (e.g. 8 KB, 16 KB)? *Tentative: yes, settable at init, immutable after.*
2. **Endianness on disk.** Little-endian hardcoded. Any reason to revisit? *Tentative: no.*
3. ~~**Varint flavor.**~~ **Closed.** LEB128, unsigned. See §12.2.
4. **Checksum vs MAC for unencrypted mode.** If a user opts out of encryption, do we still CRC pages? *Tentative: yes, CRC32C in the page header.*
5. **WAL in separate file vs embedded.** Starting with a separate `tosumu.wal` file. Embedded WAL (SQLite-style) is possible later but adds complexity.
6. **Free page zeroing.** Do we zero freed pages on disk? *Tentative: yes when encrypted (cheap), optional when not.*
7. **Pager API shape.** References-with-lifetimes vs. closure/handle-based. Default is references; escape hatch documented in §6.2. Decision deferred to Stage 2.
8. **Global LSN in AEAD AAD.** Would close the consistent-multi-page-rollback gap in §5.3. Cost: every write bumps a global counter that must be durable before the write lands. Deferred to Stage 6.
9. **Keyslot count default.** 8 slots = 1 page at 256 B/slot + header overhead, which is plenty. Bigger means wasted space; smaller means rotation is annoying. *Tentative: 8 slots, fixed at init.*
10. **TPM library choice.** `tss-esapi` (cross-platform but Linux-centric) vs. platform-native (`windows` crate TBS bindings on Windows). *Tentative: `tss-esapi` for portability; revisit in Stage 4c.*
11. **`dek_id` in page AAD.** Including it would enable safe incremental rekey but breaks every existing page on DEK rotation. §8.8 currently says no; revisit if online rekey becomes a goal.
12. **Default `auto_migrate_policy`.** Ship with auto = {metadata-only, keyslot-metadata}. Should page-local rewrite ever be auto under a size threshold (e.g. <1 MB file)? *Tentative: no. Explicit is safer and consistent.*
13. **Backup retention.** Do we cap the number of `.pre-v{N}.bak` files we leave behind? *Tentative: no. Engine never deletes backups; that’s the user's call per §13.5.*

---

## 16. Definition of done (per stage)

A stage is "done" when:

1. **All acceptance tests for that stage pass** (§11.10). This includes:
   - All unit tests (`cargo test --workspace`).
   - Stage-specific integration tests in `tests/`.
   - CLI manual smoke tests listed in the stage's acceptance criteria.
   - Property tests where applicable (page encode/decode for Stage 1, B+ tree invariants for Stage 2).
   - Fuzz targets run for 5 minutes each without panics (manual, pre-release).
   - CrashFs tests (Stage 3+).
   - KATs (Stage 4+).
2. **The on-disk format section** of this doc (§5) has been updated *before* code was merged for any format change.
3. **Any format change** is accompanied by a registered `FormatMigration` (§13.6) and a fixture-based migration test (§11.9).
4. **Test coverage** in `tosumu-core` is ≥80% (§11.12). Run `cargo tarpaulin` or `cargo llvm-cov` and review uncovered lines.
5. **`cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test`** are all clean on stable Rust.
6. **A short retrospective** is appended to a `STAGES.md` (future) describing what surprised us and what we'd do differently.
7. **Version tag** created: `git tag v0.{stage}.0 && git push --tags`.

---

## 17. Name

**`tosumu`** — a conlang word meaning *knowledge-organization device*.

Etymology (registered form `to-su-mu`):

- `to` — knowledge / information
- `su` — organized structure
- `mu` — object / device

Composed: *"knowledge-organization device"* → database, library, knowledge-store.

Written form: **`tosumu`** (lowercase, no hyphens, ASCII-only).

Conventions:

- Crate names: `tosumu-core`, `tosumu-cli`, future `tosumu-query`.
- Binary: `tosumu` (e.g. `tosumu init`, `tosumu migrate`).
- File magic: ASCII `TOSUMUv0` in the first 8 bytes of page 0.
- HKDF info strings: `"tosumu/v{N}/<role>"` — see §8.3.
- AAD prefixes for DEK wrapping: `"tosumu/v{N}/wrap"` — see §8.7.
- Default file extension: `.tsm` (short) or `.tosumu` (explicit). `.tsm` for CLI examples.
- Pronunciation: *TOH-soo-moo*.

---

## 18. Advanced indexing and future directions

This section explicitly addresses indexing features beyond a basic B+ tree, so the project scope is honest and the "finishable by a mortal" goal stays intact.

### 18.1 What tosumu *does* support (Stages 1–6)

- **Primary key index** (Stage 2): B+ tree over the primary key. Supports point lookups (`get(key)`) and range scans (`scan(start_key..end_key)`).
- **Secondary indexes** (Stage 6, stretch): Additional B+ trees mapping `(secondary_key, primary_key)`. Standard relational DB feature. Supports lookups like `SELECT * FROM users WHERE email = ?`.

That's it. That's the entire indexing story for tosumu as designed.

### 18.2 What tosumu explicitly does *not* support

The following advanced indexing features are **out of scope** for Stages 1–6 and are unlikely to be added to the core engine:

#### 18.2.1 Finite State Transducers (FSTs)

**What:** Compressed trie structure mapping strings → values, used by Tantivy (Lucene's Rust cousin) for dictionary lookups and prefix search. Orders of magnitude more space-efficient than a B+ tree for string keys with common prefixes.

**Why not in tosumu:**
- FSTs are read-only or append-mostly. tosumu's design assumes mutable records.
- FST construction is a separate build phase (sort keys, build trie, serialize). tosumu's B+ tree is incrementally mutable.
- The complexity budget for Stage 2 is "implement a B+ tree"; FSTs are a lateral move into different territory.

**If you wanted it:**
Build a separate `tosumu-fst` crate wrapping the `fst` crate from BurntSushi. Store the FST as a blob in a tosumu record, rebuild it periodically. Treat tosumu as dumb storage and the FST as an external index.

#### 18.2.2 Full-text search (Lucene-style inverted indexes)

**What:** Tokenize documents, build inverted index mapping `term → [doc_id, doc_id, ...]`, support boolean queries (`"rust" AND "database"`), ranking (TF-IDF, BM25), highlighting.

**Why not in tosumu:**
- This is **an entire search engine**, not a database feature. Lucene, Elasticsearch, Tantivy, MeiliSearch are purpose-built for this.
- Building a competitive full-text engine is a multi-year project. tosumu is a learning project about page-based storage and crypto, not information retrieval.
- The right architecture is: tosumu stores documents → external indexer (Tantivy, Sonic, etc.) builds the inverted index → queries go to the indexer.

**If you wanted it:**
Use Tantivy or MeiliSearch as the index layer. Store document IDs in tosumu, forward search queries to the indexer, fetch the resulting doc IDs from tosumu. Don't try to build a search engine inside a key/value store.

#### 18.2.3 Vector / embedding search (semantic / AI-powered search)

**What:** Store high-dimensional vectors (e.g. sentence embeddings from BERT, CLIP image vectors), support approximate nearest neighbor (ANN) queries, return top-K most similar items. Used for semantic search, recommendation, RAG pipelines.

**Why not in tosumu:**
- ANN algorithms (HNSW, IVF, product quantization) are **fundamentally different** from B+ trees. They're graph-based or partition-based, not sorted-key-based.
- This is an active research area. State-of-the-art changes every 18 months. Not a fit for a "finishable" learning project.
- Storage engines that bolt on vector search (pgvector, SQLite-vss) are essentially embedding a separate vector index library (hnswlib, faiss) and exposing it through SQL syntax. That's a thin integration layer, not a core engine feature.

**If you wanted it:**
- Store vectors as blobs in tosumu records: `key → (metadata, vector_blob)`.
- Build a separate ANN index in memory or in a specialized vector DB (Qdrant, Milvus, Weaviate, Chroma).
- Query the vector DB for top-K doc IDs, then fetch the metadata from tosumu.
- Or: use the `hnswlib-rs` crate to build an in-memory HNSW index over tosumu-stored vectors on startup. Treat tosumu as durable storage for the graph, reconstruct the index in RAM.

#### 18.2.4 Fuzzy / typo-tolerant search

**What:** Match queries with up to N typos (Levenshtein distance), support prefix/suffix wildcards, phonetic matching (Soundex, Metaphone).

**Why not in tosumu:**
- Fuzzy search requires either:
  - **Preprocessing:** Build an n-gram index or BK-tree at write time (expensive, complex).
  - **Scan-time computation:** Linear scan + edit-distance on every record (slow).
- The right place for this is in an application layer that calls tosumu for retrieval after narrowing candidates.
- MeiliSearch and Typesense specialize in typo-tolerant search. Use them, don't rebuild them.

**If you wanted it:**
- Application-layer fuzzy matching: fetch candidate keys via prefix scan from tosumu's B+ tree, compute edit distance in the application, filter results.
- Or: store phonetic hashes (Soundex codes) as secondary keys, query by phonetic hash.
- Or: use an external fuzzy-search library (like `fuzzy-matcher` or `nucleo` crates) against an in-memory key list loaded from tosumu.

### 18.3 What *could* be added as extensions (hypothetical Stage 7+)

If tosumu reaches Stage 6 and someone wants to continue the learning journey, here are reasonable next steps that don't violate the core design:

**A. Spatial indexes (R-tree / Geohash)**

Store `(lat, lon)` pairs, support bounding-box queries. This is a well-understood problem with clear algorithms (R-tree, Geohash grid) and fits the "page-based index" model. Would live as a separate index type alongside the B+ tree.

**Complexity:** Medium. A decent learning project extension.

**B. Bloom filters for negative lookups**

Per-page or per-table Bloom filters stored in the header to skip scanning pages that provably don't contain a key. Common in LSM-tree engines (LevelDB, RocksDB). Fits cleanly into tosumu's architecture.

**Complexity:** Low. Good Stage 6+ addition.

**C. Prefix compression in B+ tree nodes**

Store `["apple", "application", "apply"]` as `["apple", "+lication", "+ly"]` with shared prefix factored out. Saves space in string-heavy workloads. Standard B+ tree optimization.

**Complexity:** Medium. Fits existing B+ tree code, no new data structures.

**D. Write-optimized log-structured merge tree (LSM) mode**

Replace the in-place B+ tree with a log-structured append-only design (SSTables + compaction). Completely different write path. Would be a fork or a separate mode flag at `init` time.

**Complexity:** High. This is "build a different database."

**E. Multi-column indexes (composite keys)**

Support `CREATE INDEX idx ON users(last_name, first_name)`. Requires extending the B+ tree key encoding to handle tuples. Fits existing Stage 6 "secondary indexes" work cleanly.

**Complexity:** Low-medium. Natural Stage 6 extension.

### 18.4 What will *never* be added

Some features are fundamentally incompatible with tosumu's design or goals:

- **Distributed / replicated storage.** tosumu is single-file, single-process by design. Consensus, replication, sharding are out of scope. Use CockroachDB, TiKV, or FoundationDB if you need that.
- **OLAP / columnar storage.** tosumu is row-oriented. Columnar compression, vectorized execution, and analytics queries belong in DuckDB, ClickHouse, or DataFusion.
- **Streaming / time-series ingestion.** High-write-rate time-series workloads want a specialized engine (TimescaleDB, InfluxDB, QuestDB). tosumu's WAL and B+ tree are not optimized for append-heavy loads.
- **Graph queries (Cypher, SPARQL).** Graph traversal algorithms (BFS, shortest path, pattern matching) need adjacency-list or edge-list representations. Store graphs in Neo4j, or build a graph layer on top of tosumu as an experiment, but it won't be first-class.

### 18.5 The honest answer

If you need full-text search, use **Tantivy** or **MeiliSearch**.
If you need vector search, use **Qdrant** or **pgvector**.
If you need spatial queries, use **PostGIS** or **SpatiaLite**.
If you need graphs, use **Neo4j** or **SurrealDB**.

tosumu is a learning project about building a small, correct, encrypted, page-based key/value store with a toy SQL layer. It does that one thing well (eventually). It is not a search engine, a vector database, a graph database, or a data warehouse.

Trying to be all of those would make it none of them.

The right architecture for a real system is: **tosumu stores records, specialized engines index them**. Keep the separation of concerns clean.

---

## 19. Platform support and mobile deployment

tosumu's embedded architecture (single-file, single-process, no server) makes it naturally suitable for mobile platforms. This section documents the plan for iOS and Android support, targeted for Stage 7+.

### 19.1 Why mobile is viable

**Rust officially supports mobile targets:**
- iOS: `aarch64-apple-ios` (64-bit ARM devices), `aarch64-apple-ios-sim` (M1 simulator), `x86_64-apple-ios` (Intel simulator)
- Android: `aarch64-linux-android` (ARM64, modern phones), `armv7-linux-androideabi` (ARM32, older phones), `x86_64-linux-android` (emulator)

**tosumu's design is mobile-friendly:**
- ✅ Single-file storage (works on mobile filesystems)
- ✅ No network, no server process (perfect for embedded use)
- ✅ Small footprint (Rust produces compact binaries)
- ✅ No platform-specific dependencies (RustCrypto works everywhere)
- ✅ Same architecture as SQLite (which runs on billions of mobile devices)

**Crypto dependencies are portable:**
- ChaCha20-Poly1305, Argon2id, HKDF from RustCrypto are pure Rust implementations
- Already used in mobile apps (Signal, 1Password use RustCrypto)
- No AES-NI requirement, no OS-specific crypto APIs

### 19.2 Implementation plan (Stage 7+)

#### Stage 7a — C FFI layer

Create `crates/tosumu-ffi` with a C-compatible API for foreign language bindings:

```rust
// crates/tosumu-ffi/src/lib.rs

#[repr(C)]
pub struct TDB {
    // Opaque handle to Database
}

#[no_mangle]
pub extern "C" fn tosumu_open(
    path: *const c_char,
    passphrase: *const u8,
    passphrase_len: usize
) -> *mut TDB;

#[no_mangle]
pub extern "C" fn tosumu_put(
    db: *mut TDB,
    key: *const u8,
    key_len: usize,
    value: *const u8,
    value_len: usize
) -> i32;

#[no_mangle]
pub extern "C" fn tosumu_get(
    db: *mut TDB,
    key: *const u8,
    key_len: usize,
    value_out: *mut *mut u8,
    value_len_out: *mut usize
) -> i32;

#[no_mangle]
pub extern "C" fn tosumu_close(db: *mut TDB);

#[no_mangle]
pub extern "C" fn tosumu_free_value(value: *mut u8);
```

**Alternative:** Use `uniffi-rs` (Mozilla's FFI generator) to auto-generate Swift, Kotlin, and Python bindings from Rust trait definitions. Less boilerplate, used by Firefox mobile.

**Acceptance:**
- C FFI compiles on Linux/macOS/Windows
- Test harness in C verifies API works
- Memory safety: no leaks, no use-after-free (run with Valgrind/AddressSanitizer)

#### Stage 7b — iOS support

**Build for iOS:**
```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
cargo install cargo-lipo
cargo lipo --release --targets aarch64-apple-ios,aarch64-apple-ios-sim
# Produces universal .a library for Xcode
```

**Swift wrapper library:**
```swift
// TosumuKit/Sources/TosumuKit/Database.swift
import Foundation

public class TosumuDB {
    private var handle: OpaquePointer?
    
    public init(path: String, passphrase: String) throws {
        let cPath = path.cString(using: .utf8)
        let cPass = passphrase.data(using: .utf8)!
        
        handle = cPass.withUnsafeBytes { passPtr in
            tosumu_open(cPath, passPtr.baseAddress, cPass.count)
        }
        
        guard handle != nil else {
            throw TosumuError.openFailed
        }
    }
    
    public func put(key: Data, value: Data) throws {
        let result = key.withUnsafeBytes { keyPtr in
            value.withUnsafeBytes { valPtr in
                tosumu_put(handle, keyPtr.baseAddress, key.count,
                          valPtr.baseAddress, value.count)
            }
        }
        guard result == 0 else { throw TosumuError.writeFailed }
    }
    
    public func get(key: Data) throws -> Data? {
        var valuePtr: UnsafeMutablePointer<UInt8>? = nil
        var valueLen: Int = 0
        
        let result = key.withUnsafeBytes { keyPtr in
            tosumu_get(handle, keyPtr.baseAddress, key.count,
                      &valuePtr, &valueLen)
        }
        
        guard result == 0 else { throw TosumuError.readFailed }
        guard let ptr = valuePtr else { return nil }
        
        defer { tosumu_free_value(ptr) }
        return Data(bytes: ptr, count: valueLen)
    }
    
    deinit {
        if let h = handle {
            tosumu_close(h)
        }
    }
}

public enum TosumuError: Error {
    case openFailed, writeFailed, readFailed
}
```

**iOS Keychain protector:**

Add a new `IosKeychainProtector` (§8.6) to replace the unavailable `TpmProtector`:

```rust
// Feature: ios-keychain
// Uses Security framework to store KEK in iOS Keychain (hardware-backed on devices with Secure Enclave)

#[cfg(feature = "ios-keychain")]
pub struct IosKeychainProtector {
    service: String,  // e.g. "com.yourapp.tosumu"
    account: String,  // e.g. database UUID
}

impl KeyProtector for IosKeychainProtector {
    fn derive_kek(&self, meta: &ProtectorMetadata, input: &ProtectorInput)
        -> Result<Zeroizing<[u8; 32]>>
    {
        // kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        // Retrieve 32-byte KEK from Keychain
        // Falls back to passphrase if Keychain unavailable
    }
}
```

**Demo app:**
SwiftUI app demonstrating encrypted note storage using tosumu.

**Acceptance:**
- Builds for iOS devices and simulator
- Demo app runs on physical iPhone
- Keychain protector stores KEK in Secure Enclave
- Database persists across app restarts

#### Stage 7c — Android support

**Build for Android:**
```bash
rustup target add aarch64-linux-android
cargo install cargo-ndk
cargo ndk --target aarch64-linux-android --platform 21 -- build --release
# Produces .so library for JNI
```

**Kotlin wrapper library:**
```kotlin
// com/yourapp/tosumu/Database.kt
package com.yourapp.tosumu

class TosumuDB {
    private var handle: Long = 0
    
    companion object {
        init {
            System.loadLibrary("tosumu_ffi")
        }
    }
    
    external fun tosumuOpen(path: String, passphrase: ByteArray): Long
    external fun tosumuPut(handle: Long, key: ByteArray, value: ByteArray): Int
    external fun tosumuGet(handle: Long, key: ByteArray): ByteArray?
    external fun tosumuClose(handle: Long)
    
    fun open(path: String, passphrase: String) {
        handle = tosumuOpen(path, passphrase.toByteArray(Charsets.UTF_8))
        if (handle == 0L) throw TosumuException("Failed to open database")
    }
    
    fun put(key: ByteArray, value: ByteArray) {
        val result = tosumuPut(handle, key, value)
        if (result != 0) throw TosumuException("Write failed")
    }
    
    fun get(key: ByteArray): ByteArray? {
        return tosumuGet(handle, key)
    }
    
    fun close() {
        if (handle != 0L) {
            tosumuClose(handle)
            handle = 0
        }
    }
}

class TosumuException(message: String) : Exception(message)
```

**Android Keystore protector:**

Add `AndroidKeystoreProtector` (§8.6):

```rust
// Feature: android-keystore
// Uses Android Keystore (hardware-backed on modern devices) to wrap KEK

#[cfg(feature = "android-keystore")]
pub struct AndroidKeystoreProtector {
    alias: String,  // Keystore key alias
}

impl KeyProtector for AndroidKeystoreProtector {
    fn derive_kek(&self, meta: &ProtectorMetadata, input: &ProtectorInput)
        -> Result<Zeroizing<[u8; 32]>>
    {
        // Call JNI to Android KeyStore API
        // Wrap/unwrap KEK using hardware-backed AES key
        // Requires API 23+ (Marshmallow)
    }
}
```

**Demo app:**
Jetpack Compose app demonstrating encrypted task list using tosumu.

**Acceptance:**
- Builds for Android ARM64 (minSdk 21, targetSdk 34)
- Demo app runs on physical Android device
- Keystore protector uses hardware-backed key
- Database persists across app restarts

### 19.3 Platform-specific considerations

#### File system and permissions

**iOS:**
- Apps run in sandboxed container (`/var/mobile/Containers/Data/Application/{UUID}/`)
- Store database in `Documents/` (user-visible, backed up) or `Library/Application Support/` (hidden, backed up)
- No special permissions needed

**Android:**
- Apps have private storage (`/data/data/{package}/`) — no permissions needed
- External storage (`/sdcard/`) requires `WRITE_EXTERNAL_STORAGE` permission (deprecated in API 30+)
- Recommended: use app-specific private directory (`context.filesDir`)

#### Protector availability

| Protector | Desktop | iOS | Android | Notes |
|-----------|---------|-----|---------|-------|
| Passphrase | ✅ | ✅ | ✅ | Universal |
| RecoveryKey | ✅ | ✅ | ✅ | Universal |
| Keyfile | ✅ | ⚠️ | ⚠️ | Limited (iOS/Android restrict file access) |
| Tpm | ✅ (Windows/Linux) | ❌ | ❌ | Desktop only |
| IosKeychain | ❌ | ✅ | ❌ | iOS only (Secure Enclave) |
| AndroidKeystore | ❌ | ❌ | ✅ | Android only (hardware-backed) |

**Design implication:** Protector abstraction (§8.6) cleanly handles platform differences. Each platform gets its own hardware-backed protector; the core engine is unchanged.

#### CLI not useful on mobile

- `tosumu-cli` binary won't run on iOS/Android (no shell access)
- Mobile apps embed `tosumu-core` library directly via FFI
- All operations through programmatic API, not CLI subcommands

#### Testing on mobile

**iOS testing:**
- Unit tests run via `cargo test` on macOS
- Integration tests run on iOS simulator via `cargo test --target aarch64-apple-ios-sim`
- Manual testing on physical iPhone (requires Apple Developer account)

**Android testing:**
- Unit tests run via `cargo test` on Linux
- Integration tests run on Android emulator (requires Android SDK)
- Manual testing on physical Android device (enable USB debugging)

### 19.4 Performance expectations

**Expected performance vs desktop:**
- **Similar or better:** Modern ARM chips (A17 Pro, Snapdragon 8 Gen 3) rival desktop CPUs
- **I/O may be slower:** Mobile flash is optimized for power, not raw throughput
- **Battery impact:** Crypto operations (Argon2id) should use conservative parameters on mobile

**Argon2id tuning for mobile:**
```rust
// Desktop: 128 MB, 8 iterations, 4 threads
Argon2id { m: 128_000, t: 8, p: 4 }

// Mobile: 64 MB, 4 iterations, 2 threads (preserve battery)
Argon2id { m: 64_000, t: 4, p: 2 }
```

### 19.5 Distribution and packaging

**iOS:**
- Distribute as **Swift Package** (SPM) or **CocoaPod**
- Include prebuilt `libtosumu_ffi.a` (universal binary) + Swift wrapper
- Xcode automatically links with app

**Android:**
- Distribute as **AAR** (Android Archive) via Maven Central or GitHub Packages
- Include `.so` libraries for `arm64-v8a`, `armeabi-v7a`, `x86_64` architectures
- Gradle automatically bundles with APK

**Binary size:**
- Rust release build: ~500 KB (stripped)
- With RustCrypto dependencies: ~800 KB
- Per-architecture overhead: iOS universal binary ~1.5 MB, Android multi-arch ~2.5 MB

### 19.6 Security considerations on mobile

**Advantages:**
- ✅ Hardware-backed key storage (Secure Enclave on iOS, TEE on Android)
- ✅ Biometric authentication (Touch ID, Face ID, fingerprint) can unlock Keychain/Keystore protector
- ✅ Apps can't access other apps' databases (OS-level sandboxing)

**Risks:**
- ⚠️ Screen lock bypass → attacker gains file access (but database still encrypted)
- ⚠️ Backup exposure (iCloud/Google Drive backups may store database file; passphraseprotector alone is vulnerable)
- ⚠️ Jailbreak/root → OS security model bypassed

**Mitigation:**
- Recommend `IosKeychainProtector` / `AndroidKeystoreProtector` over passphrase-only
- Document that backups include encrypted database (user must protect backup separately)
- Add `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` flag (iOS) to prevent cloud backup of Keychain items

### 19.7 What this section does *not* promise

- No WebAssembly (WASM) support. File I/O in browsers is limited; IndexedDB is the better choice.
- No cross-platform mobile framework bindings (React Native, Flutter). FFI layer is C-compatible; community can build bindings.
- No mobile-specific optimizations (e.g., adaptive page size for flash characteristics). Desktop settings work fine.
- No "lite" mode. Full tosumu feature set on mobile. If it's too heavy, the app can use SQLite instead.

### 19.8 Precedents

**Rust databases on mobile:**
- **redb** (embedded key/value store): Runs on iOS/Android, used in production apps
- **sled** (embedded key/value store): Mobile-compatible
- **rusqlite** (SQLite bindings): Widely deployed on mobile

**Rust crypto on mobile:**
- **Signal** (messaging app): Rust crypto library on iOS/Android
- **1Password** (password manager): Rust security components
- **Mullvad VPN**: Rust client on mobile

**If SQLite can do it, tosumu can do it.** Same architecture, same constraints, same capabilities.

### 19.9 Timeline and staging

**Not before Stage 6 complete.** Mobile support is an extension, not a core goal. Desktop platforms (Linux/macOS/Windows) must be stable first.

**Estimated effort:**
- Stage 7a (FFI layer): 1 week
- Stage 7b (iOS): 2 weeks
- Stage 7c (Android): 2 weeks
- **Total: 5 weeks** for full mobile support

**Success criteria:**
- Demo iOS app and demo Android app both:
  - Create encrypted database
  - Insert/retrieve records
  - Persist across app restarts
  - Use hardware-backed key storage (Keychain/Keystore)
- FFI layer has comprehensive tests (memory safety, error handling)
- Documented in README with "mobile" badge

---

## 20. Differentiation opportunities

The interesting database ideas are not "faster index." They are: **make systems understandable, safe, and repairable.** Performance problems get optimized. Understanding problems haunt you forever.

This section documents the design bets where tosumu can go beyond being another learning-exercise toy database. Not all of them will ship. The honest answer for a solo learning project is: pick 2–3 that align with your actual pain, build them well, and leave the rest as named ideas rather than half-implemented messes.

**The ideas are documented regardless of shipping status.** Naming them explicitly is useful: it tells future contributors what's intentional vs. simply missing, and it keeps scope decisions from being accidental.

### 20.1 Differentiation bets (ranked by pain alignment)

#### 🥇 20.1.1 Explainability and data provenance (highest priority)

Most databases treat result provenance as "trust me, bro." Even `EXPLAIN` gives you a cryptic execution plan written by a compiler having a bad day.

**The opportunity:** Make every operation explainable.

```
WHY does this record exist?
WHAT wrote it?
WHEN was it last modified?
WHICH operation produced this value?
```

**What this looks like in practice:**

```
tosumu get customer:123
→ value: { status: "active" }
→ provenance:
    created:  2026-01-10  by: import-job/v12
    modified: 2026-03-10  by: patch-operation/2026-03-10
    field "status": set by rule-engine/rule-X at 2026-03-01
```

**Implementation path:**

This is a natural extension of the WAL. Every WAL record already has an LSN. Adding an optional `source` field to write operations (a short opaque string — "import-job:v12", "api:PUT /customer/123") costs almost nothing at the write site. At query time, the pager can annotate the response with the LSN + source of the last write that touched each record.

Stage-level targeting:
- Stage 3+ (WAL exists): store `source` in WAL records as an optional tagged field.
- Stage 5+ (query layer): surface as `GET ... EXPLAIN` or `provenance(key)` query verb.
- Stage 6+ (MVCC): full "who wrote this version" history.

**Why it matters for this codebase specifically:** Customer support and debugging workflows. "What produced this document" is a question asked daily in production systems. Almost no embedded database has a good answer.

**Explicitly not scope-creep:** This is not a full audit log system. It is one tagged field on write operations. The heavy version is opt-in.

---

#### 🥈 20.1.2 Derived data correctness (staleness tracking)

Most systems treat derived data as: "store it somewhere and hope it stays fresh."

**The opportunity:** Formalize the relationship between source data and materialized output.

```
source key(s)
     ↓
declared derivation (a named transform, a version)
     ↓
materialized output (stored alongside or separate)
     ↓
version + dependency tracking
```

**What this looks like:**

```
derive rendered_html:customer:123
    from source:customer:123
    by transform:html-render/v7

tosumu get rendered_html:customer:123
→ value: "<html>..."
→ freshness: STALE (source modified at LSN 1042, derived from LSN 990)
→ advice: re-run transform html-render/v7 against source:customer:123
```

**Implementation path:**

A "derivation record" is just a special value stored alongside the derived key:
```
{
  source_keys: ["customer:123"],
  transform_id: "html-render/v7",
  derived_at_lsn: 990,
}
```

When any `source_key` is modified (LSN > `derived_at_lsn`), the derived record is automatically flagged stale on read. No background process needed. Staleness is a query-time annotation.

Stage-level targeting:
- Stage 3+ (LSN exists): derivation records + staleness check on read.
- Stage 5+ (query layer): `DERIVE key FROM source BY transform` as a query verb.
- Stage 6+ (MVCC): time-travel lets you "see what the derived value looked like at LSN X."

**Why it matters for this codebase specifically:** The "stale HTML nightmare" — rendered output that silently diverges from source because there's no formal relationship tracked between them.

---

#### 🥉 20.1.3 Repairability (verification → diagnosis → repair)

Most databases assume things work. You should assume things break.

**The opportunity:** A full repair stack, not just `PRAGMA integrity_check` that returns a wall of text and wishes you luck.

```
verify()  → structured error list
diagnose()→ "here is what is wrong and where"
repair()  → "here is what was fixed, what was unrecoverable"
rebuild() → reconstruct indexes from raw page data
```

**This is already partially in the plan** via `tosumu verify` (§12.3). The extension is making it *actionable*, not just diagnostic.

**What "repair" means concretely:**
- **Freelist corruption:** Rebuild freelist by scanning all pages and inferring free vs. allocated state.
- **B+ tree corruption (Stage 2+):** Rebuild the tree index from leaf pages (raw data survives even if the tree structure doesn't).
- **WAL corruption:** Truncate WAL to last clean commit point. Report which transactions were lost.
- **Keyslot corruption (Stage 4+):** Report which slots are tampered (`KeyslotTampered` error), which slots are intact, whether any valid protector remains.

**Repair is never silent.** Every repair operation produces a structured `RepairReport`:
```rust
RepairReport {
    pages_ok: 1021,
    pages_repaired: 2,
    pages_unrecoverable: 1,
    lsn_before: 1044,
    lsn_after: 1039,    // rolled back to last clean WAL point
    warnings: vec!["page 847: slot 3 truncated to page boundary"],
}
```

Stage-level targeting:
- Stage 1: `rebuild_freelist()` — reconstruct freelist from page scan.
- Stage 3+: `repair_wal()` — truncate to last clean commit.
- Stage 4+: `diagnose_keyslots()` — report which slots are intact.
- Stage 5+: `rebuild_index()` — reconstruct B+ tree from leaf pages.

---

### 20.2 Secondary bets (valuable, lower priority)

These are worth naming but should not be built before the primary bets above are working.

#### 20.2.1 Time travel / navigable history

WAL + LSN naturally supports "what did this key look like at LSN N?" The cost is retaining WAL longer and supporting point-in-time reads.

**Minimum viable version:** `tosumu get key --at-lsn 1000`. No new storage format needed for Stage 6 MVCC — LSN-based snapshots already give you this. The UI work is a `--at-lsn` flag on CLI commands.

**Stretch version:** `tosumu diff key --from 900 --to 1000` — show what changed between two LSNs. Useful for debugging "what happened between this deploy and the customer's complaint."

**Why not now:** Requires MVCC (Stage 6). Do not fake it before then.

#### 20.2.2 Structured observability (operation log)

Instead of logs scattered in files, operations emit **structured, queryable events** linked to data:

```
tosumu ops key:customer:123
→ [LSN 900]  PUT  by: api/v2    value_size: 412  duration: 0.3ms
→ [LSN 1042] PUT  by: patch/v3  value_size: 415  duration: 0.2ms
→ [LSN 1044] GET  by: render/v7              duration: 0.1ms
```

**Implementation path:** A thin op-log table (ring buffer of recent operations, queryable by key prefix). Separate from WAL — WAL is durability, op-log is observability. Capped at N entries; no persistence guarantees.

**Why not now:** Needs Stage 5 query layer to be useful. Before then, `tosumu verify` and `dump` are sufficient.

#### 20.2.3 Schema-optional validation

```
data is flexible
validation rules are explicit
rules are versioned
rule violations surface as typed errors, not silent writes
```

**Not a schema in the SQL sense.** Think closer to: a declared set of `(key_pattern, validator_fn)` pairs that run at write time. Validators are pure functions (no side effects), evaluated in a sandboxed interpreter or expressed as a compact rule DSL.

**Why not now:** Needs Stage 5 query layer and a safe extension mechanism (§20.2.4). Do not build the validator before the storage is solid.

#### 20.2.4 Safe extensions (structured, inspectable, sandboxed)

Instead of "run this arbitrary trigger and pray," extensions are:

- **Structured:** defined in a typed manifest, not arbitrary code.
- **Inspectable:** `tosumu extensions list` shows what's registered and what it touches.
- **Sandboxed:** extensions cannot write outside their declared scope, cannot block I/O, have execution time limits.

**Minimum viable version:** A pure-function trigger expressed as a rule AST (no Turing-complete code execution). Heavy version: WASM sandbox for arbitrary logic. Do not start with WASM.

**Why not now:** Stage 7+ at earliest. Sandboxed execution is a project in itself. Name it, don't build it yet.

### 20.3 What is explicitly off the table

Some ideas from the landscape that are **not** tosumu's direction, even if they sound appealing:

- **Full graph database.** Relationship-aware lookups (§20.2) are not a graph DB. No traversal engine, no Cypher-style query language, no hyperedges.
- **Event sourcing framework.** WAL is not an event bus. Do not expose WAL entries as a pub/sub mechanism.
- **Distributed / replicated storage.** Single-process, single-file. Replication is an application-layer concern.
- **ML/AI pipeline integration.** Vector search, embedding storage, nearest-neighbor indexes — out of scope per §18. Use a specialized tool.

### 20.4 Design principle summary

Across all of the above, the common thread is:

> **Make systems understandable, safe, and repairable.**

Applied to tosumu:

| Principle | Current expression | Future expression |
|-----------|-------------------|-------------------|
| Understandable | `verify`, `dump`, `hex`, TUI viewer | Provenance on reads, op-log, time travel |
| Safe | AEAD per page, typed errors, no silent corruption | Sandboxed extensions, schema validation |
| Repairable | `verify` exits non-zero | Structured repair stack, `RepairReport` |
| Explainable | `EXPLAIN` roadmap (Stage 5) | Derivation tracking, staleness annotation |

**The most honest version of this section:** tosumu is a learning project, and learning projects that try to innovate on 10 axes finish zero of them. The value of this section is naming the ideas clearly so that Stage-N decisions are made deliberately, not accidentally. When Stage 3 WAL design comes up, add the `source` field. When Stage 5 query design comes up, add `GET ... EXPLAIN`. When Stage 6 MVCC comes up, add `--at-lsn`. These are not separate projects. They are one extra field or one extra flag added at the right moment.

---
