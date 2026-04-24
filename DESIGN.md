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

### 1.4 Motivating real-world context: offline-first sync

Tosumu is a learning project, but the epistemic model (§29) emerged from a concrete problem: the standard offline-first architecture —

```
client → local SQLite
         ↕ periodic sync
         central server (e.g. a Raspberry Pi)
```

— has a structural confidence problem that most systems paper over.

**The actual failures in offline-first systems:**

1. **Stale reads presented as current.** The local DB says "here is your data." It hasn't synced in two hours. SQLite returns it without comment. The application has no way to know whether to trust it.

2. **Sync conflicts with no epistemic metadata.** When two clients diverge, conflict resolution asks "which write wins?" — but neither side can say "how confident am I in this version?" The system has no vocabulary for confidence.

3. **Silent partial failures.** A network glitch or crash mid-sync leaves the system in unknown state while continuing to behave as if it is in known state.

Tosumu's three-dimension model (§29.2) gives offline-first systems a vocabulary that is currently missing:

```
integrity:   OK     — AEAD tag verified
freshness:   unanchored — last sync 2h ago, no witness
epistemic:   do not present as current
```

This lets the application make an honest disclosure:

```
⚠ Data may be stale — last sync 2h ago
```

rather than silently returning data that may be wrong.

**The deeper shift.** The purpose of sync in this model is not just moving bytes — it is moving *confidence*. A client that has not recently synced has lower epistemic standing than the server it synced from. Conflict resolution that takes this into account ("which claim is stronger?") is more correct than resolution that ignores it ("which write is newer?").

**A small central server as a witness.** The §23 witness model maps naturally onto this topology: the central server holds the freshness anchor. Clients ask "am I current?" and receive a real answer backed by the server's audit head. The server becomes a `tosu`-tier anchor; clients that have not yet synced are `to`-tier at best.

**Migration strategy for adopters.** The right approach is not to replace an entire existing stack at once:

1. Introduce Tosumu for one subsystem where staleness visibly hurts.
2. Add sync metadata and use the server as a freshness witness.
3. Extend the UI to surface epistemic state where it matters.

The existing stack and Tosumu can coexist. The point is not to eliminate other databases — it is to stop pretending that local copies are ground truth.

---

## 2. Guiding principles

1. **Finishable by a mortal.** Every stage must produce something runnable and testable on its own.
2. **On-disk format is sacred.** The file format is documented before it is coded. Every byte has a reason.
3. **Crypto binds structure.** AEAD AAD must cover anything that would be dangerous to swap, reorder, or roll back.
4. **No silent corruption.** Any integrity failure surfaces as a typed error. Never "just a weird byte."
5. **Types over comments.** Layout is expressed in `#[repr(C)]` structs and enums, not prose.
6. **Tests before cleverness.** Property tests and fuzzers land with the module they test.
7. **Declarative intent, imperative mechanics.** Queries, migrations, validation, and provenance express *what* is intended — as plans, ASTs, and typed declarations. The storage engine, pager, and crypto layer express *how* — pages, fsyncs, and AEAD operations. These layers do not leak into each other. A page does not understand a query. A migration plan does not perform I/O. The line between them is the most important architectural boundary in the system.
8. **Structural impossibility over advisory rules.** The strongest guardrail is one that makes the dangerous path structurally impossible, not one that documents it as inadvisable. An `Err`-returning write closure cannot accidentally commit regardless of what the caller does. An AEAD tag failure is `AuthFailed`, not `Ok(suspicious_bytes)`. `#[forbid(unsafe_code)]` is a proof, not a lint suggestion. When a design decision requires writing a warning in the documentation, first ask whether a redesign could eliminate the need for the warning by construction.
9. **Stabilize traits after three independent callers.** A public trait, type, or API is not ready to lock until at least three independent, concrete use cases drive its shape. One caller writes the API for its own convenience. Two callers suggest a pattern. Three callers reveal the actual contract. `KeyProtector` earns its trait because `Passphrase`, `RecoveryKey`, and `Tpm` are each independently motivated and would produce incompatible ad-hoc designs without the abstraction. Convenience wrappers with a single caller stay concrete until a second caller appears.
10. **Sequence is not grounding; label which claim you are making.** Observing that B followed A is a sequence claim (Humean constant conjunction). Asserting that A *constitutively ensures* B is a causal-grounding claim (necessary connection). These are different guarantees and must not be confused. A WAL commit record followed by an `fsync` that returns `Ok` constitutively grounds durability *if and only if the OS contract makes `Ok` mean "the bytes are on disk."* On a network filesystem the same `Ok` is only a sequence observation — it says the OS accepted the call, not that the bytes are persisted. Every durability guarantee, crash-safety claim, and integrity assertion in Tosumu should be clear about which kind of claim it is. A sequence-only claim is not wrong; it is weaker, and callers need to know. When a guarantee turns out to be sequence-only at the OS level, the response is verify-after-write and AEAD re-check — not pretending the sequence is grounding.
11. **"Unspecified" and "undefined" are different design choices; name them.** A behavior that is *unspecified* by design — where the implementation is intentionally free to choose — must be labelled as such so callers know not to rely on it. A behavior that is *undefined* — where any result, including a corrupt database or a panic, is permitted — is a different and stronger statement. The separation matters for compatibility: an unspecified but stable implementation-defined behavior that callers have silently relied on cannot be changed without a version bump. The scan-order example (§10.3) is the canonical case: `scan_physical()` and `scan_by_key()` exist precisely to replace one vague "scan" with two explicit contracts. When a vague term is suppressed by naming it, the suppression is a design decision and should be documented as one.

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

**The pager is the trust boundary.** Memory is the trusted zone. Disk is the adversarial zone. Every page that crosses from disk into the cache is authenticated and decrypted at the boundary; every page that crosses from cache to disk is encrypted and tagged at the boundary. Nothing above the pager ever touches ciphertext. Nothing below the pager ever touches plaintext. The crypto layer enforces this: it is not a feature the pager uses — it is the definition of what the pager boundary means.

This has a practical implication: all integrity checking happens exactly once, at the boundary, in one place. There is no secondary "was this tampered with?" check higher up the stack because the answer is already known — a page that passed the AEAD boundary is authentic; a page that failed never entered the cache.

**Layer dependency is a structural invariant, not a convention.** No lower layer calls into a layer above it. No higher layer bypasses a layer below it. The B+ tree does not access the file directly. The pager does not know about transactions. The crypto layer does not know that keys are protector-derived. This is enforced by the crate and module structure: the dependency graph is a DAG, and module visibility rules make cross-layer calls a compiler error, not a code-review comment.

This matters because safety-by-convention degrades under time pressure. An architectural boundary that can be crossed when things are urgent is not a boundary. The Tarski hierarchy that makes the Liar Paradox unexpressible in Tonesu works for the same reason: the one-directional level constraint is structural, not advisory.

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
| 22 | 2 | `flags` | bit 0 = reserved (was `encrypted`; always 1); bit 1 = has keyslots |
| 24 | 8 | `page_count` | total pages including header |
| 32 | 8 | `freelist_head` | page number or 0 |
| 40 | 8 | `root_page` | B+ tree root (Stage 2) |
| 48 | 8 | `wal_checkpoint_lsn` | last durable LSN |
| 56 | 8 | `dek_id` | monotonic id of the currently-active DEK (for rotation, Stage 4b+) |
| 64 | 16 | `dek_kat` | AEAD of a fixed known-plaintext under the DEK; cheap wrong-DEK detection |
| 80 | 2 | `keyslot_count` | number of protector slots present (always ≥ 1; slot 0 is the `Sentinel` protector) |
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

Every database is always encrypted. There is no unencrypted mode. A database opened without a user-supplied passphrase uses the `Sentinel` protector (§8.6) — a machine-generated key stored in keyslot 0 that provides AEAD integrity even before the user has configured a passphrase. The user can rotate the sentinel out at any time by adding a `Passphrase` or `RecoveryKey` protector and removing slot 0.

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

The pager API is **closure-based**. This is the committed design, not a fallback.

```rust
pub struct Pager { /* ... */ }

impl Pager {
    pub fn open(path: &Path, key: Option<&Key>) -> Result<Self>;

    /// Read-only access. Closure receives a shared view; cannot mark page dirty.
    pub fn with_page<F, T>(&self, pgno: PageNo, f: F) -> Result<T>
    where F: FnOnce(&PageView) -> Result<T>;

    /// Read-write access. Closure receives a mutable view; page is marked dirty on return.
    pub fn with_page_mut<F>(&self, pgno: PageNo, f: F) -> Result<()>
    where F: FnOnce(&mut PageViewMut) -> Result<()>;

    pub fn allocate(&self, page_type: PageType) -> Result<PageNo>;
    pub fn free(&self, pgno: PageNo) -> Result<()>;
    pub fn flush(&self) -> Result<()>;   // called by txn commit
    pub fn close(self) -> Result<()>;
}
```

**Why closure-based, not `PageRef<'_>` / `PageRefMut<'_>` with explicit lifetimes:**

Returning borrowed references tied to `&self` causes aliasing problems as soon as the B+ tree needs to hold views into two pages at once (e.g. during a node split: parent + child both pinned). `RefCell` borrow guards don't compose across two simultaneous `borrow_mut()` calls — the second panics at runtime, not at compile time. Lifetime-based APIs that "seem fine" at Stage 1 spread into the B+ tree and become expensive to unwind.

Closure-based API properties:
- No simultaneous borrows. Each closure runs, completes, and releases before the next.
- The pager owns the cache exclusively; no external code holds a view longer than one call.
- Multi-page operations (splits, merges) acquire pages sequentially through nested closures, which is correct by construction.
- `with_page_mut` marks the page dirty on return from the closure, regardless of how the closure exits.

The one genuine trade-off: closures cannot return borrows into the page data. All data needed outside the closure must be copied out. For a 4096-byte page this is not a problem; if profiling ever shows copy overhead as hot, the inner type can expose a cheap `Copy` view type.

Interior mutability via `parking_lot::Mutex` on the cache map. Single-writer assumption means `with_page_mut` is uncontended in the expected case.

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

### 7.4 Connection and session model

The `Database` type is a shared engine handle — it owns the file lock, the page cache, and the writer gate. User code never talks to the pager directly. Instead it goes through short-lived session and transaction handles:

```rust
let db = Database::open(path, options)?;   // shared handle; holds file lock

let session = db.session()?;               // lightweight user context

session.read(|tx| {                        // snapshot at current committed LSN
    tx.get(b"key")
})?;

session.write(|tx| {                       // exclusive; goes through writer gate
    tx.put(b"key", b"value")?;
    Ok(())
})?;
```

Type rules:

| Type | Owns | Lifetime |
|------|------|----------|
| `Database` | file lock, pager, writer gate | process lifetime |
| `Session` | a reference to `Database` | short-lived; per-request or per-caller |
| `ReadTransaction` | LSN snapshot | duration of the read closure |
| `WriteTransaction` | exclusive writer slot | duration of the write closure; commit on `Ok`, rollback on `Err` |

A `ReadTransaction` sees the database at the LSN that was current when the transaction opened. It does not see writes that commit after it opens. This is a snapshot, not a live view.

A `WriteTransaction` goes through the **writer gate** (§7.5). There is always at most one live `WriteTransaction` at a time.

Rationale: separate types for separate roles prevents "I opened a handle somewhere and now the database is haunted." The write closure model also makes it structurally impossible to forget `commit()` — commit is implied by returning `Ok(())`, rollback by returning `Err(...)`.

### 7.5 Writer gate and busy policy

The writer gate serializes all write transactions. Many callers can request writes concurrently; the gate queues or rejects them according to the `BusyPolicy` set at open time.

```rust
pub enum BusyPolicy {
    FailFast,                          // return Err(Busy) immediately
    Wait(Duration),                    // block up to Duration, then Err(Busy)
    Retry { max: u32, backoff: Duration }, // retry with fixed backoff
}
```

`BusyPolicy::FailFast` is the default. Users opt into waiting behavior explicitly — the opposite of SQLite's implicit busy timeout, which surprises people until they read the docs.

Do not implement `BusyPolicy::Queue` (unbounded internal write queue) until Stage 6+. An unbounded queue hides backpressure problems and is a footgun in disguise.

### 7.6 Snapshot reads and LSN visibility

`ReadTransaction` captures the **committed LSN** at open time. All reads within the transaction see data as of that LSN and no later. The writer can advance the LSN without blocking readers.

```rust
let snap = db.snapshot()?;     // shorthand: session.read(...)
let val  = snap.get(b"key")?;
```

Snapshots keep old WAL frames pinned (the checkpoint cannot truncate past the oldest active reader's LSN). Long-lived snapshots cause WAL growth. See §7.7 for how this is surfaced.

### 7.7 Connection introspection

`Database` exposes a diagnostics view. This is the "checkpoint blocked by mystery" problem solved:

```rust
let info = db.connection_info();
// info.active_readers        — count of open ReadTransactions
// info.oldest_reader_lsn     — oldest pinned LSN
// info.writer_queue_depth    — pending write requests
// info.current_writer_age    — how long the current write tx has been open
// info.dirty_page_count      — pages modified but not yet checkpointed
// info.wal_frame_count       — total WAL frames since last checkpoint
// info.last_checkpoint_lsn   — LSN at last successful checkpoint
// info.checkpoint_blocked_by — Some(session_id) if checkpoint is blocked
```

If a checkpoint stalls, the engine can say:

```
Checkpoint blocked by session 8, open for 14m32s (oldest LSN: 882).
```

Not "the file is large because mystery."

### 7.8 Explicit checkpoint API (Stage 3+)

Checkpointing moves committed WAL frames back into the main file and advances the checkpoint LSN. Three modes:

```rust
pub enum CheckpointMode {
    Passive,    // checkpoint whatever frames are not blocked by active readers; never waits
    Full,       // wait for all current readers to close, then checkpoint everything
    Truncate,   // Full + truncate WAL to zero bytes after checkpoint
}

db.checkpoint(CheckpointMode::Passive)?;
```

`checkpoint()` returns a `CheckpointReport`:

```rust
pub struct CheckpointReport {
    pub frames_copied: u32,
    pub frames_remaining: u32,          // frames not checkpointed (blocked by readers)
    pub blocked_by: Option<SessionId>,  // first blocking reader, if any
    pub oldest_blocked_lsn: Option<u64>,
    pub wal_truncated: bool,
}
```

The engine does **not** auto-checkpoint at arbitrary points. Checkpointing is either explicit (via `checkpoint()`) or triggered at `Database::close()`. This keeps behavior predictable — "the WAL grew because no one called checkpoint" is a diagnosable problem, not a mystery.

---

## 8. Cryptography

### 8.1 Threat model

**Invariant:** every database is always encrypted. There is no opt-out. A database without a user-configured protector uses the `Sentinel` protector (machine-generated key, stored in keyslot 0). The sentinel provides full AEAD integrity from byte one; it is not a placeholder or a CRC substitute.

> **Sentinel means always-authenticated, not always-secret.** This distinction is important and must not be blurred. AEAD provides two properties: *integrity* (tampering is detectable) and *confidentiality* (contents are unreadable without the key). Sentinel provides both — *for an attacker who does not have keyslot 0*. Since the Sentinel key is stored in keyslot 0 on the same file, a local attacker who can read the file can read keyslot 0, derive the KEK, unwrap the DEK, and decrypt the database. Sentinel protects against external attackers, file corruption, and bitflip attacks. It does not protect against a local user with read access to the file. **Do not document Sentinel as providing data confidentiality in any user-facing context.** The correct statement: "Tosumu is always authenticated; if you require data confidentiality, add a Passphrase or RecoveryKey protector." This must be stated at `tosumu init` time in the CLI output.

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
- From the DEK, derive three subkeys via HKDF-SHA256 with fixed info strings:
  - `page_key`        = `HKDF(DEK, info = "tosumu/v1/page")`
  - `header_mac_key`  = `HKDF(DEK, info = "tosumu/v1/header-mac")`
  - `audit_key`       = `HKDF(DEK, info = "tosumu/v1/audit")`
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
| `Sentinel` | 1 | Machine-generated 32-byte random key. Stored in keyslot 0 at `init`. Provides full AEAD from day one with no user secret. No KDF — the key is the KEK directly. Intended to be rotated out once a real protector is added. |
| `Passphrase` | 4a | Argon2id over passphrase + per-slot salt. |
| `RecoveryKey` | 4b | 256-bit random secret, shown to user once at init; encoded as a groups-of-6 Base32 string. |
| `Keyfile` | 4b (optional) | Raw 32 bytes read from a file path. |
| `Tpm` | 4c | Platform-backed; seals KEK to a TPM policy. Feature-flagged, not required to build tosumu. |
| `TpmPlusPin` | 4c | Combines a TPM-sealed secret with a user PIN through Argon2id. |
| `AuditProtector` | 7+ | Wraps the `audit_key` independently from the DEK. Enables segregation of duties: a DBA holds the database protector; an auditor holds the `AuditProtector`. Neither role can read or modify the other's domain alone. See §27.3. |

Protectors live behind a trait object; the storage engine never sees protector-specific fields.

### 8.7 Keyslot region (on-disk)

The keyslot region is a contiguous run of `keyslot_region_pages` pages immediately after page 0. It is a flat array of fixed-size **keyslots**. Non-populated slots are zeroed and marked `Empty`.

One keyslot (256 bytes, exact layout TBD during Stage 4a):

| Size | Field | Notes |
|---|---|---|
| 1 | `kind` | 0=Empty, 1=Sentinel, 2=Passphrase, 3=RecoveryKey, 4=Keyfile, 5=Tpm, 6=TpmPlusPin |
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

- **Consistent multi-page rollback is not detected, and per-page AEAD does not change this.** AEAD proves authorship at the claimed `page_version` — it does not prove that the claimed version is the current one. An old authentic page frame (old nonce + old `page_version` + old ciphertext + old tag) still verifies correctly. Detecting staleness requires an independent external anchor: the writer's in-process expected version (safe in verify-after-write), a checkpoint-signed page manifest, a global LSN, or a Merkle root. Without such an anchor, a consistent rollback of old-but-authentic frames is indistinguishable from a current state. This is the standard AEAD bound: authentication proves origin and integrity; it does not prove recency. See §5.3 and §21.10.
- **DEK/KEK split does not protect against a compromised running process.** If malware can read process memory, it has the DEK. Envelope encryption protects *at rest*, not *at runtime*.
- **TPM protector does not imply remote attestation.** Sealing to a TPM policy proves "this machine in this state" locally; it says nothing to a remote verifier. Not a goal.
- **Recovery key secrecy is the user's problem.** If the recovery string is stored next to the database file, the recovery protector adds zero security. Documented in the CLI output at init time.

### 8.11 What is *not* protected

- The *existence* and *size* of the database.
- The number of pages.
- Which pages changed between two snapshots (access pattern leakage).
- The order and timing of writes.
- Anything readable from process memory while the database is open.
- **Data confidentiality when only a `Sentinel` protector is configured.** The Sentinel key is stored on the same file; a local reader with file access can recover the DEK. Sentinel provides authentication (integrity), not secrecy from local readers. See §8.1.

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
- `Busy` — writer gate rejected the request per `BusyPolicy::FailFast`
- `Poisoned` — previous `AuthFailed` or `Corrupt` on this handle; handle is no longer safe to use

No `unwrap` / `panic` on user-controlled input paths. Panics are reserved for "the programmer wrote a bug" invariants.

**Naming principle: commit to the phenomenon, not the mechanism.** Error variant names should describe the observable fact, not the particular mechanism that detected it. `Corrupt { pgno }` describes the phenomenon (this page cannot be correctly read). `AuthFailed { pgno }` describes the detection mechanism (AEAD authentication failed). Both are available; the phenomenon-name is preferable when the same observable fact could arise from multiple mechanisms, because it does not over-commit the API to a specific causal story that might need to change.

Examples:
- `WrongKey` is correct: the phenomenon IS that the key did not match — there is nothing more primitive to name.
- `Corrupt { pgno }` is correct: corruption is the phenomenon; AEAD failure is one way to detect it.
- `AuthFailed { pgno }` is appropriate for a variant specifically about AEAD tag failure, where the caller may want to distinguish "the tag was missing" from "the file is garbage." But mixing auth-mechanism names with phenomenon-names in one flat enum creates ambiguity.

The practical rule: if a variant name implies a specific implementation mechanism, ask whether the variant should be renamed to describe the observable symptom, or whether a sub-variant structure (a nested `CorruptReason` enum) better separates the phenomenon from the diagnosis.

### 9.2 Error taxonomy

The flat variant list above can be classified into five categories. Knowing which category an error belongs to determines how the caller should respond:

| Category | Variants | Caller response |
|----------|----------|-----------------|
| **Io** | `Io(std::io::Error)` | OS said no. Could be transient (disk full, network blip) or permanent (permission, removed device). Caller decides whether to retry. Never silently discard. |
| **Corruption** | `Corrupt`, `KeyslotTampered`, `VersionMismatch`, `NewerFormat` | On-disk data is inconsistent or unrecognisable. Not safe to continue operating on this file. Surface to user with path context. |
| **AuthFailure** | `AuthFailed`, `WrongKey`, `NoProtectorAccepted` | Cryptographic authentication failed or no valid key. Distinct from corruption: the file may be intact but the key is wrong. User-actionable. |
| **LogicInvariant** | `InvalidArgument`, `TxnConflict`, `OutOfSpace` | The caller did something the engine cannot satisfy given current state. The database itself is fine. Caller fixes their usage. |
| **Busy** | `Busy` (from `BusyPolicy::FailFast`) | Another writer holds the gate. Caller should back off or wait with `BusyPolicy::Wait`. |

**Migration errors** (`MigrationRequired`, `MigrationFailed`) straddle Corruption and LogicInvariant. `MigrationRequired` is a LogicInvariant (the caller must choose to migrate). `MigrationFailed` is effectively a Corruption (the file may be in a partial state; treat as unsafe to continue).

### 9.3 What crashes vs what bubbles

The "no silent corruption" principle (§2) implies many loud failure paths. This is the policy:

**Panics (`unreachable!` / `panic!` / debug assertions)** — reserved for programmer bugs: invariants that cannot be violated by any valid input, only by code that was written wrong. Examples:
- An internal enum arm that should be unreachable given earlier validation
- A `PageNo(0)` appearing as a B+ tree child pointer (caught by `DataPageNo(NonZeroU32)` — §28.2)
- A cached page whose length is not 4096 bytes

Panics are **not** appropriate for:
- I/O errors (disk could fail)
- AEAD failures (file could be tampered)
- Wrong passphrase (user could mistype)
- Out of space (disk could be full)

**Errors that bubble to the caller** — everything caused by external state: I/O, cryptography, format version, key material, busy state, caller logic errors. The caller decides whether to retry, prompt the user, abort, or log.

**Errors that are fatal to the session** — `AuthFailed { pgno }` and `Corrupt { pgno }` indicate the database file cannot be trusted. After either of these, the `Database` handle should be treated as poisoned. Reading further pages from it is not safe. The engine closes the file and all subsequent operations on that handle return `Err(Poisoned)` until the handle is dropped and re-opened.

```rust
// Conceptual (Stage 2+): poisoned state propagation
match db.read(|tx| tx.get(b"key")) {
    Err(TosumError::AuthFailed { pgno }) => {
        // The handle is now poisoned. Log, alert, do not continue.
    }
    Err(TosumError::Io(e)) => {
        // Could be transient. Caller decides.
    }
    _ => { ... }
}
```

The `Poisoned` state itself is not stored in an error variant — it is stored in the `Database` struct. Subsequent calls return `Err(TosumError::Poisoned)` without touching the file.

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
│   ├── v1_sentinel.tsm        # known-good DB from Stage 1 (sentinel protector, no passphrase)
│   ├── v2_with_btree.tsm      # known-good DB from Stage 2
│   └── v3_passphrase.tsm      # known-good DB with passphrase protector
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
2. **Migration testing:** Start with a `v1_sentinel.tsm`, run migration, verify output matches `v2_expected.tsm`.

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
**Explicitly not there:** no page format, no B+ tree, no crash safety. (Sentinel AEAD is deferred to MVP +1 when the real page format lands.)

#### MVP +1 — "It has a real format" *(Stage 1 storage)*

Replace the append-only log with the real on-disk format from §5: file header, 4 KB pages, slotted layout, freelist.

- File header with magic `TOSUMUv0`, `format_version`, `min_reader_version`.
- Slotted leaf pages (§5.4). Linear scan across all leaf pages for `get`/`scan`.
- Freelist for page reuse after delete.
- CLI: `init`, `put`, `get`, `scan`, `stat`, `delete`.
- Property tests for page encode/decode round-trip.

**Proves:** on-disk format works. Pages are a real concept. Reopen is deterministic.
**Demo:** `tosumu init db.tsm && tosumu put db.tsm k v && tosumu stat db.tsm` shows 1 record, 1 page.
**Explicitly not there:** no B+ tree (linear scan only), no WAL, no user-configured passphrase (sentinel only).

#### MVP +2 — "It's inspectable" *(Stage 1 debug trio)*

The debug tooling from §12.3. Without it, debugging MVP+3 onward is guesswork.

- `tosumu dump <path> [--page N]` — pretty-print header and page contents.
- `tosumu hex <path> --page N` — raw hex+ASCII dump with annotations.
- `tosumu verify <path>` — walk every page, report anomalies, exit non-zero on any.
- Fuzz target: `fuzz_page_decode` — arbitrary 4 KB blobs must not panic.

**Proves:** "no silent corruption" principle (§2.4) works end-to-end.
**Demo:** Hand-edit a byte in a page with a hex editor → `tosumu verify` reports it.
**Explicitly not there:** no interactive viewer (that's MVP+8).

#### MVP +3 — "It scales past linear scan" *(Stage 2 B+ tree)*

Replace linear scan with a B+ tree index. Enables range scans in sorted order.

- Internal pages, splits, lazy deletes (merge in MVP+7 if needed).
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
**Explicitly not there:** no user-configured passphrase (sentinel only until MVP +6), no multi-reader concurrency.

#### MVP +5 — "It can't be lied to" *(Stage 3 correctness harness)*

Fault injection, structural invariant checker, and property-based crash testing. Proves the system maintains correctness guarantees under adversarial write failures — not just under clean-close conditions.

- `BTree::check_invariants()`: DFS walk verifying page types, slot offsets, separator routing, uniform depth, leaf-chain order, no duplicate live keys. (Half-occupancy deferred until delete/merge rebalancing exists.)
- `CrashWriter` harness (`test_helpers.rs`): phase-based `Write + Seek` wrapper that injects `BrokenPipe` at five precise phases — `BeforeWrite`, `MidWrite { fail_after_bytes }`, `AfterWrite`, `DuringTruncate`. Shared across all crate-internal crash tests.
- WAL append crash tests: crash mid-PageWrite record, crash after PageWrite with no Commit, crash mid-Commit record. Each verifies old state is preserved (no partial transaction applied).
- Named invariant: **"WAL is never truncated unless apply succeeded"** — proven by construction: `checkpoint()` calls `recover()` first; if `recover()` fails, `set_len(0)` is never reached.
- `prop_btree_ops_invariants_always_hold` (proptest, 64 cases): random `put`/`delete` sequences with narrow key alphabet; `check_invariants()` called after every operation; final scan matched against BTreeMap model.
- Fuzz target: `fuzz_btree_crash_boundaries` — commits real transactions, truncates WAL at `crash_seed % wal_size`, reopens, asserts `check_invariants()` passes and no `AuthFailed`.
- `tosumu verify` extended: structural invariant check runs after page AEAD walk passes.
- `pub DEFAULT_MAX_RETRIES`, `open_file_retrying_n()`: retry budget made externally configurable; mutex-poison cascade in fault-injection tests fixed.

**Proves:** the engine cannot be left in a half-written state by a crash at any WAL write site. Correctness is checkable by machine, not just by eye.
**Demo:** Run `fuzz_btree_crash_boundaries` with arbitrary byte input — no panic, no `AuthFailed`, `check_invariants()` always passes after recovery.
**Explicitly not there:** no delete/merge rebalancing (so half-occupancy invariant deferred), no multi-writer crash testing.

#### MVP +6 — "It's encrypted" *(Stage 4a — single protector)*

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

#### MVP +7 — "Key management works" *(Stage 4b — multiple protectors)*

Multiple protectors, recovery key, cheap KEK rotation.

- Up to 8 keyslots. Any one can unlock.
- **RecoveryKey** protector with one-time Base32 display at init (§10.5 footgun: require confirmation).
- Optional **Keyfile** protector.
- CLI: `tosumu protector add|remove|list`.
- `tosumu rekey-kek` (fast — rewraps DEK only).
- `tosumu rekey-dek` (slow — rewrites all pages; may slip to MVP+11).
- Tests: protector-swap attack must fail (§8.7 AAD binding).

**Proves:** real-world key management scenarios work. Lost passphrase doesn't mean lost data.
**Demo:** Add recovery key, delete passphrase slot, unlock with recovery key.
**Explicitly not there:** no TPM, no mobile key storage.

#### MVP +8 — "It's interactively inspectable" *(Stage 2–4 TUI viewer)*

Interactive TUI viewer (§12.4). Can slot in any time after MVP+2, but most valuable after MVP+6 when encrypted DB inspection becomes interesting.

- `tosumu view <path>` — ratatui + crossterm TUI.
- Views: file header, page list, page detail, B+ tree structure, WAL records, verification.
- Encrypted DB views (after MVP+6): protector summary, keyslot detail, per-page auth status.
- Keyboard navigation, colorized output, watch mode, read-only.

**Proves:** the "storage engine autopsy table" aesthetic (§12.4).
**Demo:** `tosumu view db.tsm` → navigate pages → see B+ tree visually → spot corrupt page highlighted red.
**Explicitly not there:** no write operations, no query builder, no remote connections.

#### MVP +9 — "It speaks SQL (toy)" *(Stage 5 query layer)*

Minimal query layer. Proves the engine supports relational-style workloads.

- Parser for `CREATE TABLE`, `INSERT`, `SELECT ... WHERE key = ?`.
- System catalog page: `(rootpage, name)` entries per table.
- Single-column primary key. No joins, no planner, no optimizer.
- CLI: `tosumu sql <path> "SELECT * FROM users WHERE id = 42"`.

**Proves:** the storage engine is a real foundation for query languages.
**Demo:** `CREATE TABLE users (id, name); INSERT INTO users VALUES (1, 'alice'); SELECT * FROM users WHERE id = 1`.
**Explicitly not there:** no joins, no GROUP BY, no aggregates, no transactions over SQL (use library API).

#### MVP +10 — "Multiple readers" *(Stage 6 — MVCC snapshots)*

Multi-reader concurrency without blocking writes.

- MVCC snapshot by LSN (read transactions see a fixed point-in-time view).
- Single writer, multiple concurrent readers.
- Secondary indexes (additional B+ trees mapping `(secondary_key, primary_key)`).
- `VACUUM` command — reclaim space from deleted records.
- Benchmarks vs SQLite on toy workloads (§11.11).

**Proves:** real concurrency works. Read-heavy workloads don't block writers.
**Demo:** 10 reader threads scanning while 1 writer inserts — no contention, no stale errors.
**Explicitly not there:** no multi-writer, no distributed concurrency.

#### MVP +11 — "It runs on mobile" *(Stage 7 — iOS/Android)*

Per §19, mobile support with hardware-backed key storage.

- **MVP +11a:** C FFI layer (`tosumu-ffi`) with Swift/Kotlin bindings.
- **MVP +11b:** iOS wrapper with `IosKeychainProtector` (Secure Enclave).
- **MVP +11c:** Android wrapper with `AndroidKeystoreProtector` (Keystore API).

**Proves:** the engine is portable to constrained platforms with hardware crypto.
**Demo:** iOS demo app reads/writes encrypted tosumu DB with biometric unlock.
**Explicitly not there:** no iCloud sync, no cross-device replication, no web assembly target.

#### MVP +12 — "It runs in a cluster" *(Stage 8+ — witness/observer on K3s)*

Deploy the three-server witness model (§23.4) and local observer model (§23.6) as containerised workloads on a lightweight Kubernetes cluster. K3s is the reference target: single-binary, runs on resource-constrained hardware, close enough to production Kubernetes to be meaningful.

- `tosumu-server` as a Deployment with a PersistentVolumeClaim for the DB file.
- `tosumu-witness` as a StatefulSet across three nodes; each witness stores signed receipts in its own PVC.
- `tosumu-observer` as a sidecar container in the `tosumu-server` Pod communicating over a shared Unix socket (emptyDir volume mount).
- Health status surfaced via Kubernetes readiness and liveness probes: `Healthy` → probe passes; `RollbackSuspected` / `AuditChainBroken` → readiness probe fails, pod taken out of rotation.
- Helm chart or kustomize overlay for the full topology.

**Proves:** the audit and witness layers work in a real multi-node deployment. Rollback detection triggers correctly when a stale PVC snapshot is swapped in.
**Demo:** Take a volume snapshot of the DB PVC at LSN 800. Let it advance to LSN 950. Restore the snapshot. `tosumu-cli status` reports `RollbackSuspected`; witnesses confirm the disagreement; server refuses writes.
**Explicitly not there:** no automatic failover, no multi-writer consensus, no Raft. Witnesses are auditors, not replicas.

#### MVP increment summary table

| MVP | Ships | Proves | Maps to stage | Status |
|-----|-------|--------|---------------|--------|
| 0 | Append-only log, in-memory index | I/O works, binary runs | pre-Stage 1 | ✅ done |
| +1 | Slotted pages, file header, freelist | On-disk format works | Stage 1 storage | ✅ done |
| +2 | `dump` / `hex` / `verify`, fuzz page decode | No silent corruption | Stage 1 debug | ✅ done |
| +3 | B+ tree, range scans, overflow pages | Real DB lookups | Stage 2 | ✅ done |
| +4 | Transactions, WAL, recovery, retry-on-lock | Durability | Stage 3 | ✅ done |
| +5 | `CrashWriter`, `check_invariants`, proptest, crash-boundary fuzz | No partial transactions under crash | Stage 3 correctness | ✅ done |
| +6 | Passphrase-encrypted DB, Argon2id, KATs | Crypto works end-to-end | Stage 4a | 🔜 next |
| +7 | Multiple protectors, recovery key, KEK rotation | Key management works | Stage 4b | |
| +8 | TUI viewer (`tosumu view`) | Interactive inspection | Stage 2–4 crosscut | |
| +9 | Toy SQL (`CREATE TABLE`, `SELECT`) | Real query foundation | Stage 5 | |
| +10 | MVCC readers, secondary indexes, `VACUUM` | Concurrency | Stage 6 | |
| +11 | iOS/Android FFI, Keychain/Keystore | Mobile portability | Stage 7 | |
| +12 | K3s cluster: server + witnesses + observer sidecar | Audit/witness in real deployment | Stage 8 | |

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

**Why explicit versioning and a stable primitive set matter: the Wilkins lesson.**  John Wilkins (1668) built *An Essay Towards a Real Character, and a Philosophical Language* — a system where every word encoded its position in a taxonomy of concepts. When the taxonomy changed, all vocabulary had to change with it. The language was obsolete before it was finished.

Tosumu applies the same lesson. The on-disk page layout, AEAD construction, and keyslot format are the primitive roots. Once locked at the end of Stage 2, they are stable by policy. New features grow by composition on top of them: new `KeyProtector` implementations, new index types, new CLI commands, new metadata fields in reserved header space. The `format_version` bump is the signal that a primitive has changed — and the migration system, backup policy, and verifier suite exist to handle those controlled exceptions without discarding everything built on top.

A large format built on an unstable foundation requires wholesale revision. Lock the primitives first; grow the vocabulary forward.

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

**The plan is a correction-pivot, not an inspection.** `plan().preflight().apply().verify()` does not re-examine the old state and ask "is this still valid?" — it asserts "the previous format is denied; the replacement is format N." The old state is named exactly once, in `plan.explain()` output. After `apply()` succeeds, the pre-migration format version does not exist in this file. `verify()` confirms the replacement, not the original.

This means rollback is not "undo apply" — it is "apply failed," which surfaces as a typed error. If `apply()` returns `Err`, the copy-and-swap strategy (§13.4-A) ensures the original file is intact. There is no partial-migration state where the old format and new format coexist in a single live file.

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

**Source of truth vs. derived artifacts.** DESIGN.md is the hand-authored source of truth. The codebase is derived from it. Before Stage 2 is complete and the on-disk format is locked, DESIGN.md wins when it conflicts with the implementation — the implementation follows the design, not the other way around. Discrepancies are bugs to fix, not justification for retroactive spec updates.

After Stage 2, the relationship partially inverts in one direction: the implemented and tested on-disk format is the ground truth for that format version, and DESIGN.md must be kept in sync with it. Format documentation that diverges from the actual bytes on disk is worse than no documentation.

The same rule applies to generated artifacts: files produced by a build pipeline are never hand-edited. Hand-edits create divergence that cannot be detected and will be silently overwritten on the next build run.

---

## 15. Open questions

These are tracked here, not silently deferred.

1. **Page size.** 4 KB is the obvious default. Do we want to make it configurable at `init` time for experimentation (e.g. 8 KB, 16 KB)? *Tentative: yes, settable at init, immutable after.*
2. **Endianness on disk.** Little-endian hardcoded. Any reason to revisit? *Tentative: no.*
3. ~~**Varint flavor.**~~ **Closed.** LEB128, unsigned. See §12.2.
4. ~~**Checksum vs MAC for unencrypted mode.**~~ **Closed.** There is no unencrypted mode. All pages use AEAD. The `Sentinel` protector (§8.6) covers Stages 1–3 before user-configured protectors exist. CRC32C is not needed.
5. **WAL in separate file vs embedded.** Starting with a separate `tosumu.wal` file. Embedded WAL (SQLite-style) is possible later but adds complexity.
6. **Free page zeroing.** Do we zero freed pages on disk? *Tentative: yes (always encrypted, always cheap).*
7. **Pager API shape.** References-with-lifetimes vs. closure/handle-based. Default is references; escape hatch documented in §6.2. Decision deferred to Stage 2.
8. **Global LSN in AEAD AAD.** Would close the consistent-multi-page-rollback gap in §5.3. Cost: every write bumps a global counter that must be durable before the write lands. Deferred to Stage 6.
9. **Keyslot count default.** 8 slots = 1 page at 256 B/slot + header overhead, which is plenty. Bigger means wasted space; smaller means rotation is annoying. *Tentative: 8 slots, fixed at init.*
10. **TPM library choice.** `tss-esapi` (cross-platform but Linux-centric) vs. platform-native (`windows` crate TBS bindings on Windows). *Tentative: `tss-esapi` for portability; revisit in Stage 4c.*
11. **`dek_id` in page AAD.** Including it would enable safe incremental rekey but breaks every existing page on DEK rotation. §8.8 currently says no; revisit if online rekey becomes a goal.
12. **Default `auto_migrate_policy`.** Ship with auto = {metadata-only, keyslot-metadata}. Should page-local rewrite ever be auto under a size threshold (e.g. <1 MB file)? *Tentative: no. Explicit is safer and consistent.*
13. **Backup retention.** Do we cap the number of `.pre-v{N}.bak` files we leave behind? *Tentative: no. Engine never deletes backups; that’s the user's call per §13.5.*

---

## 16. Definition of done (per stage)

> **Design status: FROZEN as of 2026-04-24.**
> §§1–28 are the complete design. No new philosophy sections. The next thing written in this repository is code: `tosumu init` writing a file header, AEAD-encrypting a sentinel-protected DEK, and a test that corrupts the ciphertext and watches authentication fail. Start there.

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

### 17.1 Tofeka and epistemic boundary

Two related terms from the same language appear throughout the design and inform how Tosumu classifies state validity:

| Written | Parse | Meaning | Application |
|---|---|---|---|
| `tofe` | `to-fe` | epistemic boundary — the line where evidence meets claim | The pager boundary (§4) is a structural `tofe` |
| `tofeka` | `to-fe-ka` | epistemic boundary crossing by **intentional action** — deliberate misrepresentation | The failure mode being prevented |
| `tofeki` | `to-fe-ki` | epistemic boundary crossing by **passive change** — accidental overclaiming | A correctable error; lower stakes |

In the Tonesu system, `fe` is the root for physical limits, danger thresholds, and category edges. A false knowledge claim and a structural-engineering failure are the same kind of event: a boundary was violated.

**Tosumu's design goal, restated in these terms:** make `tofeka` structurally impossible at each layer, and make `tofeki` immediately detectable.

- AEAD prevents claiming a page is authentic without verifiable proof (`si → to` gate cannot be skipped).
- The WAL and fsync discipline prevents claiming a write is durable without an OS contract (`to → tosu` gate).
- The witness model (§23) prevents claiming state is current without an external anchor.
- `#[forbid(unsafe_code)]` prevents claiming the memory model is safe without compiler verification.

Each of these is not a warning in documentation — it is a structural constraint. The goal is to make the dangerous claim unrepresentable, not to advise against it. This is §2 principle 8 expressed in Tonesu terms.

**Implementation note.** Do not use `tofeka` as a variant name, type name, or error identifier in code. Future maintainers should not need to learn the conlang. Use `AuthFailed`, `FreshnessViolation`, `StateInconsistency` in code. Use the tofeka vocabulary to *design* the system and *discuss* it; use English to *implement* it. See §29 for the full epistemic model this vocabulary names.

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

### 18.6 Stage 5+ query layer design notes

These are design constraints for the eventual `tosumu-query` crate, captured here so they don't get rediscovered the hard way.

**The core query primitive is a `RowSet`.**

Indexes don't return rows directly — they return sets of row identifiers. Query operations are then set operations:

| Query construct | Set operation |
|-----------------|---------------|
| `AND` | intersection |
| `OR` | union |
| `NOT` | difference |
| `JOIN` | indexed nested-loop lookup |
| `UNION` | merge (if both streams sorted) or materialize + dedupe |
| `INTERSECT` | intersection |
| `EXCEPT` | difference |

A `RowSet` can be a sorted iterator, a temporary materialized list, or (eventually) a bitmap. The query layer composes them; the storage layer knows nothing about them.

**ASTs describe intent. Plans describe execution.**

There is a mandatory translation step:

```
query AST (what the user wrote)
     ↓
plan tree (what the engine will do)
     ↓
execution (set operations against RowSets)
```

Example: `WHERE (status = 'open' OR priority = 'high') AND customer_id = 42`

```
intersect(
  union(
    index_scan(status_idx, 'open'),
    index_scan(priority_idx, 'high')
  ),
  index_scan(customer_idx, 42)
)
```

The plan tree is a first-class value — it can be inspected, explained, and logged before execution begins.

**OR rewrites to union of index scans when possible.**

A naive OR triggers a full table scan. A smart OR triggers two index scans + a RowSet union. The query planner should detect when all OR terms have covering indexes and rewrite accordingly. If only some terms are indexed, the planner chooses full scan and emits an explain warning — it does not silently degrade.

**Joins are index-driven or explicit.**

For Stage 5, only two join strategies are supported:

1. **PK lookup join:** For each row in the outer table, look up the inner table by primary key. Requires the join column to be the inner table's PK.
2. **FK index join:** For each outer PK, range-scan the hidden FK index (`_fkidx:table:column:{val}:*`). Requires a hidden FK index to exist.

Any other join pattern is rejected with an explicit error — not silently degraded to a nested-loop full scan.

**Hidden FK indexes serve double duty.**

An FK constraint (`orders.customer_id → customers.id`) auto-creates:

```
_fkidx:orders:customer_id:{customer_id}:{order_id}  →  ∅
```

This index is used both for FK enforcement (delete customer → range scan for referencing rows) and for join execution (join customers ↔ orders on customer_id → range scan FK index). Two birds, one index.

**Expensive operations explain themselves and degrade predictably.**

When the planner cannot use indexes, it says so:

```
Warning: OR condition cannot use indexes.
  notes CONTAINS "urgent" has no index.

Plan will scan 42,318 rows.
Consider: CREATE INDEX notes_text ON orders(notes).
```

This fits guiding principle 7 (declarative intent, imperative mechanics): the plan describes what will happen before it happens. Surprises are for production incidents, not query plans.

**Implementation order for Stage 5+:**

1. PK point lookup
2. Secondary index point lookup
3. `AND` as RowSet intersection over indexed columns
4. `OR` as RowSet union over indexed columns (with full-scan fallback + warning)
5. Simple nested-loop join over PK or FK index
6. `UNION` via sorted RowSet merge
7. `EXPLAIN` output (plan tree → human-readable text)
8. Query statistics (row counts, cardinality estimates) — only after 1–7 work

Do not start with arbitrary joins, subqueries, or aggregates.

**The stupid-but-safe planning rule:**

```
If indexed equality available   → use index
Otherwise                       → scan + emit warning

If all OR terms indexed          → union of index scans
If any OR term unindexed        → full scan + emit warning

If join has indexed inner side  → nested-loop index join
Otherwise                       → reject with descriptive error
```

"Reject with descriptive error" is better than "silently do something terrible." Mature systems know what they cannot do.

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

## 21. Storage location policy and network filesystem safety

SQLite's WAL documentation states explicitly: all processes sharing a WAL-mode database must be on the same host. WAL uses shared memory for coordination; it does not work reliably over network filesystems. This is the root of most "SQLite got weird on `//server/share`" corruption stories — not a bug in SQLite, but a mismatch between the engine's assumptions and the storage layer beneath it.

Tosumu makes the same assumption (single host, single process) and enforces it rather than relying on users to read the docs.

### 21.1 Storage location policy

Four modes, set at open time:

| Mode | Behavior | Default for |
|------|----------|-------------|
| `Local` | Normal operation. Refuses to open if path looks like a network filesystem. | library |
| `NetworkWarn` | Opens on a network path, prints a loud warning, applies conservative rules (§21.3). | CLI |
| `NetworkStrict` | Same as `NetworkWarn` but refuses if the lock probe (§21.6) detects unreliable locking. | explicit opt-in |
| `NetworkDeny` | Refuses all network paths with no override. | library, high-security contexts |

**CLI default is `NetworkWarn`** — users will put databases on network shares regardless, so the right behavior is: allow it, say so loudly, and apply conservative rules. Silent is how support tickets are born.

**Library default is `Local`** — code that calls `Database::open` directly should fail-fast and force the caller to acknowledge the risk. Library callers can opt in with `NetworkPolicy::WarnAndExclusive` or `NetworkPolicy::AllowUnsafe` (§21.4).

`NetworkDeny` is for deployments that want to guarantee no network storage is ever used, regardless of what the caller passes.

### 21.2 Network path detection

On open, tosumu inspects the path before acquiring any lock:

- **Windows UNC paths:** `\\server\share\...`
- **Mapped network drives:** Query the drive type via OS API (`GetDriveType` → `DRIVE_REMOTE`).
- **POSIX:** Check the filesystem type from `/proc/mounts` or `statfs()`; flag known network types: `nfs`, `cifs`, `smb`, `smbfs`, `nfs4`, `fuse.sshfs`, `glusterfs`, `ceph`.
- **Docker bind/shared mounts:** Detectable on Linux via `/proc/self/mountinfo`; best-effort on other platforms.

If detection is uncertain, log a warning rather than refusing outright — false positives on unusual local filesystems would be worse than missing some network cases.

When a network path is detected:

```
WARNING: database appears to be on a network filesystem:
  \\server\share\data.tsm

tosumu is designed for local storage. Network filesystems may have unreliable
locking, caching, and fsync semantics. Concurrent access from multiple machines
may corrupt data or cause stale reads.

Recommended:
  run tosumu-server on the machine that owns the file
  or copy/checkout the database locally

Continuing in exclusive network mode. To suppress: --network-mode=warn
To refuse network paths: --network-mode=deny
```

In `Local` or `NetworkDeny` mode, this becomes a hard error:

```
Error: NetworkFilesystemDetected
  Path: \\FILESERVER\shared\app.tsm
  Use --network-mode=warn to allow with warning.
  Use 'tosumu checkout' to create a local working copy.
```

### 21.3 Network strict / warn mode conservative rules

When `NetworkWarn` or `NetworkStrict` mode is active, tosumu applies conservative rules:

- Holds an **exclusive OS file lock for the entire open lifetime** (not just during writes).
- Disables WAL reader sharing. No concurrent readers from other processes.
- All writes use `fsync` aggressively (no lazy flushing).
- Checkpoints before close.
- No background WAL growth — checkpoint is called after every commit above a low threshold.
- Writes the owner lock file (§21.5).
- Optionally: **verify-after-write** — after each commit, re-reads the written page(s) and verifies the AEAD tag. This catches silent write corruption from unreliable network storage. It is slower; it is opt-in; it is the correct trade-off for a database on a network share.

```rust
OpenOptions {
    network_verify_writes: bool,  // default: false; recommended: true in NetworkWarn/Strict mode
    ...
}
```

This is slower. That is the price of the life decision that put the database on a network share.

This is slower but predictable. Explicitly single-process, single-machine, stored-on-a-network-path. Not multi-machine concurrent access. `NetworkStrict` additionally refuses if the lock probe (§21.6) finds unreliable locking behavior.

### 21.4 Library API — `NetworkPolicy`

```rust
pub enum NetworkPolicy {
    /// Refuse to open on any detected network path. (library default)
    Deny,
    /// Allow network paths; print warning; apply conservative rules.
    WarnAndExclusive,
    /// Allow network paths without warning. Caller acknowledges the risk.
    /// Named honestly so callers type the shame.
    AllowUnsafe,
}

OpenOptions {
    network_policy: NetworkPolicy,  // default: NetworkPolicy::Deny
    ...
}
```

The option is named `AllowUnsafe`, not `Allow`. The name is the warning.

### 21.5 Owner lock file

In any network mode, tosumu writes an advisory lock file alongside the database:

```
data.tsm.lock
```

Contents:

```json
{
  "host":       "DESKTOP-17",
  "pid":        1234,
  "session_id": "01H...",
  "opened_utc": "2026-04-24T10:42:00Z",
  "mode":       "network-exclusive"
}
```

This is not security. Not correctness. It is human-readable evidence for the inevitable "why is my database locked" conversation.

`tosumu stat` includes it:

```
Storage location:   \\server\share\data.tsm
Filesystem:         network (SMB detected)
Mode:               network-exclusive (NetworkWarn)
Risk:               elevated
Locking confidence: low  (advisory only; SMB lock semantics unreliable)
Owner lock:         DESKTOP-17 pid 1234, opened 2026-04-24T10:42Z
```

When another process opens the same path and finds a lock file, it warns:

```
Warning: data.tsm was last opened by DESKTOP-17 pid 1234 at 10:42 UTC.
The lock may be stale if that session ended without cleanup.
Proceed? [y/N]
```

Not silent. Not automatic. User decides. Even though users will press Y immediately and skate on the wet floor anyway.

### 21.6 Lock probe

Before opening in any mode, tosumu creates a lock probe file (`<db>.lockprobe`) and tests whether OS-level file locking behaves as expected:

1. Create probe file.
2. Acquire exclusive lock.
3. Verify lock is visible to a second file descriptor.
4. Release. Clean up.

If lock behavior appears unreliable (probe acquire fails, or a second open unexpectedly succeeds without blocking), emit `NetworkLockUnreliable` and refuse unless `--force` is passed.

The probe is a fast, best-effort heuristic, not a guarantee. Its value is catching obviously broken environments (some NFS configurations, Samba with `oplocks=no`) rather than certifying all network paths safe.

### 21.7 CLI surface

```
tosumu open <path>                         # CLI default: NetworkWarn
tosumu open <path> --network-mode=warn    # allow + warn (CLI default)
tosumu open <path> --network-mode=strict  # warn + refuse if lock probe fails
tosumu open <path> --network-mode=deny    # hard refuse on network paths

tosumu checkout <path> [--dest <local>]   # copy to local, write advisory lock
tosumu publish  <path> --from <local>     # atomic write-back to network path

tosumu copy   <src> <dst>                 # safe copy: flush + checkpoint first
tosumu backup <path>                      # snapshot via copy-and-fsync
```

`copy` and `backup` always flush and checkpoint first — they do not copy a live database while the WAL contains uncommitted frames. Dragging a `.tsm` file without its WAL is a classic data loss pattern; these commands make the safe operation the easy operation.

### 21.8 Design principle

Three tiers of reality, in order of correctness:

```
1. Local mode       — correct, fast, safe. The design target.
2. Server mode      — correct, multi-user. The recommended path for network access.
3. Network file mode — tolerated, single-user, degraded. For the chaos goblins.
```

The goal is not to stop users from doing tier 3. It is to:

```
detect it
warn loudly
degrade safely
give them a better path
```

So when it breaks, it says: **"this was a bad idea"** — not **"tosumu randomly ate my data."**

**Network file mode must never evolve into a poor man's server mode.** The moment it becomes plausible to run three processes against the same network-share database and have it "mostly work," people will do that, corrupt their data, and the reputation damage accrues to Tosumu. The conservative rules (exclusive lock, single-process, no WAL reader sharing) are not limitations to be lifted — they are the fence that keeps tier 3 from creeping into tier 2's territory.

Tosumu is **local-first**. Network paths are supported through explicit, conservative, single-user modes, not by pretending a network filesystem is a local disk. Most embedded database corruption on network paths is not a bug in the database — it is a mismatch between assumptions and environment, and the database was silent about it. Tosumu is not silent about it.

### 21.9 Additional network mode safeguards

Beyond the core conservative rules, these measures help when someone does make the bad decision:

**Verify on open.**  
Before beginning any session in network mode, run a fast page-MAC sweep of the file. If any page fails verification, refuse to open and report `CorruptionDetectedOnOpen`. The file may have been corrupted by a previous session, a network glitch, or another process. Fail before the session starts, not after the first write makes things worse.

**Mtime watchdog.**  
After open, periodically stat the database file and compare mtime/size to what tosumu expects. If the file changes in a way tosumu did not cause — another process wrote to it — immediately suspend the session and emit `FileModifiedExternally`. Do not attempt to continue. This is the "two processes on the same network share" scenario; it should be loud and fatal, not silent and corrupting.

**Lock file heartbeat.**  
The owner lock file (§21.5) gets a `last_heartbeat_utc` field updated every N seconds. Stale lock detection becomes: if `last_heartbeat_utc` is more than 2× the heartbeat interval in the past, the lock is probably stale. Without a heartbeat, "stale" is a guess; with one, it is a measurement.

```json
{
  "host":               "DESKTOP-17",
  "pid":                1234,
  "session_id":         "01H...",
  "opened_utc":         "2026-04-24T10:42:00Z",
  "last_heartbeat_utc": "2026-04-24T10:55:30Z",
  "heartbeat_interval_secs": 30,
  "mode":               "network-exclusive"
}
```

**Periodic lock re-probe.**  
Some NFS/SMB implementations silently drop locks after a network partition or server restart. After open, re-run a lightweight version of the lock probe (§21.6) every N minutes. If the lock appears to have been lost, suspend writes immediately and emit `LockLost`. Do not continue writing to a file you may no longer exclusively own.

**Network I/O error handling.**  
Network filesystems can return errors that local filesystems never do: `EIO`, `ENETDOWN`, `ECONNRESET` on an `fsync` or `write`. In local mode these are catastrophic hardware failures. In network mode they may be transient. When these errors occur:
- Immediately suspend the session — no further writes.
- Emit `NetworkIoError` with the raw OS error code.
- Do not attempt transparent retry. The database state is unknown.
- The WAL remains intact; recovery is possible once the network is restored and the user explicitly re-opens.

**Session close summary in network mode.**  
On close, print a one-line summary to stderr:

```
tosumu [network-exclusive] closed: 42 writes, 42 fsyncs, 42 verify-after-write OK, 0 errors.
backup recommended: data.tsm.pre-session.bak not found.
```

This gives the user a paper trail. When something goes wrong later, "I got zero errors at close" is useful diagnostic information. When no backup exists, say so.

**Recommend server mode after repeated use.**  
If tosumu detects that the same database file on a network path has been opened more than N times across different sessions (tracked in the migration history page, §13.12), emit a one-time advisory:

```
Advisory: this database has been opened 25 times from a network path.
Consider running tosumu-server on the host that owns the file for safer multi-session access.
Suppress: set network_server_advisory = false in config.
```

Not a nag. Once. Suppressible. The right thing.

### 21.10 Using per-page AEAD as the network integrity mechanism

Every Tosumu page already carries a ChaCha20-Poly1305 authentication tag (§8.4). The AAD binds `pgno || page_version || page_type` — so decryption failure means not just "these bytes are wrong" but **"this specific page, at this version, was not written by this database engine with this key."**

On a network filesystem this is more valuable than a plain checksum. A CRC tells you bytes changed. AEAD tells you tosumu didn't write what it's now reading. Those are different diagnoses.

**What AEAD catches on a network path that a plain checksum doesn't:**

| Scenario | CRC/checksum | AEAD |
|----------|-------------|------|
| Bit flip in transit | detects | detects |
| Silent partial write (NFS trailing zeros) | detects if zeros change CRC | detects |
| Stale read from NFS client cache | may not detect (cache has valid CRC) | detects **only if** writer holds expected `page_version` and checks it after re-read (old complete frame still verifies) |
| Page swap between databases (same app, different files) | misses (bytes are valid) | detects (DEK is different) |
| Page rollback (old valid page reinserted) | misses (bytes are valid) | detects **only if** checked against a trusted version anchor (LSN, checkpoint manifest); old frame with old tag still verifies |
| External write that happens to produce valid CRC | misses | detects (no valid AEAD tag without DEK) |

**Concrete uses in network mode:**

1. **Verify-after-write (§21.3) uses AEAD, not a separate checksum.**  
   After `fsync`, re-read the page and call `decrypt_page()`. If the tag fails, the filesystem accepted the `fsync` call but did not persist the bytes tosumu wrote. This is the "fsync lied" scenario on unreliable network storage. It surfaces as `CorruptPage { pgno }` — the same typed error as local corruption — so the error path is not special-cased.

2. **Verify-on-open (§21.9) is a full AEAD sweep.**  
   Not a metadata check. Every page is decrypted (or at minimum its tag verified without decrypting the body — if the AEAD construction permits tag-only verification). A page written by a different database, or corrupted in storage, fails immediately.

3. **Mtime watchdog (§21.9) triggers targeted AEAD re-verification.**  
   When the watchdog detects an unexpected file modification, re-verify the pages tosumu wrote this session. If any AEAD tag fails, the external modification was destructive. If all tags still verify, the modification was metadata-only (timestamp drift, attribute change). The distinction matters: one is `FileModifiedExternally` + suspend, the other is logged and tolerated.

4. **Session integrity baseline.**  
   At session open, tosumu records the AEAD-verified page count. On close, it re-verifies the pages written this session and reports:
   ```
   [network-exclusive] closed: 42 pages written, 42 AEAD-verified on close. 0 failures.
   ```
   A close-time AEAD failure that didn't show up during the session indicates the filesystem swapped or corrupted a page after the write — not impossible on NFS with aggressive attribute caching.

5. **Page version in AAD: conditional rollback detection.**  
   `page_version` is in the AAD, so an old ciphertext for page N *at version M* cannot be presented as page N *at version M+1* — that would be a different AAD and the tag would fail. But an old *complete* page frame (old nonce + old `page_version` + old ciphertext + old tag) still decrypts and verifies correctly. AEAD proves *authorship at the claimed version*; it does not prove *freshness* unless the reader holds an independent trusted expectation of what the current version must be.

   Verify-after-write (item 1) is the safe case: the writer just wrote version N and immediately re-reads, requiring `decrypted.page_version == N`. That works because the writer holds the expected version as in-process state.

   On a subsequent open, without a checkpoint-signed manifest, global LSN, or Merkle root anchoring which version each page should be at, an old valid frame is indistinguishable from a current one. This is consistent with the known limitation already noted in §8.10: per-page `page_version` does not prevent coordinated multi-page rollback without a global anchor.

**What AEAD does not catch:**

- **Dropped writes.** If the filesystem silently discards a write (page N was never persisted), the pre-existing page N still has a valid AEAD tag — AEAD alone cannot detect this. Verify-after-write catches it: write page N at version M, immediately re-read, require `decrypted.page_version == M`. A stale old page (version M−1) has a valid tag but the version check fails. This works because the writer holds M as in-process state; it is not derived from the on-disk page itself.
- **WAL frame corruption.** WAL frames are also AEAD-encrypted (§7.2: `PageWrite` records store `ciphertext_blob`). A corrupt WAL frame fails AEAD during recovery. This is already in the design; network mode just means corruption is more likely.

**What AEAD proves vs. what it doesn't:**

```
AEAD proves:   this page was written by someone holding the DEK,
               for this pgno / page_version / page_type.

AEAD does not prove: this is the newest version of the page.

Freshness (rollback/staleness detection) requires a trusted external anchor:
  - expected page_version held by the writer (verify-after-write: safe)
  - checkpoint-signed page manifest
  - global LSN bound to a trusted checkpoint record
  - Merkle root over the page set

Without one of those anchors, an old but authentic page frame is
indistinguishable from a current one.
```

This is not a weakness unique to Tosumu. It is the standard AEAD bound: authentication proves origin and integrity, not recency. It is already acknowledged in §8.10 (known limitations: no global rollback protection without a signed manifest).

**The practical upshot:**

Tosumu's per-page AEAD means network mode doesn't need a *separate* integrity layer for corruption and tampering. The encryption is the integrity check for those threats. Freshness/rollback detection requires a trusted version anchor — in verify-after-write mode, the writer's in-process expected version serves that role. The cost is one extra `decrypt_page()` call per written page — roughly one ChaCha block operation per 4096 bytes. Cheap relative to a network round-trip and extremely cheap relative to data corruption.

---

## 22. Server mode and multi-client access (Stage 7+)

The §21 network story resolves to the correct answer: don't pretend a network filesystem is a local disk. The *actually correct* answer for multi-client network access is a thin server wrapper around `tosumu-core`.

This section documents that architecture so it stays consistent with the rest of the design if/when it gets built. It is explicitly Stage 7+ — it should not be designed in detail before Stage 1 exists.

### 22.1 Crate structure

```
tosumu-core    → storage engine (local, embedded, single-process)
tosumu-cli     → tooling (inspect, verify, migrate, dump, debug)
tosumu-server  → network wrapper (multi-client access to one database)
tosumu-client  → optional client SDK (talks to tosumu-server over HTTP/gRPC)
```

These do not mix. `tosumu-core` has no network code. `tosumu-server` has no storage code beyond calling `tosumu-core`. The boundary is enforced by the crate boundary.

### 22.2 Architecture

```
clients (many)
     ↓
network transport (HTTP or gRPC)
     ↓
tosumu-server
  ├── reader pool  → snapshot reads (parallel)
  └── writer queue → serialized writes (one at a time)
     ↓
tosumu-core
     ↓
file
```

The concurrency model is identical to the embedded model: many readers, single writer. The server extends that model across the network — it does not replace or complicate it. The writer queue in `tosumu-server` maps directly to the writer gate in `tosumu-core` (§7.5).

### 22.3 API design

Start stateless and boring:

```
GET    /kv/{key}          → point read (snapshot)
PUT    /kv/{key}          → single write
DELETE /kv/{key}          → single delete
POST   /tx                → batched transaction
GET    /scan?start=&end=  → range scan (snapshot)
GET    /status            → server health + connection_info
```

Batched transaction body:

```json
POST /tx
{
  "ops": [
    { "put":    { "key": "customer:123", "value": "..." } },
    { "delete": { "key": "customer:old" } }
  ]
}
```

The server enqueues the batch as a single `WriteTransaction` and returns the result atomically. Clients do not manage transaction boundaries directly — they submit a batch, get a result. This is the right default for a network API: stateless request → atomic result.

### 22.4 Transport choice

Pick HTTP/1.1 + JSON first. It works everywhere, is debuggable with `curl`, and requires no code generation. gRPC is faster and typed but adds complexity and tooling dependencies. Upgrade to gRPC only if profiling shows HTTP overhead is a real bottleneck — it almost certainly will not be for an embedded key/value store.

### 22.5 Authentication

Even a minimal deployment needs authentication. Start with static API keys in the request header:

```
Authorization: Bearer <api-key>
```

Keys are stored in the server config, not in the database. Do not skip this. Unauthenticated database endpoints are an incident waiting to happen.

Token-based auth (JWT, short-lived tokens) is a Stage 8+ concern. Static API keys are adequate for controlled deployments and substantially simpler.

### 22.6 Observability

`GET /status` returns the same `connection_info` fields as `Database::connection_info()` (§7.7), plus server-layer additions:

```json
{
  "active_clients":     3,
  "writer_queue_depth": 0,
  "current_lsn":        1204,
  "oldest_reader_lsn":  1199,
  "wal_frame_count":    42,
  "last_checkpoint_lsn": 1100,
  "checkpoint_blocked_by": null,
  "slow_queries_last_60s": 0,
  "uptime_seconds":     3612
}
```

The server is talkative by default. Silence is how you end up with a giant WAL and no idea why.

### 22.7 `LocalStore` / `RemoteStore` abstraction (optional)

Once `tosumu-client` exists, the same interface can be presented for local and remote access:

```rust
trait Store {
    fn get(&self, key: &[u8]) -> Result<Option<Value>>;
    fn put(&self, key: &[u8], value: &[u8]) -> Result<()>;
    fn delete(&self, key: &[u8]) -> Result<()>;
}

struct LocalStore  { db: Database }   // calls tosumu-core directly
struct RemoteStore { url: Url }       // calls tosumu-server over HTTP
```

This is **API-level transparency**, not storage-level lies. The caller chooses which `Store` to construct — there is no auto-detection, no magic proxying, no silent fallback. `LocalStore` and `RemoteStore` are different types with the same interface.

This enables:

```
local dev   → LocalStore  → tosumu-core
production  → RemoteStore → tosumu-server → tosumu-core
offline     → LocalStore  (no server needed)
```

Same data model. Same semantics. Different deployment. No surprise behavior when the network is absent.

### 22.8 What this is not

- **Not a distributed database.** One server, one database file, one writer loop. No consensus, no sharding, no replication.
- **Not an automatically scaled service.** If you need horizontal scaling, use a database that was designed for it. Tosumu-server is for "many clients, one database," not "many databases, many writers."
- **Not a hidden network layer.** There is no auto-detection that silently switches from local to remote. You construct `LocalStore` or `RemoteStore` explicitly.

### 22.9 Design principle

The correct pattern for multi-client network database access is **embedded core + explicit server wrapper**, not "make the filesystem work harder." Tosumu-server is that wrapper — minimal, explicit, and built directly on the same concurrency model as the embedded engine rather than layered on top of different assumptions.

---

## 23. Auditability, witnesses, and health detection (Stage 7+)

AEAD proves page authenticity. It does not prove recency. A rolled-back database — one silently restored from a stale backup, or one whose WAL was truncated — will return authentic pages for a state that is no longer current. The database will appear healthy to any check that only looks inward.

Auditability makes disagreement detectable from the outside.

> Tosumu's audit layer exists to detect disagreement between the database's current state and independently observed prior state. AEAD proves page authenticity; witnesses and observers provide freshness anchors.

This section describes three interlocking mechanisms: a hash-chained audit log (§23.1–§23.3), an external witness model for multi-server deployments (§23.4–§23.5), and a local observer model for single-server deployments (§23.6–§23.7). All three produce the same thing: an external vantage point that can say "the database claims to be at state X, but I last saw state Y."

### 23.1 WAL vs. audit log

These are different tools for different questions.

| | WAL | Audit log |
|---|---|---|
| **Question answered** | How do we recover storage state? | What happened, who/what caused it, does the sequence make sense? |
| **Primary consumer** | Recovery path, checkpoint | Operator, observer, external verifier |
| **Mutable after write?** | Yes, checkpointed away | No, hash-chained |
| **Contains** | Page images | Event records |
| **Covers** | Page writes only | All significant lifecycle events |

The WAL is internal storage infrastructure. The audit log is externally verifiable evidence. They are stored separately. Neither replaces the other.

> **Do not conflate these.** The WAL tells you how to recover storage state. The audit log tells you what happened and whether the sequence makes sense. Writing audit events into the WAL ("WAL with vibes") loses the independence property: the WAL is checkpointed and truncated; the audit log must be append-only and independently verifiable. The `audit_key` being a separate HKDF subkey (§8.3) exists precisely to enforce this independence — the audit log can be verified by a party who does not hold the DEK, because the chain runs over ciphertexts. Keep them separate at every level: storage, key material, crate, and API.

### 23.2 Audit event types

```
-- Lifecycle
DatabaseOpened
DatabaseClosed
TransactionStarted
TransactionCommitted
TransactionRolledBack

-- Storage
PageWritten
CheckpointStarted
CheckpointCompleted
VerificationRun

-- Security
AuthFailureDetected       -- AEAD tag verification failed
RollbackSuspected         -- LSN went backward
ProtectorUsed             -- which keyslot kind unlocked the DB (not the key)
ProtectorAdded
ProtectorRemoved
KekRotated
DekRotated
UnauthorizedOpenAttempted -- wrong key / failed unlock

-- Access fingerprints (§26)
ReadFingerprint           -- sampled read: key prefix, session_id, lsn, timestamp
WriteFingerprint          -- every write: key prefix, byte size, session_id, lsn
ScanFingerprint           -- range scan: start/end prefix, row_count, session_id, lsn
BulkReadAnomaly           -- heuristic: session read >N distinct key prefixes in window
HighWriteVelocity         -- heuristic: session wrote >N pages in window
UnusualAccessPattern      -- heuristic: access outside normal session profile

-- Compliance (§27)
DeletionFingerprint       -- key deleted: prefix, lsn, session, compliance_tag
RetentionViolationBlocked -- attempt to truncate audit log inside retention window
AttestationIssued         -- signed integrity attestation produced
MofNQuorumRequired        -- destructive op requested; awaiting M-of-N approval
MofNQuorumApproved        -- quorum reached; destructive op authorized
MofNQuorumDenied          -- quorum not reached within timeout
ComplianceTagged          -- operation carried a compliance context string
AuditExportProduced       -- SIEM export produced; export manifest hash recorded

-- Network / deployment
NetworkModeWarning
MigrationApplied
ObserverConnected
ObserverDisconnected
WitnessReceiptIssued
```

Events are append-only. There is no delete. Read and scan fingerprints are **sampled by default** (1-in-N, configurable); write fingerprints are always recorded.

### 23.3 Hash-chained event structure

Because every database is always encrypted (§8.1), the audit log is also AEAD-protected. Each event record is encrypted with `audit_key` (derived from the DEK via `HKDF(DEK, info = "tosumu/v1/audit")`, §8.3) before being appended. The hash chain runs over the **ciphertexts**, not the plaintexts: a verifier without the DEK can still check chain integrity; a verifier with the DEK can additionally decrypt and inspect event content.

Each event record on disk:

```
nonce             [u8; 12]  random, per-event
event_ciphertext  [u8; N]   AEAD ciphertext of the plaintext fields below
authtag           [u8; 16]  ChaCha20-Poly1305 tag
previous_hash     [u8; 32]  hash of previous on-disk event record (covers nonce+ciphertext+tag)
event_hash        [u8; 32]  H(nonce ++ event_ciphertext ++ authtag ++ previous_hash)
```

Plaintext fields (inside the ciphertext):

```
event_id          u64      monotonic, per-database
timestamp         i64      Unix nanoseconds (wall clock; not trusted alone)
event_type        u16      enum discriminant
session_id        u64      from §7.7 connection_info
process_id        u32
host_id           [u8; 8]  first 8 bytes of hostname hash
lsn               u64      database LSN at time of event
```

Chain integrity:

```
event[n].event_hash = H(event[n].nonce ++ event[n].ciphertext ++ event[n].tag ++ event[n-1].event_hash)
```

The genesis event (event 0) sets `previous_hash` to all zeros.

If any event is deleted, reordered, or modified — even a single ciphertext byte — every subsequent `event_hash` value is invalidated. Verification is O(n) in the number of events.

**What the chain proves and does not prove:**

The chain proves the sequence of ciphertexts is internally consistent and unmodified since it was written. AEAD additionally proves each event was written by a process holding the DEK. A witness without the DEK can verify chain integrity; an auditor with the DEK can verify both chain integrity and event authenticity. Neither can be fooled without leaving evidence.

### 23.4 Three-server witness model

This is not a distributed database. Do not accidentally build Raft in a bathrobe.

Three servers act as **witnesses and auditors**, not as writable replicas. Writes still go to exactly one primary. Witnesses hold signed freshness receipts.

```
tosumu-primary
tosumu-witness-1
tosumu-witness-2
```

After each committed transaction, the primary broadcasts a **witness receipt**:

```
db_id             [u8; 16]   stable database identity (set at init)
lsn               u64        LSN just committed
manifest_hash     [u8; 32]   hash of page 0 + keyslot region
audit_head        [u8; 32]   event_hash of the most recent audit event
observed_at       i64        Unix nanoseconds
```

Witnesses store and sign these receipts. They do not validate them against each other in real time — they only store what the primary reported. Disagreement is detected by a **reconciliation check**, either scheduled or on-open.

**Rollback detection:**

```
primary reports   LSN = 1040
witness-1 last saw LSN = 1092
witness-2 last saw LSN = 1092
→ primary is sick / rolled back / restored from stale backup
```

**What the witness model detects:**

- Database rolled back to older LSN
- Stale backup silently restored in place
- Audit chain truncated (audit_head no longer matches the receipt chain)
- Missing witness receipts for an LSN range
- Node disagreement between witnesses

**What it does not automatically solve:**

- Multi-writer consensus
- Automatic failover
- Conflict resolution

Those are distributed database problems. Do not acquire them yet.

### 23.5 Witness receipt storage

Receipts are stored in a sidecar file (`tosumu.witness`) or in the witness process's own database. The primary is responsible for broadcasting; witnesses are responsible for storing. If a witness misses a receipt, it records the gap; gaps are distinct from disagreement.

On reconnect, witnesses can request a batch of receipts for an LSN range from the primary. This handles temporary disconnection without treating it as an attack.

### 23.6 Single-server observer model

When a three-server deployment is not warranted, the same freshness-anchor guarantee can be approximated locally. The main database process spawns one or more adjacent **observer processes** that communicate via IPC.

```
tosumu-server        main database process
tosumu-observer-a    adjacent observer
tosumu-observer-b    adjacent observer
```

IPC transport: Unix socket (Linux/macOS) or named pipe (Windows). Observers do not write the database. They watch, record, and verify.

Each observer tracks:

```
last_seen_lsn         u64
last_seen_audit_head  [u8; 32]
last_seen_manifest    [u8; 32]
last_heartbeat        i64        Unix nanoseconds
process_identity      u32        PID of the main process
file_mtime            i64        observed mtime of tosumu.db
file_size             u64        observed byte size
last_verify_result    HealthStatus
```

On every heartbeat (configurable, default 10 seconds), the main process sends a short report to each observer. Observers store it locally, reply with acknowledgment, and record a last-seen timestamp.

**Rollback detection (local):**

```
main process reports   current LSN = 900
observer-a last saw    LSN = 950
→ main database is sick or rolled back
```

**Observer sickness detection:**

```
observer-a reports   LSN = 950
observer-b reports   LSN = 1001
→ observer-a is sick, stale, or partitioned
```

The local mini-quorum is not a consensus protocol. It is a simple comparison: do the observers agree with each other and with the main process? If not, surface the disagreement explicitly and refuse further writes until an operator makes a decision.

### 23.7 Observer failure modes

Observers fail in two distinct ways:

**Observer is sick** — the observer process has crashed, lost its state, or is returning garbage. The main process detects this by missed heartbeats or by receiving a report that contradicts the other observers. Response: log the failure, continue operations, alert the operator. A sick observer is not the same as a sick database.

**Main process is sick** — the main process reports an LSN lower than the observer last saw. The database may have been rolled back. Response: refuse writes, transition to `RollbackSuspected`, wait for operator confirmation before accepting any further transactions.

The two cases have different recovery paths and must not be conflated.

### 23.8 Health status model

Database health is an explicit enum, not an implicit "no errors seen recently."

```rust
enum HealthStatus {
    Healthy,
    Degraded,              // non-critical warning; writes allowed
    ObserverDisagrees,     // observer LSN mismatch; writes allowed with warning
    RollbackSuspected,     // LSN went backward; writes refused
    AuditChainBroken,      // hash chain verification failed
    ManifestMismatch,      // page 0 / keyslot hash disagrees with witness
    AuthFailureDetected,   // AEAD tag verification failed on a page
    CheckpointStalled,     // WAL not checkpointing; growing unbounded
    Unknown,               // health cannot be determined
}
```

Status transitions are driven by observed events, not by timers. `Healthy` requires positive evidence; absence of failure is not positive evidence.

Diagnostics for `RollbackSuspected`:

```
Status: RollbackSuspected
Reason:
  local DB header LSN:  882
  observer-a last seen: 914
  observer-b last seen: 914
Action:
  writes refused until operator confirms recovery path
  run: tosumu-cli verify --full
  run: tosumu-cli audit tail --n 50
```

`Unknown` is the initial state before any checks have run. The system should reach a known state within seconds of opening.

### 23.9 Crate structure expansion

The full crate map once the audit and observer layers exist:

```
tosumu-core       local storage engine (no network, no IPC)
tosumu-cli        inspect / verify / migrate / audit / dump
tosumu-server     network wrapper (multi-client access)
tosumu-client     optional HTTP/gRPC client SDK
tosumu-audit      hash-chained event log + manifest management
tosumu-witness    external freshness receipts (three-server model)
tosumu-observer   local IPC health observers (single-server model)
```

Dependency rules mirror the existing layer invariant (§4): `tosumu-core` has no dependency on any of the others. `tosumu-audit` depends on `tosumu-core` (reads LSN and manifest) but not on `tosumu-server`. `tosumu-witness` and `tosumu-observer` depend on `tosumu-audit` for the event chain; neither depends on each other.

### 23.11 Cluster deployment target (K3s)

The reference deployment target for the three-server witness model (§23.4) and observer sidecar model (§23.6) is **K3s** — a single-binary Kubernetes distribution that runs on resource-constrained hardware. K3s is close enough to production Kubernetes that patterns proven there transfer directly, without the overhead of a full cluster for development.

This is deferred to MVP +12 (§12.0). Nothing in §23.1–§23.10 requires K3s to be running. The witness and observer APIs are transport-agnostic; the K3s deployment layer sits entirely above them.

Key K3s deployment decisions that must be made at MVP +12, not before:

- **PVC type for the DB file.** Local-path provisioner is fine for single-node K3s; Longhorn or a cloud block store for multi-node. The DB file must never be on a shared NFS mount (§21).
- **Observer IPC.** In K3s, `tosumu-observer` runs as a sidecar in the same Pod as `tosumu-server`, communicating via a Unix socket on a shared `emptyDir` volume. This is the correct topology — the observer is local to the process, not across the network.
- **Witness placement.** Each `tosumu-witness` instance must be scheduled on a separate physical node. Pod anti-affinity rules enforce this. A witness on the same node as the primary is not an independent observer.
- **Probe mapping.** `HealthStatus::Healthy` maps to readiness probe pass. Any non-`Healthy` / non-`Degraded` status maps to readiness probe fail — the pod is taken out of rotation until an operator resolves the disagreement.

### 23.10 Design principle

The fundamental distinction this section is built around:

> AEAD proves a page is real. Witnesses and observers prove a page is current.

Any system that only checks AEAD can be fooled by a faithful reproduction of an older state. Any system that also checks independent observers cannot be fooled without compromising those observers too — and compromising them leaves its own evidence.

The goal is not to make attacks impossible. It is to make attacks visible.

---

## 24. Competitive positioning

This section exists because someone will ask, and "it's a learning project" is not an answer. This is the honest version.

### 24.1 Positioning statement

SQLite is the correct choice for most embedded database workloads. It is small, fast, battle-tested, and ships everywhere. If you need a fast, portable key/value or relational store and you are not worried about tamper detection, rollback detection, or audit trails, use SQLite.

Tosumu is not competing for that space. The distinction:

> SQLite assumes the disk is honest.
> Tosumu assumes the disk might be lying and is designed to detect it.

This is a different product category, not a better version of the same one.

### 24.2 Honest feature comparison

#### Core storage

| Feature | SQLite | Tosumu |
|---------|--------|--------|
| B-tree storage | ✅ | ✅ |
| WAL | ✅ | ✅ |
| Page-based | ✅ | ✅ |
| Single-file DB | ✅ | ✅ |
| Embedded | ✅ | ✅ |

Parity. No differentiation here.

#### Integrity and tamper detection

| Feature | SQLite | Tosumu |
|---------|--------|--------|
| CRC / checksum | optional (`PRAGMA integrity_check`) | per-page AEAD tag |
| AEAD per page | ❌ | ✅ |
| Tamper detection | weak (CRC only) | strong (AEAD — any bit flip is caught) |
| Cross-DB page swap detection | ❌ | ✅ (AAD includes `db_id`) |
| Wrong-key detection | ❌ | ✅ (tag fails on wrong key) |

SQLite with CRC detects accidental corruption. Tosumu detects accidental corruption and intentional manipulation.

#### Freshness and rollback detection

| Feature | SQLite | Tosumu |
|---------|--------|--------|
| Detect LSN rollback | ❌ | ✅ (with witnesses / observers) |
| External freshness anchors | ❌ | ✅ |
| Hash-chained audit log | ❌ | ✅ |

AEAD alone is insufficient here — §21.10 documents this explicitly. A faithful copy of an older valid page frame still verifies. Rollback detection requires an external anchor; that is what §23 builds.

#### Security model

| Feature | SQLite | Tosumu |
|---------|--------|--------|
| Encryption built-in | ❌ (SEE / SQLCipher are extensions) | ✅ |
| Envelope encryption (DEK/KEK) | ❌ | ✅ |
| Multiple key protectors | ❌ | ✅ |
| KEK rotation without re-encrypt | ❌ | ✅ |

SQLite's answer to encryption is "use an extension." That is a reasonable answer; it is also a separate dependency, a separate attack surface, and a different maintenance contract.

#### Observability and explainability

| Feature | SQLite | Tosumu |
|---------|--------|--------|
| `EXPLAIN` query plan | ✅ | planned (Stage 5) |
| Storage behavior introspection | ❌ | ✅ (`dump`, `hex`, `verify`) |
| Connection / session introspection | ❌ | ✅ (§7.7 `connection_info`) |
| Audit trail | ❌ | ✅ (§23) |
| Structured error reporting | medium (`SQLITE_BUSY` etc.) | goal: high (§9) |

SQLite's `database is locked` error is accurate. It does not tell you which reader is holding the lock, at which LSN, or how long it has been there. Tosumu's design goal is to always answer "why."

#### Migrations

| Feature | SQLite | Tosumu |
|---------|--------|--------|
| Structured migration system | ❌ (application concern) | ✅ (§13) |
| Preflight / dry-run | ❌ | ✅ |
| Verification after migration | ❌ | ✅ |
| Format version in header | `application_id` / `user_version` | first-class header field |

SQLite migrations are the application's problem. That is a legitimate design choice. It is also where most production incidents involving schema changes originate.

### 24.3 Where Tosumu loses, honestly

There is no version of this comparison where Tosumu beats SQLite on:

- **Speed.** SQLite is 30+ years of query and I/O optimization. Tosumu is not competing here.
- **Maturity.** SQLite has billions of deployments and an exhaustive test suite with 100% branch coverage as a stated goal. Tosumu does not.
- **Ecosystem.** Every language has SQLite bindings. ORMs target it. Tools exist for it. The Tosumu ecosystem is this document and a stub crate.
- **SQL support.** SQLite has a full SQL engine. Tosumu's SQL layer (Stage 5) will be a toy subset for years.
- **"Just works."** SQLite requires no configuration, no key management, no audit setup. Tosumu's full feature set requires explicit setup. That is the correct trade-off for what it is, and it is a real cost.

Any pitch that glosses over these is dishonest. Don't make it.

### 24.4 Who would actually choose Tosumu

Not "instead of SQLite." Alongside, or for workloads where the following are true:

1. **Tamper detection is a requirement**, not a nice-to-have — regulated environments, audit logs, financial records, medical device logs, safety-critical telemetry.
2. **Forensic capability matters** — "what happened, when, and can I prove it?" is a real question, not an edge case.
3. **Migrations are a first-class concern** — long-lived embedded products where format evolution needs structured tooling, not scripts and hope.
4. **Rollback or stale-state detection is needed** — any deployment where someone could swap in an old backup and the system needs to notice.
5. **Explainability is a design value** — teams that want to be able to answer "why" for storage behavior without reading source code.

None of these are niche in isolation. The combination narrows the field.

### 24.5 The honest two-sentence version

Tosumu is not a better SQLite. It is a stricter, more paranoid, more explainable storage engine for workloads where "trust but verify" is the minimum acceptable bar — not an afterthought bolted on later.

---

## 25. Ransomware threat model and defenses

Ransomware is a specific adversary: a process running as the same OS user as the database that encrypts files it can reach and demands a key for restoration. It is distinct from the §8.1 threat model (attacker with file-level read/write access trying to be subtle). Ransomware is not subtle — it overwrites files wholesale.

This section documents what Tosumu provides by design, what it does not provide, and what the operator must supply at the deployment layer.

### 25.1 What the always-encrypted design provides for free

Because every page is AEAD-authenticated, ransomware encryption is **immediately detectable** on next open. Ransomware doesn't understand Tosumu's page format; it overwrites file bytes with its own ciphertext. The result: every page AEAD tag fails. `AuthFailureDetected` fires on the first page read. The database refuses to open.

This is a meaningful property:

- There is no "silently corrupted but apparently working" state after a ransomware attack. The database is either intact and opens correctly, or it fails loudly on the first page authentication.
- The exact failure (`AuthFailed { pgno: 1 }` on the first data page) tells the operator immediately what happened, without needing to reason about whether the data is trustworthy.
- The audit chain (§23.3), if the audit log survived on a separate path, preserves the last authenticated state before the attack.

This does **not** prevent the attack. It provides immediate, unambiguous detection.

### 25.2 What the witness model provides

If witnesses (§23.4) or observers (§23.6) were running before the attack:

- Witnesses hold signed receipts with the last-known-good `lsn`, `manifest_hash`, and `audit_head`.
- The witness receipts are stored on separate machines with separate credentials. Ransomware on the primary cannot reach them without lateral movement.
- On recovery, the operator knows exactly which LSN to restore to. The recovery point is not "the last backup" but "the last LSN the witnesses saw before the attack."

This is the complement to §25.1: detection gives you a hard stop; witness receipts give you a precise recovery target.

### 25.3 Key hierarchy resilience

The DEK is wrapped by protectors. A ransomware process running as the database user can read the database file and any keyfile stored in the same directory. It cannot read a:

- Passphrase the user typed at open time (never on disk)
- Recovery key the user stored offline or in a separate credential store
- TPM-sealed key (accessible only on the same hardware, under the same TPM policy, often gated by platform auth)

After a ransomware incident and database restoration from backup:

1. Rotate the sentinel key or any protectors the attacker may have observed.
2. Add a new protector with a fresh passphrase or recovery key.
3. Use `tosumu rekey-kek` to rewrap the DEK under the new protectors.
4. Remove compromised keyslots.

The DEK itself never needs to change if the attacker only had file-level access and could not read process memory — key rotation is a KEK operation (cheap, §8.8), not a DEK operation.

### 25.4 Append-only audit log strategy

On Linux, the audit log file can be opened with `O_APPEND` and the filesystem append-only flag (`chattr +a`). A process with normal user permissions can append to the file but cannot overwrite or truncate it. Ransomware running as the database user cannot destroy the audit log — it can only append garbage, which will fail AEAD verification and be identifiable as the attack artifact.

On Windows, the equivalent is NTFS object permissions: grant `FILE_APPEND_DATA` but not `FILE_WRITE_DATA` or `DELETE` to the database service account.

This is outside Tosumu's direct control (it is a deployment concern) but should be configured in any environment where the audit log is treated as evidence.

### 25.5 OS-level snapshot strategies (outside Tosumu)

These are complementary and outside Tosumu's responsibility, but warrant documentation:

| Strategy | Platform | What it provides |
|----------|----------|------------------|
| Volume Shadow Copy (VSS) | Windows | Point-in-time snapshots of volumes; ransomware typically cannot delete VSS snapshots without admin rights |
| ZFS snapshots | Linux/FreeBSD | Instant, writable snapshots; can be made read-only after creation; stored as part of the pool the ransomware cannot normally reach |
| btrfs snapshots | Linux | Similar to ZFS; subvolume snapshots; can be made read-only |
| Filesystem-level immutability (`chattr +i`) | Linux | Immutable flag; even root cannot modify without removing the flag first |
| Offsite / cloud backup with retention | Any | The last line of defense; a ransomware-resistant copy requires write-once / object-lock semantics at the storage layer |

The correct deployment posture is: Tosumu detects immediately (§25.1), witnesses provide a precise recovery point (§25.2), and OS snapshots or offsite backups provide the restorable copy. No single layer is sufficient alone.

### 25.6 What Tosumu does not protect against

- **Ransomware with process memory access.** If the attacker can read process memory, they can extract the in-memory DEK. This is out of scope per §8.1 and requires OS-level mitigations (e.g., memory encryption, process isolation) outside Tosumu's control.
- **Ransomware with admin/root.** A process with root can remove append-only flags, delete VSS snapshots, and access TPM-sealed keys under some policies. Defense requires privileged access management outside Tosumu.
- **Pre-encryption exfiltration.** Ransomware that reads and exfiltrates data before encrypting it. Tosumu's AEAD protects data at rest from passive readers without the key; it does not protect against a process that legitimately holds the key (i.e., runs as the database user).
- **Backup destruction before detection.** If ransomware destroys backups before the next health check, the recovery window depends entirely on the backup strategy. Witness receipts survive only if witnesses are on separate machines.

### 25.7 Design principle

> Ransomware cannot produce a valid Tosumu database. It can only produce a broken one. The question is how quickly the operator knows.

Tosumu's answer: immediately, on the next open, with a typed error that distinguishes AEAD failure (ransomware / tampering) from a legitimate corruption event.

---

## 26. Fingerprinting and behavioral telemetry (Stage 7+)

AEAD proves a page is authentic. The audit chain proves the event sequence is unmodified. Neither alone tells you *who did what, in what pattern, and whether that pattern is normal*. Fingerprinting is the third layer.

The threat model here is two distinct adversaries:

- **External attacker:** gained access to the database process (compromised credentials, exploited vulnerability). Behavior: unusual key access, bulk reads of data they don't normally touch, rapid writes, attempted key rotation.
- **Insider threat:** legitimate user doing something outside their normal scope. Behavior: reading key ranges they don't normally read, bulk exports, probing with key patterns, accessing the database at unusual times.

Fingerprinting does not prevent either. It produces a record that makes the behavior visible, auditable, and detectable by witnesses and observers.

### 26.1 What gets fingerprinted

**Every write** is fingerprinted. Writes are already recorded in the WAL; the fingerprint adds session identity and key prefix to the audit event stream.

**Reads are sampled.** Recording every read for a high-throughput database is expensive. Default: 1-in-100 reads emit a `ReadFingerprint` event. The sampling rate is configurable. In high-security deployments, set it to 1-in-1 (record everything).

**Scans are always recorded.** A range scan touching many keys in one operation is a higher-signal event than an individual read. `ScanFingerprint` includes the start/end key prefix and the number of rows returned.

**Unlock events are always recorded.** `ProtectorUsed` records which keyslot kind was used (e.g. `Passphrase`, `Sentinel`, `RecoveryKey`) but not the key itself. Repeated unlock attempts with different protectors → `UnauthorizedOpenAttempted`.

### 26.2 Session identity fields

Every fingerprint event carries:

```
session_id      u64      from §7.7; unique per Database::open() call
process_id      u32      OS PID
process_name    [u8;32]  first 32 bytes of the process name (not a trust anchor; informational)
host_id         [u8; 8]  first 8 bytes of hostname hash
user_identity   [u8;32]  OS user name hash (not a trust anchor; informational)
timestamp       i64      Unix nanoseconds
lsn             u64      current LSN at time of event
key_prefix      [u8; 8]  first 8 bytes of the key (prefix, not full key; avoids leaking data)
```

`process_name` and `user_identity` are informational only. A compromised process can lie about them. Their value is not authentication; it is that a legitimate process doesn't bother lying, so discrepancies between expected and observed values are themselves a signal.

### 26.3 Heuristic anomaly events

Three lightweight heuristics run inside the engine and emit events when they fire. These are not ML models — they are simple counters with thresholds, configurable at open time.

#### BulkReadAnomaly

```rust
BulkReadConfig {
    window_seconds:       60,    // rolling window
    distinct_prefix_threshold: 500,  // distinct key prefixes in window
    sample_rate:          1,     // 1-in-1 (record all reads for this session)
}
```

A session that reads more than 500 distinct key prefixes within 60 seconds fires `BulkReadAnomaly`. This is the exfiltration signal.

#### HighWriteVelocity

```rust
HighWriteConfig {
    window_seconds: 10,
    page_threshold: 100,  // pages written in window
}
```

A session that writes more than 100 pages in 10 seconds fires `HighWriteVelocity`. This is the ransomware / bulk overwrite signal (relevant before AEAD detection fires).

#### UnusualAccessPattern

A session that accesses key prefixes it has never accessed before in any prior session (tracked via a compact Bloom filter of `(session_id, key_prefix)` tuples). Signal fires once per session on first new-prefix access outside a configurable whitelist. This is the lateral-movement / privilege-escalation signal.

All three thresholds default to conservative (high threshold, low false-positive rate). Operators can tighten them. Setting them to zero disables the heuristic.

### 26.4 Fingerprint trails in the witness and observer model

Fingerprint events are part of the AEAD-protected audit chain (§23.3). Witnesses receive them as part of witness receipts. Observers track them locally.

This means:

- A bulk read by an insider that happens while witnesses are running will produce `ReadFingerprint` + possibly `BulkReadAnomaly` events that are signed into the audit chain and broadcast to witnesses.
- After the fact, even if the attacker deletes the local audit log, witness receipts still contain the `audit_head` from before the deletion, and the chain can be shown to have been truncated.
- Observers can be configured to fire an immediate alert on `BulkReadAnomaly` or `HighWriteVelocity` without waiting for a reconciliation check.

### 26.5 What fingerprinting does not do

- **It does not prevent access.** Any process that can open the database can read from it. Fingerprinting records the access; it does not block it.
- **It is not a firewall.** Access control at the application layer (who is allowed to open the database, with which protector) is outside Tosumu's scope.
- **It is not tamper-proof in isolation.** The fingerprint record is only trustworthy if the audit chain and witnesses are intact. An attacker who compromises both the database and all witnesses can suppress the record. This is the same limitation as §23.3 — the chain is as strong as the independence of its observers.
- **The heuristics produce false positives.** A legitimate batch migration will fire `HighWriteVelocity`. A legitimate analytics query will fire `BulkReadAnomaly`. The events are signals for investigation, not verdicts.

### 26.6 Diagnostic queries on the fingerprint trail

`tosumu-cli` provides audit trail queries as first-class operations:

```
tosumu audit tail --n 100
    → last 100 events in the chain, decrypted, pretty-printed

tosumu audit session <session_id>
    → all events for a given session_id

tosumu audit anomalies [--since <lsn>]
    → only BulkReadAnomaly, HighWriteVelocity, UnusualAccessPattern, AuthFailureDetected

tosumu audit diff --witness-a tosumu.witness --witness-b local
    → compare local audit_head against a witness receipt; highlight divergence

tosumu audit export --format jsonl [--since <lsn>]
    → export decrypted events as JSON lines for SIEM ingestion
```

The `export` command enables feeding fingerprint data into external security tooling (Splunk, Elastic, etc.) without requiring those tools to understand Tosumu's on-disk format.

### 26.7 Backup as the best ransomware defense

Routine backups remain the most reliable single defense. The fingerprint trail and witness model tell you *what happened and when*; backups give you the restorable copy. Neither substitutes for the other.

**Backup properties that matter for Tosumu:**

- **Frequency.** The maximum data loss is bounded by the backup interval. For databases where data loss is costly, backup frequency should be set accordingly.
- **Integrity verification.** A backup that cannot be opened with the correct protector is not a backup. `tosumu verify <path>` should be run against every backup before it is considered valid.
- **Offsite / separate credential.** A backup stored in the same directory as the database, accessible with the same credentials, provides no protection against ransomware or an insider threat. The backup credential (or the backup copy of the sentinel key / recovery key) must be stored separately.
- **Write-once / object-lock semantics.** Cloud storage with object-lock enabled prevents ransomware (running with the backup-agent credentials) from overwriting or deleting existing backup objects. This is the property that makes offsite backups ransomware-resistant rather than merely ransomware-delayed.
- **Retention window.** Keep enough history to recover from a ransomware attack that isn't detected immediately. If the detection window is "next open," a daily backup with 30-day retention is likely sufficient. If the detection window could be weeks (e.g. cold standby), retain accordingly.

**Integration with witness receipts:** after each successful backup, record the current `lsn` and `manifest_hash` (from `tosumu verify`) in the backup metadata. On restore, the witness receipts tell you whether the backup LSN is consistent with what the witnesses observed — i.e., whether you're restoring to the right point.

### 26.8 Design principle

> Fingerprinting makes the invisible visible. It does not make the system impenetrable. The goal is to ensure that any access — legitimate or not — leaves a trail that cannot be quietly erased.

---

## 27. Compliance and audit-friendly capabilities (Stage 7+)

This section documents capabilities that exist specifically because professional auditors, compliance teams, and regulated environments need them. The features here are not useful for every deployment — they are opt-in, explicitly staged, and designed so that their absence does not affect core storage engine operation.

The audience is: SOX, HIPAA, GDPR, PCI-DSS, ISO 27001, and similar frameworks where a human auditor will ask hard questions and expect structured answers.

### 27.1 Signed integrity attestations

`tosumu audit attest` produces a signed, exportable attestation document:

```
Attestation {
    db_id:              [u8; 16]
    attested_at:        i64        Unix nanoseconds
    current_lsn:        u64
    manifest_hash:      [u8; 32]   hash of page 0 + keyslot region
    audit_chain_head:   [u8; 32]   event_hash of the most recent audit event
    audit_event_count:  u64
    anomalies_detected: bool
    attested_by:        [u8; 32]   hash of the protector that signed this document
    signature:          [u8; 64]   Ed25519 signature over all fields above
}
```

The attestation is self-contained: it can be saved to a file, emailed to an auditor, or attached to a compliance report. An auditor with the corresponding public key can verify it offline without access to the live database.

`AttestationIssued` is recorded in the audit chain, so there is a tamper-evident record of when attestations were produced and by whom.

**What it proves:** at the stated LSN and timestamp, the database was intact (pages verified), the audit chain was unbroken, and the document was produced by a process holding the named protector.

**What it does not prove:** that the content of the data is correct, complete, or meaningful. Attestation is a structural integrity claim, not a semantic one.

**Rotation:** attestations use an Ed25519 key pair managed as a separate `AttestationKey` protector. The private key can be held by a compliance officer rather than a DBA, enabling independent attestation without database write access.

### 27.2 Proof of deletion

When a key is deleted, a `DeletionFingerprint` event is appended to the audit chain:

```
DeletionFingerprint {
    key_prefix:      [u8; 8]   first 8 bytes of deleted key (not full key)
    key_hash:        [u8; 32]  SHA-256 of the full key (enables verification without storing the key)
    deleted_at_lsn:  u64
    session_id:      u64
    compliance_tag:  Option<[u8; 32]>  e.g. "GDPR-erasure", "retention-expiry"
    deletion_type:   enum { UserRequested, RetentionExpiry, MigrationPurge, SecureWipe }
}
```

This is directly useful for:

- **GDPR right-to-be-forgotten:** an auditor asks "was subject X's data deleted?" The answer is a signed event with a timestamp and LSN, not "we think so."
- **Retention enforcement audits:** "all records older than 7 years were purged on this date" — the `RetentionExpiry` deletion type with a compliance tag produces exactly this evidence.
- **Dispute resolution:** if a record is claimed to have existed and been deleted, the audit chain either contains the deletion event or it doesn't. The chain cannot be modified without breaking subsequent hashes.

**Secure wipe:** `DeletionType::SecureWipe` additionally zeroes the freed page on disk (the freed page is re-encrypted with a random throwaway key and overwritten before release to the freelist). The `DeletionFingerprint` records that the wipe occurred. This is distinct from normal deletion, which only marks the slot as deleted in the B+ tree.

### 27.3 Segregation of duties — AuditProtector

By default, the `audit_key` is derived from the DEK (`HKDF(DEK, info = "tosumu/v1/audit")`). This means anyone who can unlock the database can read the audit log. A DBA can theoretically read and observe their own access trail.

The `AuditProtector` breaks this coupling:

- At init or later, an `AuditProtector` is configured by a separate principal (e.g. a compliance officer, a CISO).
- The `audit_key` is re-wrapped under the `AuditProtector`'s KEK, independent of the DEK.
- The database can be opened and written to without the `AuditProtector` being present.
- The audit log can only be *read* (decrypted) by a principal holding the `AuditProtector`.
- The DBA cannot read the contents of their own audit trail without the compliance officer's credential.

Chain integrity verification (§23.3) remains possible without the `AuditProtector` — it runs over ciphertexts, not plaintexts. Only content decryption requires the audit key.

This satisfies the four-eyes principle at the audit layer: the person operating the database cannot unilaterally read, modify, or suppress their own access record.

### 27.4 Retention enforcement

A `RetentionPolicy` is set at database init or updated later by an authorized principal:

```rust
RetentionPolicy {
    min_retention_days: u32,   // e.g. 2555 (7 years for SOX)
    policy_name:        String, // e.g. "SOX-7yr"
    enforced_since_lsn: u64,
}
```

The engine refuses any operation that would truncate, delete, or overwrite audit events within the retention window. The refusal is itself audited (`RetentionViolationBlocked`). To override, two conditions must be met:

1. A second principal holding an `OverrideProtector` must co-authorize the override.
2. The override itself is recorded as an `MofNQuorumApproved` event with both principals' protector hashes.

This means: no single administrator can silently destroy audit evidence within the retention window. Override is possible (for legitimate operational reasons) but leaves an indelible record.

### 27.5 M-of-N quorum for destructive operations

Certain operations are too consequential to authorize with a single credential:

| Operation | Minimum quorum |
|-----------|----------------|
| DEK rotation (full page re-encrypt) | 2-of-N |
| Audit log truncation inside retention window | 2-of-N |
| Database deletion (`tosumu destroy`) | 2-of-N |
| `AuditProtector` key rotation | 2-of-N |
| Retention policy change | 2-of-N |

The quorum threshold is configurable. The default `M = 2` requires two distinct protectors (e.g. DBA + compliance officer) to independently authorize before the operation proceeds.

Quorum flow:

```
Operator A requests: tosumu rekey-dek
→ MofNQuorumRequired emitted in audit chain
→ operation suspended; waiting for M-of-N approvals

Operator B approves: tosumu quorum approve <operation_id>
→ MofNQuorumApproved emitted
→ operation proceeds

If approval does not arrive within timeout:
→ MofNQuorumDenied emitted
→ operation aborted
```

Each `MofNQuorumApproved` event records the hash of every approving protector, the operation requested, and the timestamp. This produces a complete chain-of-custody record for every destructive operation.

### 27.6 Compliance context tagging

Any write operation, deletion, or migration can carry an optional compliance context string:

```rust
tx.put_with_context(b"patient:123", value, ComplianceTag::new("HIPAA-treatment-record"))?;
tx.delete_with_context(b"subject:456", ComplianceTag::new("GDPR-erasure-request-REF-2026-04"))?;
```

The tag (up to 64 bytes) is stored in the audit event alongside the fingerprint. It is not stored in the data page itself — it is audit metadata only.

This enables post-hoc SIEM queries like:

```
tosumu audit export --tag "GDPR-erasure" --format jsonl
→ all deletions carried out under GDPR erasure requests, with timestamps and LSNs
```

Compliance tags are informational annotations, not access-control labels. They do not grant or restrict permissions. Their value is search and reporting, not enforcement.

### 27.7 Tamper-evident audit export

`tosumu audit export` produces a JSONL file. Without additional protection, that file can be modified after export — defeating the purpose of sending it to an auditor.

Tamper-evident export adds a signed manifest:

```
tosumu audit export --format jsonl --sign > audit-2026-04.jsonl
```

The output file includes a final line:

```json
{"type":"manifest","event_count":4821,"chain_head":"a3f2...","exported_at":1745520000,"signature":"ed25519:..."}
```

The signature covers all preceding lines. An auditor runs:

```
tosumu audit verify-export audit-2026-04.jsonl --pubkey auditor.pub
```

and gets a pass/fail with the number of events verified. Any modification to any line — including deletion of lines — fails the signature check.

`AuditExportProduced` is recorded in the live audit chain, so there is a record of every export: when it was produced, how many events it covered, and the chain head at that moment.

### 27.8 Per-key last-access metadata

For workloads where "who last accessed this record" is a routine question (HIPAA, PCI-DSS), Tosumu can store lightweight per-key last-access metadata:

```
LastAccess {
    last_read_lsn:     u64
    last_read_session: u64
    last_written_lsn:  u64
    last_written_session: u64
}
```

This is stored in the B+ tree alongside the value, not in the audit chain. It enables O(log n) point queries — "who last read `patient:123`?" — without requiring a full audit chain scan.

This is a **Stage 5+ optional feature**. It adds 32 bytes of overhead per key and slightly increases write amplification (a read updates the last-read metadata, which is a write). The default is off; operators enable it per-database at `init`.

The per-key metadata is complementary to the audit chain, not a substitute. The chain provides the full history; the per-key metadata provides a fast answer to the most common forensic question.

### 27.9 Compliance framework mapping

| Framework | Relevant Tosumu capability |
|-----------|---------------------------|
| **GDPR Art. 17** (right to erasure) | `DeletionFingerprint` with `compliance_tag`; `SecureWipe` deletion type |
| **GDPR Art. 30** (records of processing) | Audit chain export; `AttestationIssued`; session fingerprints |
| **SOX §302 / §404** (internal controls) | Signed attestations; M-of-N quorum for destructive ops; retention enforcement |
| **HIPAA § 164.312(b)** (audit controls) | `ReadFingerprint`; per-key last-access; `BulkReadAnomaly`; SIEM export |
| **PCI-DSS Req. 10** (audit trails) | Hash-chained event log; tamper-evident export; `AuditProtector` segregation |
| **ISO 27001 A.12.4** (logging) | Full event taxonomy; anomaly heuristics; witness receipts |
| **ISO 27001 A.9.4** (access control) | `UnauthorizedOpenAttempted`; `ProtectorUsed`; session identity on all events |

This table is a guide, not a certification claim. Actual compliance requires deployment configuration, operational procedures, and legal review outside Tosumu's scope. Tosumu provides the technical primitives; the operator configures and operates them correctly.

### 27.10 Design principle

> An auditor should be able to ask any reasonable question about what happened to this database — who accessed it, what changed, when, under whose authority — and get a structured, verifiable answer without requiring access to the live system.

---

## 28. Rust-specific design patterns

Rust provides several features that go beyond what most languages offer for a project like this. This section documents how the language is used deliberately — not just "we wrote it in Rust" but "these language features are load-bearing parts of the design."

Most of these are already partially present in the design. This section names them explicitly so they are applied consistently rather than rediscovered case-by-case.

### 28.1 Typestate pattern for database lifecycle

The database has a lifecycle with distinct legal states:

```
Closed → Locked → Unlocked → (read / write transactions)
```

Encoding this in the type system means illegal transitions are compile errors, not runtime panics.

```rust
struct Database<State> {
    inner: Arc<DatabaseInner>,
    _state: PhantomData<State>,
}

struct Closed;
struct Locked;     // file open, format verified, protector not yet supplied
struct Unlocked;   // DEK in memory, pages can be read

impl Database<Closed> {
    pub fn open(path: &Path, policy: NetworkPolicy) -> Result<Database<Locked>> { ... }
}

impl Database<Locked> {
    pub fn unlock(self, input: &ProtectorInput) -> Result<Database<Unlocked>> { ... }
    pub fn protectors(&self) -> &[ProtectorMetadata] { ... }  // readable before unlock
}

impl Database<Unlocked> {
    pub fn read<F, T>(&self, f: F) -> Result<T> where F: FnOnce(&ReadTransaction) -> Result<T> { ... }
    pub fn write<F>(&self, f: F) -> Result<()> where F: FnOnce(&mut WriteTransaction) -> Result<()> { ... }
    pub fn lock(self) -> Database<Locked> { ... }  // zeroise DEK, return to Locked
}
```

Properties this gives for free:
- You cannot call `read` or `write` on a locked database — it does not compile.
- You cannot forget to unlock — the type you need for transactions is only producible via `unlock`.
- `lock()` consumes the `Unlocked` state and returns `Locked`, which drops and zeroises the DEK.

The `PhantomData<State>` is zero-cost at runtime.

### 28.2 Newtype wrappers for domain primitives

Raw integers for LSN, page numbers, session IDs, and key lengths are interchangeable at the type level. A function that takes `(u64, u64, u64)` for `(lsn, pgno, session_id)` silently accepts arguments in the wrong order.

Newtype wrappers eliminate the confusion:

```rust
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Lsn(u64);

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PageNo(u32);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct DekId(u64);
```

Passing a `PageNo` where an `Lsn` is expected is a compile error. `Lsn` and `PageNo` derive `Ord` so they can be compared directly without unwrapping.

`PageNo(0)` is always the header page. If page 0 ever appears in a B+ tree node as a child pointer, that is a bug. A `NonZeroU32`-backed `DataPageNo` could make this structural:

```rust
pub struct DataPageNo(NonZeroU32);  // guaranteed never page 0
```

### 28.3 `const` assertions for layout invariants

On-disk format correctness can be partially validated at compile time:

```rust
const PAGE_SIZE: usize = 4096;
const PAGE_HEADER_SIZE: usize = 8;
const SLOT_ENTRY_SIZE: usize = 4;
const MIN_RECORD_SIZE: usize = 2 + 1; // 1-byte key + 1-byte value min

// These fire at compile time if the constants are inconsistent:
const _: () = assert!(PAGE_SIZE.is_power_of_two());
const _: () = assert!(PAGE_HEADER_SIZE + SLOT_ENTRY_SIZE < PAGE_SIZE);
const _: () = assert!(core::mem::size_of::<FileHeader>() <= PAGE_SIZE);
const _: () = assert!(core::mem::size_of::<KeyslotEntry>() == 256);
const _: () = assert!(AUDIT_EVENT_MAX_SIZE < PAGE_SIZE / 2);
```

A change to any constant that breaks a layout invariant fails the build. No runtime check, no test harness — the compiler refuses the program.

This is the §2 principle 8 ("structural impossibility over advisory rules") applied to format constants.

### 28.4 `Send` and `Sync` as concurrency documentation

Rust's `Send`/`Sync` bounds are compile-time documentation of thread-safety properties. For Tosumu:

| Type | `Send` | `Sync` | Rationale |
|------|--------|--------|-----------|
| `Database<Unlocked>` | ✅ | ✅ | Internally arc-protected; multiple threads can hold references |
| `ReadTransaction<'_>` | ✅ | ❌ | Can be moved to another thread but not shared (snapshot is exclusive per-use) |
| `WriteTransaction<'_>` | ❌ | ❌ | Single-threaded by design; writer gate enforces this structurally |
| `Zeroizing<[u8; 32]>` | ✅ | ❌ | Key material can be moved but not shared across threads |
| `Database<Locked>` | ✅ | ✅ | No sensitive material in memory |

`WriteTransaction` being `!Send` means the compiler refuses to let it escape the thread that started the write closure. You cannot accidentally send a live write transaction to a thread pool.

These are not just documentation. They are enforced. Removing `!Send` from `WriteTransaction` to "make it easier to use" would be a correctness regression, not a convenience improvement.

### 28.5 Drop for automatic cleanup and zeroing

Rust's `Drop` trait runs on scope exit regardless of how the scope exits — return, `?`, panic. Tosumu uses this in several places:

**Key zeroing:**
```rust
// Zeroizing<T> from the `zeroize` crate: zeroes memory on Drop.
let dek: Zeroizing<[u8; 32]> = derive_dek(protector_input)?;
// DEK is used here, then dropped (and zeroed) at end of scope
```

**File lock release:**
```rust
struct FileLock { fd: File, path: PathBuf }
impl Drop for FileLock {
    fn drop(&mut self) { unlock_file(&self.fd); }
}
// Lock released even if the code panics
```

**WAL frame rollback:**
A `WriteTransaction` that is dropped without committing (i.e., the closure returned `Err`) must not leave partial WAL frames. `Drop` on `WriteTransaction` rolls back any buffered frames that weren't flushed to the WAL.

**Audit event flush:**
The audit log writer flushes on `Drop`. An audit event that was created but whose owning scope panicked still gets written — it's evidence of the panic, not a reason to suppress it.

### 28.6 Sealed traits for controlled extensibility

The `KeyProtector` trait (§8.6) is intended to be implemented by Tosumu's own protector types. It is not intended to be implemented by arbitrary external code (external implementations could bypass security invariants).

Rust's sealed-trait pattern enforces this:

```rust
mod private {
    pub trait Sealed {}
}

pub trait KeyProtector: private::Sealed {
    fn derive_kek(&self, meta: &ProtectorMetadata, input: &ProtectorInput)
        -> Result<Zeroizing<[u8; 32]>>;
}

// Only types in this crate can impl Sealed, so only they can impl KeyProtector
impl private::Sealed for PassphraseProtector {}
impl private::Sealed for RecoveryKeyProtector {}
impl private::Sealed for SentinelProtector {}
// External crates cannot add new protectors without a tosumu-core fork
```

The `AuditProtector` (§27.3) and `AttestationKey` (§27.1) follow the same pattern.

This is the right default for security-critical traits. If the sealed restriction becomes a genuine problem (plugin ecosystem, Stage 8+), the decision to unseal is explicit and documented; the default is locked down.

### 28.7 `#[repr(C)]` for on-disk structures

Structures that map directly to on-disk bytes use `#[repr(C)]` with explicit field ordering:

```rust
#[repr(C)]
struct PageHeader {
    page_type: u8,
    flags:     u8,
    slot_count: u16,
    free_start: u16,
    free_end:   u16,
}
```

`#[repr(C)]` with fixed-width integer types gives deterministic layout across platforms. Combined with `const` size assertions (§28.3), this ensures the in-memory layout matches the documented on-disk format exactly.

**Never use `#[repr(Rust)]` (the default) for on-disk structures.** Rust makes no stability guarantees for the default layout — field order and padding can change between compiler versions.

**Never use `#[repr(packed)]` without `const` alignment assertions.** Packed structs can produce unaligned accesses on some targets; on embedded platforms this is undefined behaviour even without `unsafe` if reached through references.

### 28.8 The `?` operator and error propagation discipline

The `?` operator is Tosumu's primary error propagation mechanism. Combined with typed error enums (§9), it produces clean propagation without swallowing context.

Two rules that must be followed:

**Rule 1: Never `.unwrap()` or `.expect()` in production paths.** Every `.unwrap()` in `tosumu-core` is a panic waiting to happen on unexpected input. Use `?` and a typed error. The only acceptable `.unwrap()` is in test code where the test is explicitly asserting the `Ok` case.

**Rule 2: Never use `anyhow` in `tosumu-core`.** `anyhow::Error` is a type-erased error. `tosumu-core` must return typed errors that callers can match on. `anyhow` is acceptable in `tosumu-cli` (where the error will be displayed to a human, not matched by code).

```rust
// In tosumu-core: typed, matchable
pub enum PageError {
    AuthFailed { pgno: PageNo },
    IoError(std::io::Error),
    VersionMismatch { found: u16, min: u16 },
}

// In tosumu-cli: anyhow is fine, we're printing to stderr
fn cmd_verify(path: &Path) -> anyhow::Result<()> { ... }
```

### 28.9 Closures for transaction scope enforcement

The write transaction API uses closures rather than explicit `begin`/`commit` calls:

```rust
db.write(|tx| {
    tx.put(b"key", b"value")?;
    Ok(())
})?;
```

This is not just aesthetics. It is a structural guarantee:
- The transaction is automatically committed if the closure returns `Ok(())`.
- The transaction is automatically rolled back if the closure returns `Err(_)`.
- There is no `commit()` function to call, so it cannot be forgotten.
- There is no way to `Ok(())` a closure that called `tx.put` on corrupted data without the AEAD failing first — the type system and the error propagation model enforce this together.

The equivalent pattern for `ReadTransaction` uses a shared reference, not a mutable one — a read closure cannot call `tx.put` because `ReadTransaction` has no `put` method.

### 28.10 Design principle

> Rust's type system, ownership model, and trait system are not constraints to work around. They are the primary implementation of the §2 principle "structural impossibility over advisory rules." Every place where a safety property is enforced by the compiler is one fewer place where a test, a lint, or a code review needs to catch it.

---

## 29. Epistemic integrity model

This section formalizes the model that underlies Tosumu's approach to correctness. The vocabulary comes from §17.1. The content is not philosophy — it is a design framework that makes the audit system (§23), the pager trust boundary (§4), and the `tosumu verify --explain` command (§29.4) legible as a coherent whole rather than three independent features.

### 29.1 The epistemic pipeline

The Tonesu epistemic stages from §17 map directly onto Tosumu's storage stack:

| Tonesu stage | Storage equivalent | Description |
|---|---|---|
| `se` | Raw disk frame | Bytes on disk. Untrusted, uninterpreted. The adversarial zone. |
| `si` | Decoded page | Structure parsed. AEAD not yet checked. Not yet knowledge. |
| `to` | Verified page | AEAD passed. Authentically the page we wrote. |
| `tosu` | Consistent database | All pages verified, WAL applied, LSN/witness chain intact. Established state. |

Each stage is a genuine epistemic upgrade — not a label change but a precondition satisfied. The pager boundary (§4) is the `si → to` transition made structurally non-bypassable. Nothing above the pager handles `si`-level data. Nothing below the pager handles `to`-level data. The boundary exists in the type system and module structure, not in documentation.

> The tofeka failure mode is: presenting `si` data as `to`; presenting `to` data as `tosu`. The pager boundary prevents the first. The WAL, fsync discipline, and witness model prevent the second. At every layer the goal is to make the misrepresentation structurally impossible, not merely inadvisable.

### 29.2 The triad: Integrity, Freshness, Epistemic correctness

Three orthogonal failure dimensions cover all state misrepresentation:

| Dimension | Question | Mechanism | Current status |
|---|---|---|---|
| **Integrity** | Is this the page we wrote? | AEAD authentication | Stage 1 — implemented |
| **Freshness** | Is this the most recent state? | LSN / witness chain | Stage 6 — deferred |
| **Epistemic correctness** | Is the system claiming only what it can verify? | Design constraints at each layer | Continuous |

These are independent. A page can be integral but stale (§5.3 rollback vector: AEAD passes, but it is a faithful copy of an old frame). A system can be neither integral nor fresh if AEAD is skipped and staleness is undetected. The three dimensions must be tracked separately because the mitigations are separate.

**The rollback gap.** Per-page `page_version` closes the single-page rollback case. It does not close the consistent multi-page rollback case. An attacker who replaces all pages with a mutually consistent earlier snapshot will have every page pass AEAD — freshness is the dimension that catches this, not integrity. Until Stage 6, Tosumu can only report freshness as `unanchored`, not as `ok`. Reporting it as `ok` before the witness chain exists would itself be a tofeka claim.

### 29.3 Tofeka violations in storage systems

| System behavior | Claim tier | Evidence tier | Violation |
|---|---|---|---|
| Page returned without AEAD check | `to` | `si` | tofeka — inflation |
| DB presented as consistent, WAL not applied | `tosu` | `to` | tofeka — inflation |
| Stale read presented as current, no freshness anchor | `tosu` | `to` | tofeka — inflation |
| `fsync` returned `Ok` on a network FS; durability asserted | `tosu` | `si` | tofeka — inflation (§2 principle 10: sequence ≠ grounding) |
| Audit log suppressed; verifier told no anomalies exist | `tosu` | `si` | tofeka — deflation |

The last row is the adversarial case. Tosumu's append-only audit chain (§23.3) and independent witness model (§23.4) exist to make deflation detectable: an attacker who wants to claim "nothing happened" cannot erase the witness receipts without access to systems the attacker does not control.

### 29.4 The `tosumu verify --explain` output

The `--explain` flag on `tosumu verify` reports per-page status across all three dimensions:

```
verifying example.tsm (4 data pages) ...

page 1:
  integrity:   OK     — AEAD tag verified (this is the page we wrote)
  freshness:   unanchored — LSN witness not configured (§23, Stage 6)
  epistemic:   OK     — no overclaiming

page 2:
  integrity:   FAIL   — AEAD tag mismatch (page corrupted or tampered)
  freshness:   N/A
  epistemic:   FAIL   — cannot verify page 2 is what was written

FAILED: 3/4 pages ok, 1 issue(s)
```

The `freshness: unanchored` status persists until Stage 6. This is intentional honest reporting: we know exactly what we can verify at this stage and what we cannot. Saying `freshness: OK` before the witness chain is implemented would be a tofeka claim in the output of the tool whose purpose is to detect tofeka claims.

### 29.5 Implications for the audit system

The audit chain (§23) records not just *what happened* but *what was claimed to be true at each step*. This is the deeper reading of §23.1:

> The WAL tells you how to recover storage state. The audit log tells you what happened and whether the sequence makes sense.

"Whether the sequence makes sense" is an epistemic claim. Each `VerificationRun` event (§23.2) records the result of a `tosumu verify` call: which pages were checked, what the three-dimension status was for each. This creates an epistemic history — not just a log of operations but a log of *how much the system could verify at each point*.

A verifier with access to the audit chain and witness receipts can reconstruct:
- Whether integrity was continuously maintained.
- When freshness became anchored (on first witness configuration).
- Whether any period of unverified state preceded an anomaly.

This is the difference between an audit log that records events and one that records evidence. Tosumu's goal is the latter.

---
