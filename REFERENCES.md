# Reference Implementations

This document lists external codebases and resources that inform tosumu's implementation. These are battle-tested algorithms and patterns we can learn from.

---

## DataStructures Library (C#)

**Location:** `F:\LocalSource\ClassLibrary\DataStructures`

A comprehensive .NET 8 library with **65+ data structures**, 836+ unit tests, and production-quality implementations. Several structures are directly relevant to tosumu's core engine.

### High-priority references

These implementations should be consulted during the corresponding stage:

#### **BPlusTree.cs** — Stage 2 (B+ tree index)
**Path:** `Trees/BPlusTree.cs`

**What to reference:**
- Node splitting logic and thresholds (when to split an internal vs. leaf node).
- Maintaining leaf-node links during splits and merges.
- Delete rebalancing strategies (merge sibling vs. redistribute keys).
- Order statistics implementation (`Rank`, `Select`).

**Adaptation notes:**
- C# version is in-memory (node pointers). Tosumu's version is page-based (page numbers).
- Key translation: `Node*` → `PageNum`, pointer chasing → `pager.get_page(page_num)`.
- Core split/merge/redistribute algorithms are language-agnostic.

**Usage:**
```bash
# Review before implementing tosumu's btree.rs
code F:\LocalSource\ClassLibrary\DataStructures\Trees\BPlusTree.cs
```

---

#### **LruCache.cs** — Stage 1 (page cache eviction)
**Path:** `Caches/LruCache.cs`

**What to reference:**
- `Dictionary<TKey, LinkedListNode<T>>` + `LinkedList<T>` pattern for O(1) get/put/evict.
- Move-to-front logic on access (mark as recently used).
- Eviction callback (`OnEvicted`) for flushing dirty pages before removal.

**Adaptation notes:**
- Translate to Rust: `HashMap<PageNum, *mut Node>` + intrusive doubly-linked list.
- Use `unsafe` for raw pointer manipulation (or `Rc<RefCell<>>` for safe alternative).
- Must flush dirty pages in the eviction callback before reclaiming the slot.

**Usage:**
```bash
# Review before implementing tosumu's pager.rs cache
code F:\LocalSource\ClassLibrary\DataStructures\Caches\LruCache.cs
```

---

#### **BloomFilter.cs** — Stage 6+ (negative lookup optimization)
**Path:** `Probabilistic/BloomFilter.cs`

**What to reference:**
- Optimal sizing formula: `m = -n * ln(p) / (ln(2)^2)`, `k = (m/n) * ln(2)`.
- Double-hashing trick for deriving k hash functions from two base hashes.
- False-positive rate estimation as the filter fills.

**Adaptation notes:**
- Tosumu use case: per-page or per-table Bloom filters to skip pages during scans.
- Store filter bits in page header or dedicated metadata page.
- Rebuild filter on page compaction or table rebuild.

**When to implement:** After Stage 2 works and performance profiling shows scan bottlenecks.

**Usage:**
```bash
# Reference when adding Bloom filters (Stage 6+)
code F:\LocalSource\ClassLibrary\DataStructures\Probabilistic\BloomFilter.cs
```

---

#### **RingBuffer.cs** — Stage 3 (WAL buffering)
**Path:** `Buffers/RingBuffer.cs`

**What to reference:**
- Fixed-size circular buffer with head/tail pointers.
- Overwrite semantics when full.
- O(1) push/pop at both ends.

**Adaptation notes:**
- Tosumu use case: batch WAL frames in memory before fsyncing to disk.
- Size = number of dirty pages buffered before flush (e.g., 64 frames).
- On overflow, trigger early flush instead of overwriting.

**Usage:**
```bash
# Review before implementing WAL frame buffering
code F:\LocalSource\ClassLibrary\DataStructures\Buffers\RingBuffer.cs
```

---

### Interesting for future extensions

These are out of scope for Stages 1–6 but could inform hypothetical Stage 7+ work.

#### **MerkleTree.cs** — Hardened integrity mode
**Path:** `Trees/MerkleTree.cs`

**What it offers:**
- O(log n) proof generation and verification.
- Incremental verification (prove one page is authentic without reading entire DB).
- Tamper detection for individual pages.

**Tosumu integration idea:**
- Replace single header MAC with Merkle root over all page hashes.
- Store internal node hashes in a separate metadata page or in-memory.
- Recompute root hash on every page write (expensive but strong).

**Trade-offs:**
- Adds O(log n) storage overhead.
- Write amplification (update page → recompute path to root).
- Benefit: Can prove "page 42 is authentic" without loading entire DB.

**When to consider:** If tosumu needs cryptographic audit logs or wants a "paranoid integrity mode."

---

#### **RTree.cs** — Spatial indexing
**Path:** `Spatial/RTree.cs`

**Relevance:** DESIGN.md §17.3 mentions spatial indexes as a "reasonable Stage 7+ extension." This is a reference implementation for bounding-box splits and nearest-neighbor queries.

---

#### **Trie.cs / RadixTree.cs** — Prefix search
**Path:** `Trees/Trie.cs`, `Trees/RadixTree.cs`

**Relevance:** Simpler than FSTs (DESIGN.md §17.2.1), incrementally mutable. Could be adapted to page-based storage for autocomplete-style queries on string keys. Less compact than FSTs but easier to implement.

---

### Out of scope

The following structures in the DataStructures library are well-implemented but not relevant to tosumu's goals:

- **Text editing structures** (Rope, PieceTable, GapBuffer) — tosumu stores key/value pairs, not documents.
- **Persistent data structures** (PersistentList, PersistentMap) — tosumu uses mutable pages with WAL, not immutable trees.
- **Statistics / Simulation** (EWMA, Markov chains, etc.) — not storage-engine concerns.
- **Graph structures** — tosumu is key/value, not graph traversal (DESIGN.md §17.4 explicitly rules this out).
- **DancingLinks** (exact cover solver) — unrelated to database internals.

---

## DatabaseTools Library (C#)

**Location:** `F:\LocalSource\ClassLibrary\DatabaseTools`

A comprehensive database tooling library with migration runner, schema builder, sync engine, and backup/export/import utilities. Built for SQLite but has design patterns applicable to any embedded database.

### Migration system

#### **ICodeMigration** + **SqliteMigrationRunner** — Directly relevant to DESIGN.md §12
**Path:** `ICodeMigration.cs`, `SqliteMigrationRunner.cs`, `MIGRATIONS.md`

**What to reference:**
- **Version-based migration ordering** — each migration has a `long Version` (uses timestamps like `202602190900`).
- **Up/Down pattern** — forward migration + explicit rollback. Tosumu's §12.6 `FormatMigration` trait mirrors this.
- **Migration history table** — `__MigrationHistory` tracks applied migrations. Tosumu should store this in page 0 header or a system page.
- **Transaction wrapping** — migrations run inside transactions by default, with opt-out for long-running ops.
- **Discovery + sorting** — runner auto-discovers migrations, sorts by version, applies pending ones.

**Adaptation notes:**
- C# version uses `SqliteConnection` + ADO.NET. Tosumu's version works on raw pages.
- Core pattern is identical: versioned changes, recorded history, safe rollback.
- Tosumu's migration categories (§12.2) are more granular (metadata-only vs. page-local vs. destructive).

**Key lesson:** The **migration history table** pattern is crucial. Tosumu should store `(version, name, applied_at, rolled_back_at)` tuples, not just `format_version` in the header.

**Usage:**
```bash
# Review before implementing tosumu's migration system
code F:\LocalSource\ClassLibrary\DatabaseTools\MIGRATIONS.md
code F:\LocalSource\ClassLibrary\DatabaseTools\ICodeMigration.cs
code F:\LocalSource\ClassLibrary\DatabaseTools\SqliteMigrationRunner.cs
```

---

#### **SqliteSchemaBuilder** — Fluent DDL pattern
**Path:** `SqliteSchemaBuilder.cs`

**What to reference:**
- Fluent API for DDL (`CreateTable`, `AddColumn`, `CreateIndex`, etc.).
- Table-level constraints (primary key, foreign key, unique).
- Accumulates statements, then executes as a batch.

**Tosumu use case:**
- If tosumu's Stage 5 SQL layer grows DDL support (`CREATE TABLE`, `CREATE INDEX`), this is a reference for the builder pattern.
- Not urgent for Stage 1–4 (hand-written page layouts), but useful for Stage 5+.

---

### Sync engine

#### **SyncEngine** + **ISyncChangeLog** — Ideas for future multi-device sync
**Path:** `SyncEngine.cs`, `SqliteSyncChangeLog.cs`, `SYNC.md`

**What it does:**
- **Change tracking** — captures INSERT/UPDATE/DELETE via application-level triggers.
- **ULID-based change IDs** — globally unique, time-sortable, no clock sync required.
- **Bidirectional sync** — push local changes to server, pull remote changes, apply both.
- **Conflict resolution** — LastWriteWins (ULID timestamp), ServerWins, ClientWins, Manual.
- **Watermarks** — track sync progress per remote node, only exchange new changes.
- **Offline-first** — all changes captured locally, sync when connectivity available.

**Tosumu integration idea (Stage 7+, hypothetical):**
- Store change log in a system table: `_sync_changelog(id ULID, table_name, operation, row_key, data, timestamp)`.
- Use tosumu's LSN (log sequence number) instead of ULID for ordering.
- Conflict resolution for distributed tosumu instances (not single-process anymore).
- Would require rearchitecting tosumu from single-writer to multi-writer with coordination.

**Why this is deferred:**
- Tosumu is explicitly single-process (DESIGN.md §1.2).
- Sync is a Stage 7+ extension, not core design.
- But: the **ULID-based change ID** pattern is excellent for globally-ordered events in distributed systems.

**When to reference:** If tosumu ever needs distributed sync, cloud backup, or multi-device replication.

---

### Other useful patterns

- **DatabaseExporter/Importer** — full-DB export to JSON/SQLite/CSV. Useful for tosumu's backup/restore (Stage 4b "backup before migration").
- **SchemaComparer** — detects differences between two databases. Tosumu could use this for migration validation tests.
- **Content packages** — self-contained SQLite files with metadata. Similar to tosumu's fixture files (§10.9).

---

## MemoryStore Library (C#)

**Location:** `F:\LocalSource\ClassLibrary\MemoryStore`

An in-memory virtual file system with URI-based resource management. Thread-safe, no disk I/O, comprehensive text/binary/JSON/XML operations.

### Interesting patterns for tosumu

#### **ConcurrentDictionary with case-insensitive URI keys** — Portable resource lookup
**Path:** `InMemoryResourceStore.cs`

**What to reference:**
- Custom `IEqualityComparer<Uri>` for case-insensitive lookups (cross-platform Windows/Linux compatibility).
- `ConcurrentDictionary<Uri, byte[]>` for thread-safe storage.
- Separate timestamp tracking (`ConcurrentDictionary<Uri, DateTime>`) for metadata.

**Tosumu use case:**
- If tosumu ever needs an in-memory mode (no disk writes, useful for testing), this is the pattern.
- Could be a `Database::open_memory()` constructor that uses a memory-backed pager instead of file I/O.
- Testing: fast, deterministic, no temp file cleanup.

**When to reference:** If Stage 1 testing becomes slow due to disk I/O, or if someone requests an in-memory mode.

---

#### **Content-type inference** — Metadata from file extensions
**Path:** `FEATURE_SUMMARY.md`, `GetContentType` method

**What it does:**
- Maps file extensions to MIME types (`.json` → `application/json`, `.xml` → `text/xml`, etc.).
- Used for serving resources via HTTP or generating metadata.

**Tosumu use case:**
- Not directly relevant (tosumu stores opaque key/value pairs, not files).
- But: if tosumu's Stage 5 SQL layer grows blob storage with content-type metadata, this is a reference.

**Deferred to Stage 5+ or never.**

---

#### **Hashing and comparison** — Integrity checks
**Path:** `GetMD5Hash`, `GetSHA256Hash`, `AreEqual` methods

**What it does:**
- Compute cryptographic hashes (MD5, SHA256) over stored resources.
- Byte-by-byte equality comparison.

**Tosumu use case:**
- Tosumu already has HMAC-SHA256 for header MAC (§8.4) and AEAD tags for pages (§8.2).
- This pattern is useful for **migration validation tests**: compute hash of pre-migration file, run migration, verify hash of specific pages or metadata hasn't changed when it shouldn't.
- Could also be used for **backup integrity** — hash backup files, verify on restore.

**When to reference:** Stage 3+ (WAL checksums), Stage 4 (migration validation), Stage 6 (backup integrity).

---

### Why MemoryStore is less critical for tosumu

MemoryStore is designed for **document processing pipelines** (XML transformations, XSLT, FOP rendering). Tosumu is a **page-based storage engine**. The overlap is smaller than with DataStructures or DatabaseTools.

**What's useful:**
- In-memory mode pattern (testing, fast iteration).
- Thread-safe resource management (if tosumu grows concurrent readers in Stage 6).
- Metadata tracking pattern (timestamps, content types).

**What's not useful:**
- XML/XSLT integration (tosumu stores opaque blobs, not documents).
- URI-based resource resolution (tosumu uses page numbers, not URIs).

---

## SecurityTools Library (C#)

**Location:** `F:\LocalSource\ClassLibrary\SecurityTools`

A comprehensive cryptographic services library with AES-256-GCM, password hashing, key derivation, digital signatures, JWT tokens, and secure random generation.

### High-priority references for tosumu

#### **AesService.cs** — Stage 4 (page AEAD encryption)
**Path:** `AesService.cs`

**What to reference:**
- **AES-256-GCM implementation** — nonce + ciphertext + tag concatenation pattern.
- Nonce size: 12 bytes (96 bits), Tag size: 16 bytes (128 bits) — standard GCM parameters.
- `Encrypt(byte[] data, byte[] key)` → `nonce || ciphertext || tag` format.
- `Decrypt(byte[] encryptedData, byte[] key)` → extracts components, verifies tag, returns plaintext.
- Stream encryption for large files (chunked processing).

**Tosumu parallels:**
- Tosumu uses ChaCha20-Poly1305 instead of AES-GCM (§8.2), but the *pattern* is identical: AEAD with nonce + ciphertext + tag.
- Tosumu's page frame layout (§5.3): `nonce (12) || ciphertext (variable) || tag (16)`.
- Same security properties: authenticated encryption prevents tampering, tag must be verified before using plaintext.

**Key lesson:** The `nonce || ciphertext || tag` serialization format is standard for AEAD. Tosumu's page frame follows this pattern.

---

#### **KeyDerivationService.cs** — Stage 4 (HKDF subkey derivation)
**Path:** `KeyDerivationService.cs`

**What to reference:**
- **HKDF implementation** — RFC 5869 compliant, supports SHA256/384/512.
- `DeriveHkdf(inputKeyMaterial, outputLength, salt, info, hashAlgorithm)` — derives subkeys from a master key.
- `info` parameter for domain separation (different subkeys for different purposes).

**Tosumu parallels:**
- Tosumu's §8.3 uses HKDF-SHA256 to derive `page_key` and `header_mac_key` from DEK.
- Info strings: `"tosumu/v1/page"` and `"tosumu/v1/header-mac"` for domain separation.
- Same pattern: one master DEK → multiple independent subkeys via HKDF.

**Key lesson:** HKDF with domain-specific `info` strings prevents subkey reuse across contexts. This is critical for key hygiene.

---

#### **PasswordHashingService.cs** — Stage 4 (passphrase protector)
**Path:** `PasswordHashingService.cs`

**What to reference:**
- **PBKDF2 password hashing** — 100,000 iterations with HMAC-SHA256.
- Salt generation (16 bytes minimum).
- Password verification (constant-time comparison).

**Tosumu parallels:**
- Tosumu's passphrase protector (§8.6) uses **Argon2id** instead of PBKDF2 (more modern, memory-hard).
- But the *pattern* is the same: `passphrase + salt → KDF → KEK`.
- Tosumu stores salt in the keyslot (§8.7), same as this library stores salt in the hash output.

**Key lesson:** Always use a random salt per password/passphrase. Never reuse salts across different passphrases.

---

### Other useful components

- **SecureRandomService.cs** — cryptographically secure random generation. Useful for nonce generation, DEK generation.
- **JwtService.cs** — JWT tokens. Not relevant to tosumu (no authentication layer), but useful pattern for signed tokens.
- **TotpService.cs** — TOTP/2FA. Could be used for optional 2FA on passphrase protector (Stage 7+).
- **ApiKeyService.cs** — secure API key generation. Could inspire recovery key format (§8.6.2).

---

## VaultServices Library (C#)

**Location:** `F:\LocalSource\ClassLibrary\VaultServices`

Enterprise-grade encrypted storage with **envelope encryption** (DEK/KEK), multiple key protectors (DPAPI, X509, Passphrase), in-memory mode, and transparent compression. **This library implements almost exactly the same envelope encryption design as tosumu §8.**

### Critical references for tosumu Stage 4

#### **VaultKeyManager.cs** — DIRECTLY MATCHES tosumu's protector design (§8.6)
**Path:** `VaultKeyManager.cs`, `KEYMANAGER_INTEGRATION.md`

**What it implements:**
- **Envelope encryption** — DEK (Data Key) wrapped by KEK (Key Encryption Key).
- **Multiple protectors**:
  - **DpapiProtector** — Windows DPAPI (CurrentUser or LocalMachine scope).
  - **X509Protector** — X.509 certificate-based wrapping (cross-platform).
  - **PassphraseProtector** — password-based wrapping (PBKDF2 or Argon2).
- **IKeyProtector interface** — `Protect(plaintext)` → wrapped key, `Unprotect(ciphertext)` → plaintext key.
- **IDataKeyManager** — `GetOrCreateDataKeyAsync()` returns DEK, creates on first run if missing.
- **FileBackedDataKeyManager** — stores wrapped DEK in `vault.keywrap` file on disk.
- **Configuration-driven protector selection** — chooses protector based on platform (Windows → DPAPI, Linux → X509).

**Tosumu parallels — THIS IS A GOLDMINE:**

| VaultServices | tosumu DESIGN.md §8 |
|---|---|
| DEK (Data Key) | DEK (Data Encryption Key) |
| KEK (from protector) | KEK (Key Encryption Key) |
| `IKeyProtector` | Protector types (Passphrase, RecoveryKey, Keyfile, TPM) |
| `Protect()` / `Unprotect()` | Wrap/unwrap operations |
| `DpapiProtector` | Windows-specific protector (tosumu Stage 4c TPM could learn from this) |
| `X509Protector` | X.509 certificate wrapping (tosumu §8.6.5 mentions this) |
| `PassphraseProtector` | Passphrase protector (§8.6.1) — exactly the same |
| Wrapped key on disk | Keyslot region (§8.7) with `wrapped_dek` blobs |
| Multiple protectors | Up to 8 keyslots (§8.7.1) |

**Key lessons:**
1. **IKeyProtector abstraction** — Clean interface for multiple wrapping strategies. Tosumu should use a similar trait.
2. **Protector discovery** — VaultServices chooses protector at runtime based on config. Tosumu hardcodes protector type in keyslot `kind` field.
3. **Wrapped key storage** — VaultServices stores one wrapped DEK in `vault.keywrap`. Tosumu stores up to 8 wrapped DEKs in keyslots.
4. **Configuration-driven** — VaultServices uses appsettings.json. Tosumu uses CLI flags (`tosumu init --encrypt`, `tosumu protector add`).

**CRITICAL INSIGHT:** This library proves the envelope encryption design works in production. Tosumu's §8 is not speculative — it's a proven pattern.

**Usage:**
```bash
# MUST READ before implementing tosumu Stage 4a/4b
code F:\LocalSource\ClassLibrary\VaultServices\VaultKeyManager.cs
code F:\LocalSource\ClassLibrary\VaultServices\KEYMANAGER_INTEGRATION.md
```

---

#### **EncryptedVaultService.cs** — File-based encrypted vault pattern
**Path:** `EncryptedVaultService.cs`

**What to reference:**
- **AES-256-GCM vault encryption** — all files encrypted with same DEK.
- **Backup rotation** — keeps last N backups before overwriting.
- **In-place updates** — overwrites encrypted files after writing new version.

**Tosumu parallels:**
- VaultServices encrypts files. Tosumu encrypts pages. Same AEAD pattern.
- Backup rotation → tosumu's §12.5 "automatic .bak files before migrations."
- In-place updates → tosumu's WAL ensures crash-safety; VaultServices relies on atomic file writes.

---

#### **MemoryVaultService.cs** + **CompressedVaultService.cs** — In-memory mode and compression
**Path:** `MemoryVaultService.cs`, `CompressedVaultService.cs`

**What they offer:**
- **MemoryVaultService** — in-memory vault (no disk I/O), useful for testing.
- **CompressedVaultService** — transparent compression wrapper (GZip/Brotli/Deflate).

**Tosumu use cases:**
- In-memory mode for fast testing (`Database::open_memory()`).
- Compression is out of scope (§1.2 non-goals), but pattern is here if requested.

---

### Why VaultServices is critical for tosumu

**This library implements the exact same envelope encryption architecture as tosumu's DESIGN.md §8.** The parallels are striking:

- DEK wraps data (files vs. pages).
- KEK wraps DEK (protectors: DPAPI/X509/Passphrase).
- Multiple protectors supported (any one can unlock).
- Wrapped keys stored on disk (vault.keywrap vs. keyslots).

**If tosumu's Stage 4 crypto design feels uncertain, study VaultServices.** It's production-ready and already deployed. The patterns are proven.

---

## SignalHubTools Library (C#)

**Location:** `F:\LocalSource\ClassLibrary\SignalHubTools`

A lightweight publish/subscribe event bus for decoupled cross-component communication. Thread-safe, exception-isolated, topic-based.

### Interesting for tosumu (Stage 6+ extensions)

#### **SignalHub.cs + ISignalHub** — Pub/sub event system
**Path:** `SignalHub.cs`, `ISignalHub.cs`

**What it offers:**
- **Publish(topic, payload)** — broadcast event to all subscribers of `topic`.
- **Subscribe(topic, handler)** — register handler, returns `IDisposable` for cleanup.
- **Exception isolation** — if one handler throws, others still run. Errors logged, not propagated.
- **Thread-safe** — uses `ConcurrentDictionary` + lock for subscription management.
- **Topic-based routing** — subscribers only see events they care about.

**Tosumu use case (Stage 6+ extensions):**
- **Internal event system** — trigger hooks for custom behavior:
  - `tosumu.page_allocated` → custom logging, telemetry.
  - `tosumu.transaction_committed` → invalidate external caches, fire webhooks.
  - `tosumu.wal_checkpoint` → notify monitoring system.
- **Plugin architecture** — Stage 7+ could expose `ISignalHub` to plugins for lifecycle events.

**Used by DatabaseTools:**
- DatabaseTools' `DatabaseTriggerHub` (application-level triggers) is built on SignalHub.
- Triggers fire `Before/After Insert/Update/Delete` events via SignalHub's pub/sub.

**Pattern lesson:** Pub/sub with exception isolation is excellent for decoupling. If a subscriber crashes, the publisher continues.

---

## Composite learnings across all libraries

### Pattern: Envelope encryption (DEK/KEK)
**Seen in:** VaultServices, implicitly in SecurityTools (HKDF).

**How it works:**
1. Generate random DEK (32 bytes).
2. Encrypt data with DEK (AES-GCM or ChaCha20-Poly1305).
3. Derive or wrap DEK with KEK (from passphrase, certificate, TPM, etc.).
4. Store wrapped DEK + encrypted data.
5. To unlock: Unwrap DEK with KEK, decrypt data with DEK.

**Benefits:**
- Rotate KEK (change passphrase) without re-encrypting data.
- Multiple KEKs can wrap the same DEK (multiple protectors).
- DEK is random, high-entropy (better than password-derived keys).

**tosumu's implementation (§8):** Exact same pattern. VaultServices proves it works in production.

---

### Pattern: HKDF subkey derivation
**Seen in:** SecurityTools (KeyDerivationService).

**How it works:**
1. One master key (DEK).
2. Derive multiple subkeys via HKDF with domain-specific `info` strings.
3. Each subkey used for a different purpose (encryption, MAC, signing, etc.).

**Benefits:**
- One secret to protect (DEK), multiple independent keys derived.
- Domain separation prevents key reuse across contexts.

**tosumu's implementation (§8.3):** DEK → HKDF-SHA256 → `page_key` + `header_mac_key`.

---

### Pattern: Protector abstraction
**Seen in:** VaultServices (IKeyProtector).

**How it works:**
1. Define interface: `Protect(plaintext) → ciphertext`, `Unprotect(ciphertext) → plaintext`.
2. Implement multiple protectors: DPAPI, X509, Passphrase, Keyfile, TPM.
3. Store wrapped DEK + metadata in keyslot.

**Benefits:**
- Add new protectors without changing core encryption logic.
- Users choose protector based on security requirements.

**tosumu's implementation (§8.6, §8.7):** Up to 8 keyslots, each with `kind` field. Same abstraction.

---

## Summary of relevance to tosumu

| Library | Directly relevant | When to reference |
|---|---|---|
| **DataStructures** | BPlusTree, LruCache, BloomFilter, RingBuffer | Stage 1 (LRU), Stage 2 (B+tree), Stage 3 (Ring), Stage 6+ (Bloom) |
| **DatabaseTools** | Migration system, schema builder, sync engine | Stage 1+ (migrations §12), Stage 5+ (DDL), Stage 7+ (sync) |
| **MemoryStore** | In-memory mode, hashing/comparison | Stage 1+ (testing), Stage 3+ (integrity checks) |
| **SecurityTools** | AES-GCM, HKDF, PBKDF2, secure random | **Stage 4 (critical)** — crypto primitives and patterns |
| **VaultServices** | Envelope encryption, protectors, key management | **Stage 4 (critical)** — direct parallel to §8 design |
| **SignalHubTools** | Pub/sub event system | Stage 6+ (hooks, plugins), optional |

**Top priority for Stage 4:** VaultServices + SecurityTools. They implement exactly what tosumu needs.

---

## UlidTools Library (C#)

**Location:** `F:\LocalSource\ClassLibrary\UlidTools`

A ULID (Universally Unique Lexicographically Sortable Identifier) implementation. ULID is a 128-bit identifier combining **48-bit millisecond timestamp** + **80-bit cryptographic randomness**, encoded as a 26-character Crockford Base32 string.

### Why ULID matters

**ULID vs GUID:**
- ✅ Time-ordered / sortable (GUIDs are random)
- ✅ Extract creation timestamp (GUIDs can't)
- ✅ Better DB index performance (monotonic, not random)
- ✅ Shorter string representation (26 chars vs 36 for GUID)

**Used by DatabaseTools' sync system (§DatabaseTools SYNC.md):**
- Change IDs in `_sync_changelog` table use ULIDs
- Globally unique, no clock sync needed
- Time-sortable for change ordering
- Embedded timestamp for conflict resolution (LastWriteWins uses ULID timestamp)

### Relevance to tosumu

#### **Potential use for LSN (Log Sequence Number)**
**Current design (§5.3, §7):** LSN is `u64` (8 bytes), just a counter.

**ULID alternative:**
- **128-bit LSN** = 48-bit timestamp + 80-bit entropy
- Extract WAL entry timestamp without separate field
- Still monotonic (timestamp increases)
- Useful for distributed tosumu (Stage 7+): globally-ordered LSN without coordination

**Trade-off:**
- Pros: Embedded timestamp, globally unique, sortable
- Cons: Larger (16 bytes vs 8 bytes), overkill for single-process (current tosumu)

**Verdict:** Not needed for Stages 1–6 (single-process). Revisit for Stage 7+ if tosumu grows distributed/replicated features.

---

#### **Potential use for change tracking (Stage 7+ sync)**
If tosumu implements multi-device sync (like DatabaseTools' SyncEngine), ULID would be ideal for change IDs:
- `_sync_changelog(change_id ULID, table_name, operation, row_key, data, ...)`
- ULID timestamp enables LastWriteWins conflict resolution
- No need for separate `timestamp` column

**When to reference:** Stage 7+ if tosumu grows sync/replication capabilities.

---

#### **Potential use for transaction IDs**
Currently tosumu doesn't expose transaction IDs (Stage 3 just has an implicit transaction per `commit`).

**ULID TxnID benefits:**
- Timestamp embedded → know when transaction started
- Unique across database restarts (unlike counter reset)
- Useful for audit logs, debugging ("show me transactions from 9 AM to noon")

**Verdict:** Nice-to-have for Stage 3+, not critical.

---

### Implementation quality

**UlidTools code characteristics:**
- Zero dependencies (pure .NET 8)
- `readonly struct Ulid` with explicit layout (`[StructLayout(LayoutKind.Explicit)]`)
- Big-endian byte order for natural string sort = chronological sort
- Crockford Base32 encoding (excludes ambiguous chars: I, L, O, U)
- Range query helpers: `MinValueForTimestamp`, `MaxValueForTimestamp`
- `IUlidProvider` abstraction for DI and testing (deterministic provider for tests)

**Key lesson:** When you need time-sortable IDs, ULID is a proven pattern. Don't invent your own format.

**Usage:**
```bash
# Review if tosumu grows distributed features or needs time-sortable IDs
code F:\LocalSource\ClassLibrary\UlidTools\Ulid.cs
code F:\LocalSource\ClassLibrary\UlidTools\README.md
```

---

## Other ClassLibrary projects

**Location:** `F:\LocalSource\ClassLibrary` (241 projects total)

The ClassLibrary is a massive enterprise toolkit with ~75 infrastructure libraries. Most are not relevant to tosumu (document processing, XSLT, FOP, PDF, AI tools, web tools, etc.).

**Already documented:**
- DataStructures (65+ structures)
- DatabaseTools (migrations, sync, schema)
- MemoryStore (in-memory virtual file system)
- SecurityTools (crypto primitives)
- VaultServices (envelope encryption)
- SignalHubTools (pub/sub events)
- UlidTools (time-sortable IDs)

**Potentially interesting but lower priority:**

### AuditLog — Structured logging
**Path:** `F:\LocalSource\ClassLibrary\AuditLog`

**What it offers:**
- Structured audit logging with EventId system (Windows Event Viewer style)
- Event categories: UserEvents, SystemEvents, APIEvents, AdminEvents, ServiceEvents, SecurityEvents
- EF Core integration, correlation IDs, task tracking

**Tosumu use case:**
- If tosumu needs structured logging (Stage 6+ observability)
- EventIds for database events: `2001 - ApplicationStarted`, `1102 - DataModification`, `2101 - SystemError`
- Probably overkill for a learning project — Rust `tracing` crate is simpler

---

### CronTools — Scheduling
**Path:** `F:\LocalSource\ClassLibrary\CronTools`

**What it offers:**
- Cron expression parser and scheduler
- Job tracking and execution

**Tosumu use case:**
- Stage 6 `VACUUM` — schedule automatic space reclamation
- Checkpoint scheduling (run WAL checkpoint every N minutes)

**Verdict:** Nice-to-have for Stage 6+, not urgent.

---

### IndexServices — In-memory inverted index
**Path:** `F:\LocalSource\ClassLibrary\IndexServices`

**What it offers:**
- Simple in-memory inverted index for text search
- Tokenization, scoring, metadata

**Tosumu use case:**
- Related to §17 (advanced indexing), but tosumu already ruled out full-text search
- If someone wants lightweight keyword search, this is simpler than Tantivy

**Verdict:** Out of scope per §17.2.2. Mentioned in DESIGN.md already.

---

## Summary: What to use from ClassLibrary

**Critical for tosumu:**
- **VaultServices** — Stage 4 (envelope encryption, protectors)
- **SecurityTools** — Stage 4 (AES-GCM, HKDF, Argon2 patterns)
- **DataStructures** — Stage 1 (LRU cache), Stage 2 (B+ tree), Stage 3 (ring buffer), Stage 6+ (Bloom filter)
- **DatabaseTools** — Stage 1+ (migrations), Stage 5+ (DDL), Stage 7+ (sync)

**Useful for extensions:**
- **UlidTools** — Stage 7+ (time-sortable LSN, sync change IDs)
- **MemoryStore** — Stage 1+ (in-memory mode for testing)
- **SignalHubTools** — Stage 6+ (internal event hooks)
- **AuditLog** — Stage 6+ (structured logging, observability)
- **CronTools** — Stage 6+ (VACUUM scheduling, checkpoint scheduling)

**Out of scope:**
- Everything else (document processing, XSLT, FOP, AI, web tools, etc.) — not storage engine concerns.

---

## Other references

### SQLite source code
**URL:** https://www.sqlite.org/src/doc/trunk/README.md

**What to study:**
- B-tree implementation in `btree.c` — page-based node representation, overflow pages, cell format.
- Pager in `pager.c` — page cache, dirty page tracking, write-ahead log integration.
- WAL implementation in `wal.c` — frame format, checkpointing, readers/writer coordination.

**Tosumu differences:**
- SQLite is unencrypted by default (encryption via extensions like SQLCipher).
- SQLite's B-tree is more complex (supports interior data, overflow chains, etc.).
- Tosumu's design is simpler by choice (no overflow pages in Stage 1, no interior data).

---

### LevelDB / RocksDB source code
**URL:** https://github.com/google/leveldb

**What to study (if considering LSM-tree mode in §17.3):**
- SSTable format (sorted string table) — immutable files with Bloom filters.
- Compaction strategies (leveled, tiered).
- Memtable + write-ahead log pattern.

**Tosumu differences:**
- LevelDB is LSM-based (append-only, periodic compaction).
- Tosumu uses in-place B+ tree updates with WAL.
- If LSM mode is ever added, this is the reference.

---

### RustCrypto crates documentation
**URL:** https://docs.rs/chacha20poly1305/, https://docs.rs/argon2/

**What to reference:**
- AEAD API patterns (encrypt_in_place, decrypt_in_place).
- AAD construction best practices.
- Argon2id parameter selection (memory cost, iterations, parallelism).

**Critical for Stage 4.**

---

---

## Tonesu (Conlang Design Project)

**Location:** `F:\LocalSource\Tonesu`

A constructed language project. Not a code library — a design artifact. Referenced here because the design decisions made during Tonesu's development produced transferable lessons that have been directly incorporated into DESIGN.md.

The core connection: both projects are attempts to build a coherent, self-consistent system from a small set of fixed primitives, where later extensions must compose on top of stable roots rather than revising them. The failure modes are structurally similar.

### Lessons incorporated into DESIGN.md

These are not analogies — they are direct derivations. The DESIGN.md sections listed are where each lesson was applied.

#### The Wilkins failure → §13 format stability policy
John Wilkins (1668) built *An Essay Towards a Real Character, and a Philosophical Language* — every word encoded its taxonomic position. When the taxonomy was revised, all vocabulary had to change. The language was obsolete before it was finished.

**Applied:** The on-disk page layout, AEAD construction, and keyslot format are Tosumu's primitive roots. They are frozen after Stage 2. New features grow by composition. `format_version` bumps are the controlled exceptions. The migration system exists for those exceptions.

**File:** `F:\LocalSource\Tonesu\spec\domain-creation.md` → §4 Stability Rule

---

#### Tarski hierarchy → §4 layer dependency as structural invariant
Tonesu's evidential frame `vund…vunds` enforces that the framing level (N+1) refers to the content level (N), but the content cannot reference its container. This is why the Liar Paradox is unexpressible in Tonesu — not forbidden, structurally impossible.

**Applied:** The Tosumu layer diagram (CLI → Query → B+tree → Transaction/WAL → Pager → Crypto → File I/O) is a DAG enforced by module visibility rules, not by convention. Safety-by-convention degrades under time pressure.

**File:** `F:\LocalSource\Tonesu\corpus\translations\Philosophy\liar-paradox.md` → Structural Blocks 1 & 2

---

#### The `go` / `;` distinction → §2 principle 10 (sequence vs. grounding)
PRF-001 established that Tonesu has two irrecducible connectors: `;` (constant conjunction — A then B, no claim about why) and `go` (necessary connection — A constitutively grounds B). The Cogito requires `go`; the `;` version (S687) is grammatical and true but is what Hume would accept and Descartes would reject.

**Applied:** `fsync` returning `Ok` followed by data being durable is `;`-grade evidence unless the OS contract makes `Ok` mean bytes-on-stable-storage (making it `go`-grade). On a network filesystem the same `Ok` is explicitly `;`-only. Every durability claim in Tosumu should state which kind it is. Verify-after-write + AEAD re-check is the response when a claim is sequence-only.

**File:** `F:\LocalSource\Tonesu\corpus\translations\Philosophy\proof-structure.md` → S687/S688 minimal pair

---

#### AEAD freshness bound → §8.10 / §21.10
Monday's review of §21.10 identified that AEAD proves *authorship at the claimed version*, not *recency*. An old authentic page frame still verifies. The parallel in Tonesu is that evidential-frame content can be authentic at level N without being the current statement at level N+1 — the frame proves origin, not currency.

**File:** `F:\LocalSource\Tonesu\corpus\translations\Philosophy\liar-paradox.md` → Three-Way Verdict table

---

#### Resist ontological over-determination → §9 naming principle
DOI-001 S636 initially used `go to-ne-su` (the organized-truth concept) to render "self-evident." The correction: Jefferson's claim is deliberately not anchored to a specific ontological framework — the over-determined name commits to a causal story the source text avoids. Corrected to bare `go to` (primitive reason/principle).

**Applied:** Error variant names in §9 should commit to the observable phenomenon, not the detection mechanism. `Corrupt { pgno }` (phenomenon) is preferable to a mechanism-name when the same observable symptom could be produced by different paths.

**File:** `F:\LocalSource\Tonesu\corpus\translations\Literature\` → DOI-001 batch

---

#### Strategic vagueness vs. unspecified → §2 principle 11
CDA-001 translated 47 U.S.C. §230 and discovered that `~su-ka-li` and `~si-go-li` (the "provider" and "publisher" categories) are not vague by accident — they are vague by design. `wi-fe'ka-to-fe` ("shall be treated as") suppresses the fuzziness for liability purposes; every new generation of §230 litigation is a case where the suppressed fuzziness re-surfaces.

**Applied:** "Unspecified" (implementation-defined; callers must not rely on it) and "undefined" (any result, including corruption, is permitted) are different design choices with different compatibility implications. Both must be explicitly labeled. The `scan_physical()` / `scan_by_key()` split is the canonical Tosumu example — replacing a vague `scan()` with two explicit contracts.

**File:** `F:\LocalSource\Tonesu\corpus\translations\Law\cda-section230.md` → `~` operator analysis

---

#### Structural impossibility over advisory rules → §2 principle 8
Tonesu's approach to guardrails is consistent: wherever possible, the dangerous thing is made unexpressible, not just discouraged. The Liar Paradox, cross-layer frame references, metalanguage-reaching-down are all structural impossibilities, not documented pitfalls.

**Applied:** `Err`-returning write closures cannot accidentally commit. `AuthFailed` is not `Ok(suspicious_bytes)`. `#[forbid(unsafe_code)]` is a compiler proof. When a design decision results in a warning in the docs, ask first whether a redesign could make the warning unnecessary.

---

#### Three-caller rule → §2 principle 9
Tonesu does not admit a new particle, construction, or rule until it has at least three independent qualifying corpus attestations across different registers. One attestation writes the form for its own convenience. Two suggest a pattern. Three reveal the actual contract. The `ke` correction-pivot particle required three attestations in three different register contexts (debate, medical, diplomatic) before admission.

**Applied:** Tosumu traits and public APIs are not locked until three independent, concrete callers drive their shape. `KeyProtector` earns its trait because `Passphrase`, `RecoveryKey`, and `Tpm` are independently motivated. Single-caller convenience wrappers stay concrete.

**File:** `F:\LocalSource\Tonesu\notes\open-questions.md` → OQ-COR-001 resolution

---

### What to read in Tonesu

| File | What it illustrates |
|------|-------------------|
| `spec/principles.md` | The 9 normative principles of the language — compare directly with DESIGN.md §2 |
| `spec/domain-creation.md` | The Stability Rule (§4) and Wilkins lesson; domain-as-namespace = crate-as-namespace |
| `corpus/translations/Philosophy/proof-structure.md` | `go` vs `;` — sequence vs. grounding; the minimal Cogito pair |
| `corpus/translations/Philosophy/liar-paradox.md` | Tarski hierarchy; structural impossibility; AEAD freshness bound parallel |
| `corpus/translations/Law/cda-section230.md` | `~` structural vagueness; unspecified vs. undefined; suppression via naming |
| `notes/open-questions.md` | Three-attestation rule in practice; how design decisions accumulate |
| `ARCHITECTURE.md` | Source-of-truth / derived-artifact separation applied to a conlang build pipeline |

---

## How to use this document

1. **Before starting a stage**, read the DESIGN.md section for that stage.
2. **Before implementing a module** (e.g., `btree.rs`), review the corresponding reference from this document.
3. **Copy algorithms, not code.** These references are in C# or C; tosumu is Rust. Understand the algorithm, then write idiomatic Rust.
4. **Test everything.** Even proven algorithms can have bugs when adapted to a new context (page-based storage, encryption, etc.).

This document is a living reference. Add new entries as useful implementations are discovered.
