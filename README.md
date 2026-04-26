# tosumu

> *knowledge-organization device*

`tosumu` is a small, page-based, authenticated-encrypted embedded database written in Rust. It is an **academic / learning project** — a clean-room implementation inspired by SQLite's structure, with per-page AEAD and envelope (DEK/KEK) key management designed in from day one rather than bolted on.

The name is a conlang word: `to` (knowledge) + `su` (organized structure) + `mu` (object / device) → *knowledge-organization device*.

## Status

**MVP +7 complete.** The core storage engine and full encryption/key-management stack are implemented and tested. 125 tests pass across `tosumu-core` and `tosumu-cli`, including an adversarial suite covering crash simulation, cross-DB splice attacks, snapshot rollback, slot-reuse stale-AAD, and structural invariant sweeps.

| MVP | Capability | State |
|---|---|---|
| 0 | Append-log store, CLI (put/get/scan) | ✅ done |
| +1 | Real on-disk format: 4 KB pages, slotted layout, freelist | ✅ done |
| +2 | Debug trio: `dump`, `hex`, `verify`; fuzz target for page decode | ✅ done |
| +3 | B+ tree index, overflow pages, sorted scan | ✅ done |
| +4 | Write-ahead log, transactions, crash recovery | ✅ done |
| +5 | `CrashWriter` harness, `check_invariants()`, property tests | ✅ done |
| +6 | Envelope encryption: per-page AEAD, single passphrase protector, KATs | ✅ done |
| +7 | Multiple protectors: up to 8 keyslots, recovery key, KEK rotation, `protector` CLI | ✅ done |
| +8 | Interactive TUI viewer (`tosumu view`) | 🔲 next |
| +9 | Toy SQL layer | 🔲 planned |
| +10 | MVCC / multiple readers | 🔲 planned |

## Warning

> **This is a learning project. Do not use `tosumu` to protect real secrets.**
>
> The crypto design is carefully documented, but it is not audited, not reviewed, not hardened, and not production-ready. See [`SECURITY.md`](SECURITY.md).

## What it is

- **Single-file, single-process, embedded** — like SQLite in shape.
- **4 KB pages** — slotted layout, B+ tree index, overflow pages for large values.
- **Write-ahead log** — physical (full-page) logging, crash-recoverable at any write site.
- **Per-page AEAD** — ChaCha20-Poly1305; page number, version, and type bound as AAD.
- **Envelope encryption** — random DEK per database, HKDF-derived page key and MAC key. DEK wrapped by up to 8 independent **protectors** (passphrase or recovery key today; keyfile, TPM, Secure Enclave planned). Rotate a passphrase without rewriting pages.
- **Header MAC** — HMAC-SHA256 over the full keyslot region; protector-swap and cross-DB splice attacks are rejected at open time.
- **`#![forbid(unsafe_code)]`** throughout.

## What it is not

- Not SQL-complete, not a query optimizer, not a planner (planned for MVP+9).
- Not multi-process or multi-reader (planned for MVP+10).
- Not networked.
- Not a drop-in SQLite replacement.
- Not audited crypto.

## Build and run

```sh
cargo build --release
cargo test --workspace

# Unencrypted DB
cargo run -- init app.tsm
cargo run -- put app.tsm hello world
cargo run -- get app.tsm hello

# Encrypted DB
cargo run -- init --encrypt app.tsm           # prompts for passphrase
cargo run -- protector add-recovery app.tsm   # displays one-time recovery key
cargo run -- protector list app.tsm
cargo run -- rekey-kek --slot 0 app.tsm       # rotate passphrase without page rewrite
```

MSRV: Rust 1.75, edition 2021.

## Crypto stack (summary)

| Primitive | Use |
|---|---|
| ChaCha20-Poly1305 | Per-page AEAD |
| HKDF-SHA256 | DEK → page_key, header_mac_key, audit_key |
| Argon2id (m=65536, t=3, p=1) | Passphrase → KEK |
| HMAC-SHA256 | Header MAC over keyslot region |
| ChaCha20-Poly1305 | DEK wrap/unwrap |
| HKDF-SHA256 (no Argon2id) | Recovery key → KEK |

Full details: `DESIGN.md §8`.

## Fuzz targets

Six `cargo fuzz` targets in `fuzz/fuzz_targets/`: page decode, B+ tree ops, WAL replay, AEAD frame, keyslot parse, and B+ tree crash boundaries. Run manually before each milestone: `cargo fuzz run <target> -- -max_total_time=300`.

## Roadmap

See [`DESIGN.md §12`](DESIGN.md) for the full MVP and stage breakdown. Next milestone is MVP+8 — an interactive TUI viewer (`ratatui` + `crossterm`) for inspecting file header, pages, B+ tree structure, WAL records, and per-keyslot detail on encrypted databases. The Windows WPF harness remains a parallel diagnostic surface for fast inspection and triage; it does not replace the TUI milestone.

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))
- MIT license ([`LICENSE-MIT`](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Further reading

- [`DESIGN.md`](DESIGN.md) — the design doc. Source of truth for all decisions.
- [`INSPECT_API.md`](INSPECT_API.md) — machine-readable inspection contract for the TUI, harness, and future companion tools.
- [`SECURITY.md`](SECURITY.md) — threat model summary and responsible disclosure.
- [`REFERENCES.md`](REFERENCES.md) — reference implementations that informed the design.
