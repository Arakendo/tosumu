# tosumu

> *knowledge-organization device*

`tosumu` is a small, page-based, authenticated-encrypted embedded database written in Rust. It is an **academic / learning project** — a clean-room implementation inspired by SQLite's structure, with per-page AEAD and envelope (DEK/KEK) key management designed in from day one rather than bolted on.

The name is a conlang word: `to` (knowledge) + `su` (organized structure) + `mu` (object / device) → *knowledge-organization device*.

## Status

**Pre-alpha.** No stage has shipped yet. Design is in [`DESIGN.md`](DESIGN.md); that is the source of truth until the first stage releases.

## Warning

> **This is a learning project. Do not use `tosumu` to protect real secrets.**
>
> The crypto design is carefully documented, but it is not audited, not reviewed, not hardened, and not production-ready. See [`SECURITY.md`](SECURITY.md).

## What it aims to be

- **Single-file, single-process, embedded** — like SQLite in shape. Runs on desktop (Linux, macOS, Windows) and mobile (iOS, Android via Stage 7+ FFI layer).
- **Page-based** — 4 KB pages, slotted layout, B+ tree index.
- **Write-ahead log** — physical (full-page) logging, crash-recoverable.
- **Per-page AEAD** — ChaCha20-Poly1305, with page number, version, and type bound as AAD.
- **Envelope encryption** — random DEK per database; DEK wrapped by one or more **protectors** (passphrase, recovery key, keyfile, TPM on desktop, Keychain on iOS, Keystore on Android). Rotate a passphrase without rewriting pages.
- **Explicit migrations** — safe additive migrations run automatically; destructive ones require an explicit call. See `DESIGN.md §12`.
- **Finishable by a mortal.** Staged roadmap, each stage runnable and testable on its own.

## What it explicitly is not

- Not SQL-complete, not a query optimizer, not a planner.
- Not multi-process.
- Not networked.
- Not a drop-in SQLite replacement.
- Not audited crypto.

## Roadmap

See `DESIGN.md §11` for desktop stages and `DESIGN.md §18` for mobile platform support. In brief:

| Stage | Focus |
|---|---|
| 1 | Storage only: pages, freelist, slotted records, CLI |
| 2 | B+ tree index, overflow pages |
| 3 | Transactions + WAL + crash recovery |
| 4a | Envelope encryption with one protector |
| 4b | Multiple protectors, recovery key, KEK rotation |
| 4c | Optional TPM protector (feature-flagged) |
| 5 | Toy SQL layer |
| 6 | Stretch: MVCC, secondary indexes, benchmarks |
| 7+ | Mobile: FFI layer, iOS (Keychain protector), Android (Keystore protector) |

## Build

Once the workspace lands (Stage 1):

```sh
cargo build --release
cargo test
cargo run -- init app.tsm
cargo run -- put app.tsm hello world
cargo run -- get app.tsm hello
```

Minimum Rust version and exact commands will be pinned in `rust-toolchain.toml` once it exists.

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))
- MIT license ([`LICENSE-MIT`](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Further reading

- [`DESIGN.md`](DESIGN.md) — the design doc. Read this first.
- [`SECURITY.md`](SECURITY.md) — threat model summary and reporting.
- [`REFERENCES.md`](REFERENCES.md) — reference implementations and resources that inform tosumu's design.
