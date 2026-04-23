# Security Policy

## This is a learning project

`tosumu` is an **academic / learning project**. It implements authenticated encryption, envelope key management, and a write-ahead log — but these are implemented by the author as an exercise, not by a cryptography team, and they have not been independently reviewed or audited.

> **Do not use `tosumu` to protect real secrets.**
>
> Use a mature, reviewed storage engine (e.g. SQLCipher, age-encrypted storage, or a purpose-built vault) if you need production-grade confidentiality or integrity.

## Threat model

See `DESIGN.md §8.1` (in scope) and `DESIGN.md §8.10–8.11` (explicit non-goals and known limitations). In brief:

**In scope**

- Attacker with read/write access to the database file at rest.
- Page swap, page rollback (single-page), page reorder, truncation, bit-flipping.
- Wrong-passphrase / wrong-protector rejection.

**Out of scope**

- Attacker with memory access to the running process.
- Side channels (cache timing, power, microarchitectural).
- Traffic analysis of file-modification patterns.
- Plaintext recovery from OS swap, hibernation, or crash dumps.
- Consistent multi-page rollback (acknowledged limitation; see `DESIGN.md §5.3`).
- Remote attestation, network key escrow, KMS integration.

## Reporting a vulnerability

If you believe you have found a cryptographic or integrity-affecting flaw in the design or implementation, please report it privately rather than by public issue.

- **Preferred:** use GitHub's [private vulnerability reporting](https://github.com/Arakendo/tosumu/security/advisories/new) if enabled on the repository.
- **Fallback:** open an issue titled `SECURITY: <short summary>` and immediately email the maintainer without including exploit details.

Because this is a learning project maintained on a best-effort basis, please understand:

- There is **no SLA** for response or fix.
- There is **no coordinated-disclosure pipeline** and no CVE assignment process.
- Fixes land in `main`; there are no backport branches.

## Scope of "security" fixes

Issues that will be taken seriously:

- Bypass of AEAD verification.
- Key leakage (in-memory or on-disk) outside the documented threat model.
- AAD construction flaws that allow page swap / rollback / reorder beyond what `DESIGN.md` already calls out as known limitations.
- Any cryptographic primitive misused against its documented constraints.

Issues that are **expected behavior** and not bugs:

- The attacker can tell how big the database file is.
- The attacker can tell which pages changed between snapshots.
- Keys in process memory are readable by other code in that process.
- Losing all protectors makes the database unrecoverable (that is the point).
- Downgrading to an older `format_version` is not supported.

## Dependencies

`tosumu` uses audited primitives from the [RustCrypto](https://github.com/RustCrypto) ecosystem (`chacha20poly1305`, `hmac`, `sha2`, `hkdf`, `argon2`) and avoids hand-rolled cryptographic primitives. The *composition* of those primitives is original and is the part most likely to contain flaws.
