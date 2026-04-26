# Inspect API

`tosumu-cli` exposes a machine-readable inspection contract for downstream tools such as the TUI, the WPF harness, and future companion tooling.

The current schema version is `1`.

## Common Envelope

Every `tosumu inspect ... --json` command returns the same top-level envelope:

```json
{
  "schema_version": 1,
  "command": "inspect.header",
  "ok": true,
  "payload": {},
  "error": null
}
```

Fields:

- `schema_version`: integer schema version for the JSON contract.
- `command`: stable command identifier such as `inspect.header` or `inspect.verify`.
- `ok`: `true` on success, `false` when the command failed or inspection found a failing status.
- `payload`: command-specific payload. Omitted or `null` on error.
- `error`: structured error payload. Omitted or `null` on success.

Error payload shape:

```json
{
  "kind": "invalid_argument",
  "message": "invalid argument: page number out of range",
  "pgno": null
}
```

Current `error.kind` values emitted by the CLI contract:

- `wrong_key`
- `auth_failed`
- `corrupt`
- `invalid_argument`
- `file_busy`
- `unsupported`
- `io`

## Current Commands

### `inspect.header`

Returns file-header fields plus slot-0 keyslot metadata.

Important payload fields:

- `format_version`
- `page_size`
- `min_reader_version`
- `flags`
- `page_count`
- `freelist_head`
- `root_page`
- `wal_checkpoint_lsn`
- `dek_id`
- `keyslot_count`
- `keyslot_region_pages`
- `slot0.kind`
- `slot0.kind_byte`
- `slot0.version`

### `inspect.verify`

Returns per-page integrity results plus the B-tree invariant result.

Important payload fields:

- `pages_checked`
- `pages_ok`
- `issue_count`
- `issues[]`
- `page_results[]`
- `btree.checked`
- `btree.ok`
- `btree.message`

### `inspect.pages`

Returns a lightweight page summary for every data page.

Important payload fields:

- `pages[].pgno`
- `pages[].page_version`
- `pages[].page_type`
- `pages[].page_type_name`
- `pages[].slot_count`
- `pages[].state`
- `pages[].issue`

Page states currently emitted:

- `ok`
- `auth_failed`
- `corrupt`
- `io`

### `inspect.page`

Returns one decoded page and its records.

Important payload fields:

- `pgno`
- `page_version`
- `page_type`
- `page_type_name`
- `slot_count`
- `free_start`
- `free_end`
- `records[]`

Record kinds currently emitted:

- `Live`
- `Tombstone`
- `Unknown`

### `inspect.wal`

Returns the presence and decoded summary of the WAL sidecar.

Important payload fields:

- `wal_exists`
- `wal_path`
- `record_count`
- `records[]`

WAL record kinds currently emitted:

- `begin`
- `page_write`
- `commit`
- `checkpoint`

### `inspect.tree`

Returns the current B-tree root and a recursive tree summary.

Important payload fields:

- `root_pgno`
- `root`
- `root.children[]`
- `root.children[].relation`
- `root.children[].separator_key_hex`

Tree child relations currently emitted:

- `leftmost`
- `separator`

### `inspect.protectors`

Returns configured keyslot / protector summaries.

Important payload fields:

- `slot_count`
- `slots[].slot`
- `slots[].kind`
- `slots[].kind_byte`

## Compatibility Rules

- New tools should branch on `schema_version`, not on CLI version strings.
- Additive fields are preferred over renaming or reinterpreting existing fields.
- Command identifiers should remain stable once published.
- UI shells should not infer extra meaning beyond what the contract states; Rust remains the source of truth for file semantics.

The canonical Rust definition for the current envelope and payloads lives in [crates/tosumu-cli/src/inspect_contract.rs](crates/tosumu-cli/src/inspect_contract.rs).