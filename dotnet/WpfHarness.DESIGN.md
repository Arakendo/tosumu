# WPF Harness Mini Design

## Purpose

This document proposes a **Windows-only inspection harness** for `tosumu` built on the existing `.NET` packaging work.

The harness is **not** a replacement for the core Rust engine. It is a UI shell for inspecting database state in a richer way than the current CLI and the early `tosumu view` TUI slice.

The harness is intended to answer one question:

> Can a Windows desktop shell help us design the MVP +8 inspection UX faster and with less friction than iterating exclusively in a terminal UI?

Short answer: probably yes.

Longer-term, the harness is also a useful proving ground for a broader `tosumu` tooling family: richer inspectors, admin consoles, or SQLDeveloper-style companion tools should learn from the same inspection contracts and UX patterns instead of inventing their own.

## Status Relative To MVP +8

Current roadmap language in `DESIGN.md` defines MVP +8 as a **TUI viewer**. This proposal does **not** silently change that contract.

Instead, this harness should be treated as one of these three things:

1. A **design/prototyping harness** that informs the eventual TUI.
2. A deliberate future pivot from TUI-first to Windows GUI-first, if we later decide that is the better product surface.
3. A **committed Windows diagnostic companion** that stays alongside the TUI because it is the fastest way to inspect a broken database when the failure mode is still unclear.

This document now assumes option 3 unless we explicitly revise `DESIGN.md` again.

Implementation note:

- the first bootstrap project now exists at `dotnet/Tosumu.WpfHarness`
- it currently targets `net10.0-windows`, because the packaged `Tosumu.Cli` wrapper currently targets `net10.0`
- if the wrapper later retargets to `net8.0`, the harness can follow without changing the UI contract

## Goals

- Reuse the existing `dotnet/Tosumu.Cli` package and local packaging flow.
- Reuse proven Windows UI infrastructure already present in `F:\LocalSource\ClassLibrary` instead of rebuilding WebView host plumbing from scratch.
- Provide a richer inspection surface for header, pages, verification, keyslots, and eventually B+ tree and WAL views.
- Keep Rust as the source of truth for all on-disk interpretation.
- Avoid native interop / FFI for the first version.
- Make UX iteration fast enough that layout, navigation, and color decisions can change daily without destabilizing the storage engine.
- Let the harness act as a prototype seam for future companion tools without forcing the storage engine to absorb UI-specific assumptions.

## Non-Goals

- No direct page parsing in C#.
- No database mutation through the harness in the first version.
- No replacement of Rust verification logic with UI-side logic.
- No cross-platform guarantee in the first version.
- No claim that the WPF harness replaces the TUI roadmap item.

## Why This Path Exists

The current repo is already well-positioned for an out-of-process UI harness:

- `tosumu-core` already exposes structured inspection primitives in Rust.
- `tosumu-cli` already wraps those primitives in `dump`, `hex`, `verify`, and the first `view` slice.
- The `.NET` setup already packages the CLI as a local NuGet package and validates it through integration tests.

That means the missing piece is not engine capability. The missing piece is a UI shell that can consume a stable inspection contract.

More bluntly: this is not just "some JSON contract".

For the harness, this becomes a **versioned inspection API** exposed by the Rust CLI.

## Existing Reusable Library Inventory

There is already substantial prior work in `F:\LocalSource\ClassLibrary` that should be treated as available leverage, not ignored.

### High-value pieces

1. **`WebViewTools`**
    - WPF and WinForms WebView2 managers already exist.
    - Covers initialization, runtime detection, virtual origin hosting, resource interception, startup scripts, and message plumbing.
    - This removes a large amount of fragile WebView2 setup code from the harness backlog.

2. **`WpfBlazorTools`**
    - Provides a WPF `UserControl` that hosts a BlazorWebView cleanly.
    - Gives us a viable .NET-first viewer path if we want something lighter than a custom React/WebView stack.

3. **`HelperClient.Wpf` pattern**
   - Demonstrates a different but valid WPF + Blazor approach: run an ASP.NET Core / Blazor Server app in-process on loopback and host it in raw WebView2.
   - Useful when we want full browser semantics and already have a server-style Blazor app shape.
   - Comes with real-world lessons around startup order, dynamic port binding, static asset copying, and host shutdown.

4. **`MonacoTools.WebView`**
    - Provides a working WPF Monaco editor hosted inside WebView2.
    - Not required for version 1, but potentially useful later for raw JSON, page payload, or structured record inspection panes.

### Consequence

The harness should be designed to **reuse or reference** these libraries where practical.

This changes the posture of the project:

- we are not evaluating WebView2 from zero
- we do not need `net10.0-windows` just to feel modern
- we can prefer the runtime and stack shape already proven in local code

## Adoption Plan

Reuse should be deliberate, not opportunistic.

### Rule 1: Prefer wrappers over direct spread

The harness should not let `ClassLibrary` APIs leak everywhere across the app.

Instead, create a small local adapter layer inside the harness solution, for example:

- `Harness.WebViewHost`
- `Harness.UiHost`
- `Harness.InspectClient`

That local layer owns references to borrowed libraries and presents a narrower app-specific surface.

This keeps us from coupling the entire harness directly to external project shapes.

### Rule 2: Start by referencing, not copying

For the first implementation pass, prefer **project or package references** to the existing `ClassLibrary` work.

Do not copy code into `tosumu` immediately unless one of these becomes true:

- the dependency is unstable for our needs
- the dependency drags in too much unrelated surface
- the harness stops being a prototype and becomes a committed product surface

### Rule 3: Internalize only after the seam is proven

If we later decide to internalize functionality, internalize only behind the local harness wrapper layer.

That way the rest of the app does not care whether the implementation comes from:

- `ClassLibrary`
- local copied code
- a future packaged dependency

### Proposed first adoption set

1. `WpfBlazorTools`
   - first choice for the initial viewer host
   - lowest complexity path to a usable Windows shell

2. `WebViewTools`
   - borrow for WebView2 lifecycle, virtual origin hosting, and message plumbing
   - use directly if we later need a custom SPA host

3. `HelperClient.Wpf` pattern
   - keep as the fallback or expansion path if BlazorWebView becomes limiting
   - especially relevant if we want a full browser-hosted shell with server-style Blazor routing and static assets

4. `MonacoTools.WebView`
   - defer until a real editor/inspector pane exists
   - not part of version 1 critical path

### Dependency ownership rule

No breaking harness dependency on `ClassLibrary` APIs should exist without a local wrapper layer.

That is the minimum discipline required to avoid turning this into a transitive maintenance problem.

## Proposed Stack

### Host Shell

- **WPF** application on `net8.0-windows` by default
- Upgrade to `net10.0-windows` only if a concrete dependency or SDK feature justifies it.
- Responsibilities:
  - native Windows windowing
  - file picker / recent files
  - app shell and command routing
  - process orchestration for the packaged CLI
  - secret prompt dialogs for encrypted DB access

Rationale:

- the reusable `ClassLibrary` components already target `net8.0-windows`
- `net8` is sufficient for a Windows harness
- matching the existing local library baseline reduces integration friction

Current implementation note:

- the bootstrap harness is presently on `net10.0-windows` because `Tosumu.Cli` is currently packaged for `net10.0`
- that is a packaging-alignment choice, not a UI architecture requirement

### Viewer Surface

- **WebView2** embedded inside WPF via existing `WebViewTools` patterns or direct reuse
- UI technology intentionally left flexible between two realistic paths:
   - **Blazor-first** via `WpfBlazorTools`
   - **Blazor Server in-process** via the `HelperClient.Wpf` pattern when full browser behavior is more useful than `BlazorWebView`
   - **React-in-WebView2** if richer front-end experimentation becomes the priority
- Responsibilities:
  - page list and virtualized tables
  - record detail panes
  - verification issue list and filters
  - keyslot / protector summaries
  - later: tree visualizer, WAL timeline, corruption highlighting

Initial recommendation:

- start **Blazor-first** if the immediate goal is to get a maintainable Windows harness up quickly
- prefer `WpfBlazorTools` first because it is the smaller host model
- keep the `HelperClient.Wpf` pattern available if the harness wants a more browser-native shell, router behavior, or server-style composition
- switch to a custom WebView2 SPA only if Blazor becomes a real UX bottleneck

This keeps us from paying the React + host-bridge complexity tax before we know we need it.

### Rust Boundary

- Rust remains **out-of-process** for the first version.
- The WPF host invokes the packaged `tosumu.exe` through the existing `.NET` wrapper.
- The Rust side should expose **machine-readable JSON inspector modes** instead of forcing the UI to parse formatted console text.

Important constraint:

Even if the first transport is one CLI invocation per request, every inspect command should be designed so it can later participate in a **long-lived session mode** without breaking the API shape.

## Why Not Parse Existing CLI Text

The current CLI output is excellent for humans and poor as a long-term UI contract.

Text scraping would create fragile coupling to:

- alignment changes
- label renames
- formatting tweaks
- localization or wording cleanup

The harness should consume JSON, not formatted paragraphs.

## Architecture

### High-Level Flow

1. User opens a `.tsm` file in the WPF shell.
2. WPF asks the Rust CLI for structured inspection data.
3. WPF converts that JSON into typed DTOs.
4. DTOs are pushed into the chosen viewer layer.
5. The viewer renders panes and handles UX-level state only.

Rust decides what the file means.
UI decides how to present it.

### Component Split

#### Rust CLI

Add dedicated machine-output commands or flags, for example:

- `tosumu inspect header --json <path>`
- `tosumu inspect pages --json <path>`
- `tosumu inspect page --json --page <n> <path>`
- `tosumu inspect verify --json <path>`
- `tosumu inspect tree --json <path>`
- `tosumu inspect wal --json <path>`

These should return stable JSON payloads with explicit fields, not ad hoc serialized debug structs.

#### .NET Wrapper Layer

Extend the existing `TosumuCliTool` package with higher-level methods such as:

- `GetHeaderAsync(...)`
- `GetPagesAsync(...)`
- `GetPageAsync(...)`
- `VerifyAsync(...)`
- `GetTreeAsync(...)`

This keeps process handling, stderr capture, timeout policy, and JSON deserialization out of the UI layer.

#### WPF App Shell

Owns:

- file open / recent files
- unlock prompt lifecycle
- menu and toolbar commands
- status bar
- background task cancellation
- error dialogs when the CLI returns `WrongKey`, `AuthFailed`, or structural corruption
- host integration with `WebViewTools` or `WpfBlazorTools`

#### Viewer Layer

Owns:

- tabs / panes
- list selection state
- search / filter state
- visual severity styling
- graph rendering for tree / WAL later

Notes:

- If we choose **Blazor**, this layer stays mostly in `.NET` and reuses `WpfBlazorTools`.
- If we choose **React**, this layer rides on top of WebView2 and should strongly reuse `WebViewTools` host plumbing.
- Both options still depend on the same Rust JSON contract.

## Initial UX Scope

Version 1 should stay narrow.

### Screen Layout

- Left rail: pages / sections
- Main panel: selected item detail
- Top summary: file identity, page count, root page, encryption state
- Bottom status: unlock state, verification summary, last refresh time

### Initial Panes

1. **Header**
   - format version
   - page size
   - page count
   - root page
   - freelist head
   - keyslot count
   - keyslot 0 kind

2. **Pages**
   - page number
   - page type
   - page version
   - slot count
   - auth/inspection state

3. **Page Detail**
   - page header fields
   - decoded records
   - tombstones / unknown records

4. **Verify**
   - pages checked / pages ok
   - issue list
   - per-page auth state

5. **Protectors**
   - slot index
   - kind
   - high-level summary only

### Later Panes

- B+ tree structure
- WAL record explorer
- side-by-side page comparison
- watch mode / auto-refresh
- page corruption heatmap

## Secret Handling

This is one of the most important design constraints.

We should **not** pass passphrases or recovery keys through command-line arguments, because those are easier to leak through logs, process listings, and debugging tools.

Preferred order for the harness:

1. Pass secrets via **stdin** to a dedicated CLI subcommand.
2. If stdin is not sufficient, use short-lived process environment variables and clear them aggressively.
3. Avoid arguments for secrets.

Keyfile paths are less sensitive than raw passphrases, but should still be treated carefully in logs.

### Version 1 secret flow

The first usable flow should be simple and explicit:

1. UI invokes a command with an explicit mode such as `--stdin-passphrase` or `--stdin-recovery-key`.
2. CLI reads exactly one secret from stdin.
3. CLI performs one inspect command and exits.
4. On `wrong_key`, the UI decides whether to re-prompt.

The harness may cache a successful secret in memory for the life of an open document session, but that should be treated as a UI policy choice, not an implicit CLI behavior.

Version 1 should not invent a broad secret exchange protocol beyond that.

## Inspection API Design

The Rust-to-UI boundary is a **versioned inspection API** carried over JSON.

The API should be:

- explicit
- version-tolerant
- additive by default
- stable enough for a UI client

### Versioning strategy

The versioning model should be simple:

- `schema_version` versions the inspection API envelope and payload semantics
- the `command` field identifies which payload shape is being returned
- adding a new command does **not** require a new schema version by itself
- changing the meaning or required shape of an existing command response **does** require a schema version bump

In other words:

- new commands are additive
- incompatible meaning changes are versioned

That keeps the API evolvable without forcing a version bump for every new surface area.

### Compatibility rules

These rules should be treated as hard constraints once the first command ships:

- always include `schema_version`
- never remove fields in an existing schema version
- only add fields
- prefer nullable or optional additions over breaking shape changes
- keep error shapes structured, not prose-only
- avoid leaking Rust internal type names as API commitments

If a true breaking change becomes unavoidable, bump the schema version rather than mutating meaning in place.

Recommended shape:

- top-level `schema_version`
- top-level `command`
- top-level `ok`
- typed payload objects
- string enums only where useful for clarity
- no dependence on Rust internal type names

Example:

```json
{
  "schema_version": 1,
   "command": "inspect.header",
   "ok": true,
   "payload": {
      "page_count": 42,
      "root_page": 3,
      "keyslot_count": 2,
      "encryption": {
         "enabled": true,
         "protector_kinds": ["Passphrase", "RecoveryKey"]
      }
  }
}
```

### Error shape

When `--json` is requested, failures should also return structured JSON.

Example:

```json
{
   "schema_version": 1,
   "command": "inspect.verify",
   "ok": false,
   "error": {
      "kind": "auth_failed",
      "message": "authentication tag mismatch",
      "pgno": 3
   }
}
```

Suggested stable error kinds for version 1:

- `wrong_key`
- `auth_failed`
- `corrupt`
- `invalid_argument`
- `file_busy`
- `io`
- `unsupported`

### Version 1 command priority

Do not try to define the entire inspection API at once.

Version 1 should start with exactly this order:

1. `inspect.header --json`
2. `inspect.verify --json`
3. `inspect.page --json --page N`

Only after those are stable should we add:

- `inspect.pages --json`
- `inspect.tree --json`
- `inspect.wal --json`

If the first command shape is messy, the rest of the API will inherit that mess.

## Error Model

The harness must preserve Rust-side distinctions that matter for user trust.

At minimum, the UI should distinguish:

- wrong secret
- authentication failure / tamper indication
- structural corruption
- file busy / transient lock issue
- unsupported command / contract mismatch

The UI should not flatten all of these into a generic “failed to load database” message.

## Packaging Model

The current `.NET` packaging pipeline is already a good base:

- `Tosumu.Cli` NuGet package carries the Rust executable.
- `.NET` integration tests already exercise packaged behavior.
- A future harness package or app can also reference borrowed local libraries from `ClassLibrary` during prototyping before deciding whether to internalize or package them.

The WPF harness can consume that same package instead of locating a developer-local Rust build.

That keeps the harness aligned with the exact packaged artifact it is testing and presenting.

## Test Strategy

### Rust Side

- unit tests for JSON DTO generation
- contract tests for required fields
- golden / snapshot tests for representative JSON payloads
- regression tests for encrypted / corrupted / wrong-key scenarios

### .NET Side

- wrapper tests for process launch and deserialization
- integration tests against packaged CLI
- app-shell tests for command routing and error propagation

### Front-End Side

- component tests for render logic
- snapshot tests for representative states
- interaction tests for navigation, filtering, and issue highlighting

## Tradeoffs

### Strengths

- fastest path to a richer inspection UX
- strong reuse of the existing `.NET` packaging work
- strong reuse of already-debugged WPF / WebView / Blazor infrastructure in `ClassLibrary`
- no FFI yet
- clean separation: Rust owns semantics, UI owns presentation

### Weaknesses

- Windows-only first
- adds a second viewer surface alongside the TUI
- requires a real JSON contract, which is a new maintenance surface
- if we choose React, WebView host complexity increases versus a Blazor-first harness
- borrowing code from `ClassLibrary` creates a dependency/ownership decision we will eventually need to formalize

### Risk

The biggest risk is not the existence of two viewers. The biggest risk is letting them drift into two different inspection contracts or two different mental models of what "healthy" and "broken" mean.

If we keep both surfaces, the rule needs to be explicit:

- Rust inspection contracts remain the source of truth.
- The TUI remains the cross-platform roadmap surface.
- The WPF harness remains the fastest Windows diagnostic shell when we need richer triage.
- Any future companion tool should reuse the same inspection contracts and interaction model rather than creating a third interpretation layer.

What must not happen is duplicating semantics or inventing harness-only interpretations of on-disk state.

## Proposed Milestones

### M0 — Contract seam

- Add JSON inspector commands to `tosumu-cli`
- Keep current human-readable commands intact
- Add tests for JSON outputs
- Benchmark CLI startup, decrypt/scan cost, and JSON serialization cost before assuming request-per-process is acceptable

### M0.5 — First consumer proof

- extend the `.NET` wrapper with one typed inspect client method for header JSON only
- add one integration test that consumes the structured header response from the packaged CLI
- prove the API is usable from the harness side before expanding command count

### M1 — Host shell

- Create WPF app
- Reuse `WebViewTools` / `WpfBlazorTools` rather than building host plumbing manually
- Evaluate the `HelperClient.Wpf` in-process Kestrel + WebView2 pattern only if `BlazorWebView` proves too limiting for the desired UI behavior
- Open file
- Invoke packaged CLI
- Render raw header/page summary data in a basic shell

### M2 — WebView viewer

- Embed viewer surface using one of:
   - `WpfBlazorTools` for a Blazor-first harness
   - `WebViewTools` for a custom WebView2-hosted SPA
- Render header, page list, page detail, verify summary
- Support selection and refresh

### M3 — Encrypted inspection

- prompt for passphrase / recovery key / keyfile
- surface wrong-key vs corruption cleanly
- show protector summary and keyslot details

### M4 — Advanced inspection

- B+ tree visualization
- WAL visualization
- corruption highlighting and explainability improvements

## Recommendation

This is a good idea if we treat it as a **committed diagnostic companion** and **UX harness** first, not a stealth replacement for MVP +8.

The right next step is to add the **structured JSON inspection contract** to the Rust CLI.

Once that seam exists, the harness should start from the **already-proven local .NET UI infrastructure**:

1. target `net8.0-windows`
2. prototype with `WpfBlazorTools` unless a custom SPA is clearly needed
3. keep the `HelperClient.Wpf` host pattern in reserve if a browser-native Blazor shell is more effective than `BlazorWebView`
4. reuse `WebViewTools` patterns if we do need a richer WebView-hosted front end

The mistake to avoid is rebuilding WebView host plumbing that already exists in `ClassLibrary`.

## Start Order

If implementation starts now, the order should be:

1. Define and document `inspect.header --json` precisely.
2. Implement it in `tosumu-cli` with structured success and structured error JSON.
3. Add Rust tests that lock the response envelope and required fields.
4. Extend the `.NET` wrapper with one typed header client.
5. Add one harness-side consumer test using the packaged CLI.
6. Only then create the first WPF shell view.

This keeps both the harness and the TUI downstream of the same API and prevents either surface from inventing assumptions the CLI has not committed to.

That same rule should apply if `tosumu` later grows a broader tooling family. The harness is valuable partly because it can prototype higher-level workflows quickly, but only if those workflows can later be expressed against the same Rust-side inspection contract.

## Decision Record

The following decisions are considered locked for version 1 unless a concrete blocker appears:

1. Windows-only harness.
2. The harness remains a committed Windows diagnostic companion alongside the TUI.
3. `net8.0-windows` baseline.
4. Rust remains out-of-process.
5. Structured JSON inspection API is mandatory.
6. Blazor-first harness host is the default starting point.
7. `WpfBlazorTools` is preferred before the `HelperClient.Wpf` pattern unless a concrete browser-hosting need appears.
8. `ClassLibrary` reuse happens through local wrapper layers.
9. Request-per-process is acceptable only until benchmarks say otherwise.

## Open Questions

1. Do we want the harness to stay explicitly Windows-only, or should we expect a future cross-platform shell?
2. How much feature parity do we want between the WPF harness and the TUI before we call both surfaces "good enough" for routine debugging?
3. Should secret input use stdin only, or do we want a broader request/response protocol for long-running sessions?
4. Do we want the viewer to refresh by requerying the CLI every time, or do we want a longer-lived child process session later?
5. Which borrowed `ClassLibrary` pieces do we reference directly versus internalize locally once the harness dependency boundary hardens?