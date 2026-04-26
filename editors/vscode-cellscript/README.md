# CellScript VS Code Extension

Production-grade VS Code tooling for `.cell` contracts, powered by a
CellScript Language Server (`cellc lsp --stdio`).

The extension connects to a `cellc` binary running as a JSON-RPC language
server over stdio. This provides real-time diagnostics, completion, hover,
go-to-definition, find-references, rename, signature help, document
highlighting, folding, formatting, code actions, and document symbols —
all backed by the CellScript compiler's parser, type-checker, and
lowering pipeline.

CLI-backed commands (compile, metadata, constraints, production report)
continue to spawn `cellc` directly for one-shot operations that are
outside the LSP scope.

## Features

### LSP-powered (via `cellc lsp --stdio`)

- real-time diagnostics on open / edit / save with incremental sync
- context-aware completion (keywords, types, user symbols, fields, locals)
- hover information (types, lowering metadata, lifecycle states)
- go-to-definition (top-level symbols, fields, local variables, cross-module)
- find-references (lexer-accurate, skips comments and strings)
- rename (cross-module, respects identifier boundaries)
- signature help (action, function, lock parameters)
- document highlight
- folding ranges
- selection ranges
- document symbols
- code actions (lowering diagnostics quickfix)
- document formatting

### CLI-backed

- compile to a scratch artifact for the configured RISC-V target
- `cellc metadata` JSON report
- `cellc constraints` JSON report
- production report (version + metadata + constraints)
- CKB target-profile arguments for compiler-backed reports

### Editor basics

- `.cell` file association
- TextMate syntax highlighting
- comment, bracket, auto-close, and folding configuration
- snippets for resources, shared state, receipts, actions, locks, effects,
  and `create ... with_lock`
- status bar state indicator

## Architecture

```
VS Code ──(LanguageClient)──> cellc lsp --stdio ──(JSON-RPC)──> CellScriptBackend
```

The `CellScriptBackend` in `server.rs` wraps the in-process `LspServer` and
implements the `tower_lsp::LanguageServer` trait. Document changes use
incremental sync; diagnostics are pushed automatically after each
open/change event.

## Requirements

Install `cellc` and make it available on `PATH`, or set
`cellscript.compilerPath` to the full compiler path.

When developing inside the CellScript Rust workspace, the extension can
fall back to:

```bash
cargo run -q -p cellscript --
```

Set `cellscript.useCargoRunFallback` to `false` to disable that fallback.

## Commands

| Command | Purpose |
|---|---|
| `CellScript: Compile Current File` | Compile the active file to a scratch RISC-V assembly artifact and print compiler output. |
| `CellScript: Show Metadata` | Run `cellc metadata` for the active file and show JSON in the CellScript output channel. |
| `CellScript: Show Constraints` | Run `cellc constraints` for the active file and show JSON in the CellScript output channel. |
| `CellScript: Show Production Report` | Show compiler version, artifact metadata, constraints, and release audit boundaries for the active file. |

Diagnostics, completion, hover, go-to-definition, references, rename,
formatting, signature help, folding, and code actions are provided
automatically by the language server — no explicit commands needed.

## Settings

| Setting | Default | Description |
|---|---:|---|
| `cellscript.compilerPath` | `cellc` | Compiler binary used for the language server and CLI commands. |
| `cellscript.useCargoRunFallback` | `true` | Use workspace `cargo run -q -p cellscript --` if `cellc` is unavailable. |
| `cellscript.commandTimeoutMs` | `15000` | Timeout for compiler-backed CLI commands. |
| `cellscript.maxOutputBytes` | `4194304` | Captured stdout/stderr limit. |
| `cellscript.target` | `riscv64-asm` | Compiler target for compile/metadata/constraints commands. |

## Local Validation

```bash
cd editors/vscode-cellscript
npm run validate
```

The validation script checks the extension manifest, grammar, snippets,
language configuration, commands, settings, and runtime wiring.

## Packaging

```bash
cd editors/vscode-cellscript
npm run package
```

Generated `.vsix` files are ignored by git and excluded from packaged source
archives.

## Release Review Checklist

For production release review, use `CellScript: Show Production Report` and
check the JSON/prose output for:

- compiler version pin;
- artifact metadata and artifact hash;
- schema hash and ABI/schema metadata;
- constraints hash or constraints JSON saved by the build;
- build provenance and source hash fields;
- target profile and entry-action/entry-lock scope;
- CKB capacity/cycle limits;
- external audit signatures attached by the release process.

The extension displays compiler evidence. It does not create audit signatures,
publish packages, deploy code cells, or replace CKB acceptance gates.

## Scope

The extension is a stable local editor integration. It is not a debugger, and
it does not replace release gates such as `cargo test`, `cargo clippy`,
`cellc check --production`, or chain acceptance scripts.
