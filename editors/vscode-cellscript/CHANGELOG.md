# Changelog

## Unreleased

- Updated lock snippets for the 0.14 lock-boundary surface:
  `protected`, `lock_args`, `witness`, and `require`.
- Added LSP completions for `lock_args`, CKB source views, witness fields,
  `env::sighash_all`, and CKB epoch/since helpers.
- Extended syntax highlighting for `source::`, `witness::`, and `ckb::`
  namespace builtins.

## 0.12.0

- Replaced direct CLI diagnostics with a full LSP language server integration
  (`cellc lsp --stdio`) using `vscode-languageclient`.
- LSP-powered features: real-time diagnostics (open/edit/save with incremental
  sync), context-aware completion, hover, go-to-definition, find-references,
  rename, signature help, document highlight, folding ranges, selection ranges,
  document symbols, code actions, and document formatting.
- CLI-backed commands continue to work for compile, metadata, constraints,
  production report, and CKB target-profile arguments.
- Updated extension architecture: VS Code → LanguageClient → `cellc lsp --stdio`
  → `CellScriptBackend` (tower-lsp) → in-process `LspServer`.
- Removed stale validation-mode and validation-debounce settings (diagnostics
  are now driven by the language server, not by CLI polling).
- Updated README to reflect the new LSP architecture.

## 0.11.0

- Promoted the extension from a thin syntax package to stable local editor
  tooling for CellScript authoring.
- Added compiler-backed commands for validation, scratch compilation, metadata,
  constraints, formatting, and target-profile arguments.
- Added `CellScript: Show Production Report`, which combines compiler version,
  artifact metadata, constraints, and release-audit boundary notes for the
  active `.cell` file.
- Documented the transport boundary: this extension is mature local
  compiler-backed tooling, not a standalone JSON-RPC/stdin language-server
  process.
- Added edit-time validation settings, command timeout/output limits, status
  bar feedback, command palette/context menu entries, and stricter manifest
  validation.
- Updated repository metadata to the standalone CellScript repository.

## 0.1.0

- initial CellScript VS Code language extension skeleton
- `.cell` file association
- TextMate syntax highlighting
- language configuration
- basic snippets
