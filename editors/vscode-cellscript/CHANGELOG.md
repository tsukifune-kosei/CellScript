# Changelog

## 0.11.0

- Promoted the extension from a thin syntax package to stable local editor
  tooling for CellScript authoring.
- Added compiler-backed commands for validation, scratch compilation, metadata,
  constraints, formatting, and target-profile selection.
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
