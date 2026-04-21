# CellScript VS Code Extension

Thin VS Code support for `CellScript` source files.

Current scope:

- `.cell` file association
- syntax highlighting
- comment / bracket / auto-close configuration
- basic snippets
- open/save-time parse diagnostics via local `cellc --parse` or `cargo run -p cellscript -- --parse`
- beta compiler LSP support exists in the CellScript crate for diagnostics,
  completions, hover, definition, references, rename, formatting, and code
  actions

Also included:

- package / publish manifest metadata
- a local `npm run validate` check for the extension files

Not included:

- direct VS Code language-server transport
- debugger integration

## Local install

1. Open VS Code.
2. Go to Extensions.
3. Use `Install from VSIX...` if you package it, or open this folder directly in an extension development host.

Extension folder:

- [cellscript/editors/vscode-cellscript](/Users/arthur/RustroverProjects/Spora/cellscript/editors/vscode-cellscript)

## Local validation

```bash
cd /Users/arthur/RustroverProjects/Spora/cellscript/editors/vscode-cellscript
npm run validate
```

## Editor diagnostics

The extension now provides a minimal runtime diagnostic layer:

- validates `.cell` files on open and save
- shells out to local `cellc --parse`
- falls back to `cargo run -q -p cellscript -- --parse` when working inside the Spora workspace

Settings:

- `cellscript.compilerPath`
- `cellscript.useCargoRunFallback`
- `cellscript.validationMode`

`cellscript.validationMode` values:

- `parse`
- `compile-asm`
- `off`

`compile-asm` is still intentionally thin: it only asks the compiler to produce an assembly scratch artifact so the editor can surface broader compile-time failures. It is not a language-server semantic model.

## Packaging

```bash
cd /Users/arthur/RustroverProjects/Spora/cellscript/editors/vscode-cellscript
npm run package
```

This extension intentionally stays a thin editor layer. The CellScript compiler
crate includes a beta LSP service, but this packaged extension still shells out
to `cellc` for validation until the language-server transport is wired into the
VS Code client.

## Extension development host

There is also a minimal VS Code launch config:

- [cellscript/editors/vscode-cellscript/.vscode/launch.json](/Users/arthur/RustroverProjects/Spora/cellscript/editors/vscode-cellscript/.vscode/launch.json)
