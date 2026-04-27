You can write CellScript with any text editor and the `cellc` CLI. The LSP and
VS Code extension make that loop shorter. Parse errors, type errors, lifecycle
mistakes, symbols, hovers, formatting, and compiler-backed reports can show up
while you work instead of after a long command sequence.

The useful thing to remember is that editor feedback is not a separate language
implementation. It is tied to the same parser, type checker, lifecycle checks,
and lowering metadata used by `cellc`.

## What You Will Learn

- what the LSP server supports;
- how the VS Code extension starts the server;
- which settings matter for local development;
- where editor tooling helps;
- where release gates still need CLI and CKB evidence.

## LSP Capabilities

The LSP implementation supports the editor features you expect while writing a
contract:

- diagnostics for parse, type, lifecycle, and lowering errors;
- hover information for actions, receipts, fields, local variables, lifecycle
  states, and lowering metadata;
- keyword, type, symbol, field, and local completions;
- go-to-definition;
- find-references;
- workspace rename with identifier-boundary checks;
- document symbols;
- document highlight;
- signature help;
- folding ranges;
- selection ranges;
- formatting;
- code actions for lowering diagnostics;
- incremental document sync using LSP UTF-16 positions.

Run the server over stdio:

```bash
cellc --lsp
```

In practice you usually let the editor start it for you.

## VS Code Extension

The extension lives in:

```text
editors/vscode-cellscript
```

Validate and package it locally:

```bash
cd editors/vscode-cellscript
npm install
npm run validate
npm run package
```

Install the generated `.vsix` in VS Code. If `cellc` is not on `PATH`, set
`cellscript.compilerPath`.

Useful settings:

| Setting | Purpose |
|---|---|
| `cellscript.compilerPath` | Path to the `cellc` binary used for LSP and CLI-backed commands. |
| `cellscript.useCargoRunFallback` | Use `cargo run -q -p cellscript --` from a workspace when `cellc` is unavailable. |
| `cellscript.target` | Compiler target for command-backed reports: `riscv64-asm` or `riscv64-elf`. |
| `cellscript.commandTimeoutMs` | Timeout for compiler-backed commands. |

The extension contributes commands for compile, metadata, constraints, and
production report. `CellScript: Show Production Report` is useful while editing
because it displays compiler version, metadata, constraints, and release-audit
boundaries.

That report is a guide, not a deployment certificate. Chain acceptance still
requires CLI evidence and builder-backed CKB transactions.

## A Comfortable Local Loop

While editing, let the LSP catch small mistakes quickly. Before committing, run
the CLI checks explicitly:

```bash
cellc fmt --check
cellc check --all-targets --json
cellc metadata . --target riscv64-elf --target-profile ckb -o /tmp/metadata.json
cellc build --target riscv64-elf --target-profile ckb --json
cellc verify-artifact build/main.elf --verify-sources --expect-target-profile ckb
```

For CKB admission, keep the profile visible:

```bash
cellc check --target-profile ckb --json
cellc build --target riscv64-elf --target-profile ckb --json
cellc verify-artifact build/main.elf --expect-target-profile ckb
```

This loop gives fast feedback first, then more formal evidence as the contract
gets closer to review.

## Formatting

Apply formatting:

```bash
cellc fmt
```

Check formatting without changing files:

```bash
cellc fmt --check
```

The formatter is especially useful after applying field shorthand or cleaning up
example code. It keeps the source style consistent without turning style into a
manual review topic.

## Generated Documentation

Generate package docs:

```bash
cellc doc
```

With JSON summary:

```bash
cellc doc --json
```

Documentation output includes the public contract surface and metadata-derived
lowering information.

## Local Package Workflow

The package manager supports:

- `cellc init`
- `cellc build`
- `cellc check`
- `cellc fmt`
- `cellc doc`
- `cellc add --path`
- `cellc remove`
- `cellc info`
- lockfile consistency checks for local dependencies

Use the top-level `cellc path/to/file.cell` form for one-off file compilation.
Use `cellc build` for package builds.

Local `cellc install --path` and `cellc update` are supported as lockfile helpers
for local path dependency workflows. Treat registry package installation,
registry publishing, `login`, and `run` flows as experimental unless your
current build explicitly reports them as completed and supported.

## Next

With the tooling loop in place, continue with
[Bundled Example Contracts](Tutorial-08-Bundled-Example-Contracts.md).
