CellScript includes a JSON-RPC LSP server and a VS Code extension for local production-style authoring. The goal is to make `.cell` contracts inspectable before they are deployed and to keep editor feedback tied to the same parser, type checker, lifecycle checks, and lowering metadata used by `cellc`.

## LSP Capabilities

The LSP implementation supports the core editor features expected for contract development:

- diagnostics for parse, type, lifecycle, and lowering errors;
- hover information for actions, receipts, fields, local variables, lifecycle states, and lowering metadata;
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

The server runs over stdio:

```bash
cellc --lsp
```

The language service is implemented in the CellScript crate under `src/lsp/`. The VS Code extension starts the server through `vscode-languageclient` and `TransportKind.stdio`.

## VS Code Extension

The extension lives in:

```text
editors/vscode-cellscript
```

Local validation and packaging:

```bash
cd editors/vscode-cellscript
npm install
npm run validate
npm run package
```

The packaged VSIX includes the `vscode-languageclient` runtime dependency. Install the generated `.vsix` in VS Code, then configure `cellscript.compilerPath` if `cellc` is not on `PATH`.

Useful settings:

| Setting | Purpose |
|---|---|
| `cellscript.compilerPath` | Path to the `cellc` binary used for LSP and CLI-backed commands. |
| `cellscript.useCargoRunFallback` | Use `cargo run -q -p cellscript --` from a workspace when `cellc` is unavailable. |
| `cellscript.target` | Compiler target for command-backed reports: `riscv64-asm` or `riscv64-elf`. |
| `cellscript.targetProfile` | Profile for command-backed reports: `spora`, `ckb`, or `portable-cell`. |
| `cellscript.commandTimeoutMs` | Timeout for compiler-backed commands. |

The extension contributes commands for compile, metadata, constraints, production report, and target-profile selection. `CellScript: Show Production Report` displays compiler version, metadata, constraints, and release-audit boundaries; it does not replace chain acceptance gates.

## Formatting

Use formatter checks before committing:

```bash
cellc fmt --check
```

Apply formatting:

```bash
cellc fmt
```

## Generated Documentation

Generate package docs:

```bash
cellc doc
```

With JSON summary:

```bash
cellc doc --json
```

Documentation output includes the public contract surface and metadata-derived lowering information.

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

Treat registry, publish, install, update, login, and run flows as experimental unless your current build explicitly reports them as completed and supported.

## Tooling Workflow

Recommended local loop:

```bash
cellc fmt --check
cellc check --all-targets --json
cellc metadata . --target riscv64-elf --target-profile spora -o /tmp/metadata.json
cellc build --target riscv64-elf --target-profile spora --json
cellc verify-artifact build/main.elf --verify-sources --expect-target-profile spora
```

For CKB admission:

```bash
cellc check --target-profile ckb --json
cellc build --target riscv64-elf --target-profile ckb --json
cellc verify-artifact build/main.elf --expect-target-profile ckb
```

## Next

Continue with [Bundled Example Contracts](Tutorial-08-Bundled-Example-Contracts).
