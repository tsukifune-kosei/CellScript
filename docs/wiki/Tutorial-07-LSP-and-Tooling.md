# Tutorial 07: LSP and Tooling

CellScript includes LSP support and a beta package/tooling workflow. The goal is to make `.cell` contracts auditable before they are deployed.

## LSP Capabilities

The LSP implementation supports the core editor features expected for contract development:

- diagnostics for parse/type/lifecycle/lowering errors;
- hover information for actions, receipts, and lowering metadata;
- keyword and symbol completions;
- go-to-definition;
- references;
- workspace rename;
- formatting;
- code actions for lowering diagnostics.

Exact editor integration depends on your editor or extension wrapper. The language service is implemented in the CellScript crate under the LSP module and is intended to be embedded by editor integrations.

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

## Beta Package Manager

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

