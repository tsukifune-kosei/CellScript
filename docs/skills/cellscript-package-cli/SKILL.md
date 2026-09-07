---
name: cellscript-package-cli
description: CellScript package layout, Cell.toml, build/check/fmt/test, canonical command groups, global JSON output, registry/package verification, and legacy alias migration.
references:
  - docs/wiki/Tutorial-04-Packages-and-CLI-Workflow.md
  - docs/releases/CELLSCRIPT_0_21_RELEASE_NOTES.md
  - docs/CELLSCRIPT_GATE_POLICY.md
commands:
  - cellc add
  - cellc lock
  - cellc check
  - cellc build
  - cellc fmt
  - cellc migrate
  - cellc test
  - cellc package verify
  - cellc registry verify
---

# CellScript Package And CLI

Use this skill when working with packages or command-line workflows. Prefer the
current nested command tree. Legacy flat aliases may exist during the
compatibility window, but public docs and agent guidance should teach the
canonical form.

Use global `--json` for one machine-readable stdout result on success or
failure. Do not scrape coloured human text when structured output exists.

Validation defaults:

- run `cellc check --json` for package feedback;
- use `cellc migrate --to 2027` only for a review-only candidate; do not treat
  its bounded semantic-ID/ELF equality as graph-wide migration or production
  evidence;
- run `cellc --list` to inspect the canonical command tree;
- run `./scripts/cellscript_gate.sh dev` before claiming local readiness.

When a root CKB environment is selected, treat environment names as local
aliases. Transitive dependencies inherit only by exact `chain_id` plus genesis
hash. Use `use_environment = "dependency-local-name"` (or `cellc add
--use-environment ...`) for an explicit matching map, and
`environment_independent = true` when the edge must apply no dependency-local
override. Never infer chain identity from equal names such as `mainnet`.
