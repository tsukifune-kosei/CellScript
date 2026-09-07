# CellScript Compiler Error Codes

Compiler diagnostics use stable numeric ranges. Runtime verifier exits remain
in the low-numbered `E####` registry documented by
`CELLSCRIPT_RUNTIME_ERROR_CODES.md`; backend/compiler failures use the
non-overlapping `E2xxx` range.

| Code | Name | Meaning | Suggested action |
| --- | --- | --- | --- |
| `E2000` | `backend-uncategorized` | Backend failure outside a classified boundary. | Preserve the full diagnostic and the source that reached code generation. |
| `E2001` | `backend-empty-artifact` | Code generation produced no artifact bytes. | Check entrypoint selection and artifact target. |
| `E2100` | `type-layout-lowering` | A type could not be lowered to its backend storage layout. | Check fixed widths, schema fields, and payload layouts. |
| `E2101` | `entry-abi-lowering` | The selected entrypoint could not be lowered to the entry ABI. | Check entry parameters and witness ABI support. |
| `E2102` | `action-lowering` | An action body could not be lowered. | Inspect the named action and operation in the diagnostic. |
| `E2103` | `lock-lowering` | A lock body could not be lowered. | Inspect the named lock and target runtime requirements. |
| `E2104` | `pure-function-lowering` | A pure function could not be lowered. | Check call ABI, return layout, and the reported expression. |
| `E2105` | `executable-surface-incomplete` | Strict production compilation found semantics that cannot be executed by the selected backend. | Use metadata-only analysis for inspection, or remove the fail-closed feature before generating an artifact. |
| `E2110` | `generic-declaration-invalid` | A value-generic declaration violates the parameter, ability, phantom, or reserved-name contract. | Correct the declaration and keep Cell lifecycle authority outside ordinary generic values. |
| `E2111` | `generic-instantiation-invalid` | A generic application has invalid arguments, constraints, layout, or identity. | Supply concrete fixed serializable value types satisfying every declared ability. |
| `E2112` | `generic-instantiation-budget` | Deterministic monomorphization exceeded its nesting, count, or identity-size budget. | Reduce recursive/nested specializations or split the generic surface. |
| `E2113` | `trusted-external-binding-invalid` | A trusted external verifier call or declaration is missing, mismatched, non-canonical, unused, or ambiguous. | Use a `trusted_*` intrinsic with an exact compile-time data hash and one matching versioned `Cell.toml` declaration. |
| `E2200` | `unresolved-assembly-symbol` | Generated assembly references a missing label or call target. | Check callable reachability and helper closure. |
| `E2201` | `assembly-layout` | Generated assembly could not form a valid machine layout. | Check sections, labels, branches, and block ordering. |
| `E2202` | `instruction-encoding` | A RISC-V instruction or immediate could not be encoded. | Check the mnemonic, operands, registers, and immediate range. |
| `E2300` | `elf-emission` | A valid RISC-V ELF artifact could not be constructed. | Check entrypoint, section layout, offsets, and size constraints. |
| `E2400` | `verified-artifact-boundary` | The verified lowering/source-map boundary for an ELF artifact could not be constructed or persisted. | Inspect the verified lowering record, source artifact map, and canonical sidecar diagnostic. |
| `E2501` | `public-interface-breaking` | `cellc interface-diff` found a breaking source API, serialized layout, runtime ABI, effect/capability, builder, or deployment change. | Inspect every reported compatibility dimension and intentionally version or reverse the incompatible change before Registry publication. |
| `E2900` | `backend-invariant` | An internal backend invariant failed after semantic checking. | Retain the source and compiler version and report a compiler defect. |
| `W2500` | `implicit-legacy-public` | A module mixes explicit visibility with Edition 2026 declarations that still default to public. | Add `public`, `public(package)`, or `private` to every declaration listed by the warning. |
| `W3012` | `legacy-raw-temporal-api` | Source uses an Edition 2026 raw-`u64` CKB temporal API for which the typed domain contract has a total replacement. | Apply the language-server migration action or use the explicit replacement in the warning; the outer raw-`u64` result remains compatible. |

The CLI exposes these codes in human diagnostics and in the `diagnostics[].code`
field of `--json` failures. The language server publishes them through the LSP
diagnostic `code` field and supplies a `codeDescription` link to this registry.
