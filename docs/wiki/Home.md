CellScript is a small language for writing Cell-based contracts on CKB. You
describe the Cells your protocol cares about, the actions that move those Cells,
and the locks that decide whether a Cell may be spent. The compiler then turns
that `.cell` source into ckb-vm compatible RISC-V assembly or ELF artifacts, and
writes metadata that explains what was built.

Last updated: 2026-04-27.

This wiki is a guided path. It starts with one compiled example, then slowly
builds the mental model: source files, Cell effects, packages, the CKB profile,
metadata, tooling, and finally the bundled examples. You do not need to
understand every production gate on the first read. The important thing is to
learn what each layer proves, and what it does not prove yet.

## How to Read This Wiki

If CellScript is new to you, read the tutorials in order. The first three
chapters are about the language. They explain how a `.cell` file is shaped, how
resources move, and why effects such as `consume` and `create` are explicit.

After that, the wiki moves outward:

- packages make builds repeatable;
- the CKB profile chooses the chain-facing runtime rules;
- metadata explains the artifact;
- production evidence proves more than compiler success;
- editor tooling shortens the local loop;
- bundled examples show the style in real contracts.

If you already know what you need, jump directly:

- writing source: start with [Language Basics](https://github.com/tsukifune-kosei/CellScript/wiki/Tutorial-02-Language-Basics);
- understanding Cell movement: read [Resources and Cell Effects](https://github.com/tsukifune-kosei/CellScript/wiki/Tutorial-03-Resources-and-Cell-Effects);
- copying a known pattern: use [Cookbook Recipes](https://github.com/tsukifune-kosei/CellScript/wiki/Cookbook-Recipes);
- checking CKB terms: keep [CKB Glossary](https://github.com/tsukifune-kosei/CellScript/wiki/CKB-Glossary) nearby;
- building a package: use [Packages and CLI Workflow](https://github.com/tsukifune-kosei/CellScript/wiki/Tutorial-04-Packages-and-CLI-Workflow);
- compiling for CKB: read [CKB Target Profiles](https://github.com/tsukifune-kosei/CellScript/wiki/Tutorial-05-CKB-Target-Profiles);
- preparing evidence: use [Metadata, Verification, and Production Gates](https://github.com/tsukifune-kosei/CellScript/wiki/Tutorial-06-Metadata-Verification-and-Production-Gates);
- working in an editor: read [LSP and Tooling](https://github.com/tsukifune-kosei/CellScript/wiki/Tutorial-07-LSP-and-Tooling);
- learning by example: finish with [Bundled Example Contracts](https://github.com/tsukifune-kosei/CellScript/wiki/Tutorial-08-Bundled-Example-Contracts).

## Tutorial Path

1. [Getting Started](https://github.com/tsukifune-kosei/CellScript/wiki/Tutorial-01-Getting-Started): compile one example and
   verify its artifact.
2. [Language Basics](https://github.com/tsukifune-kosei/CellScript/wiki/Tutorial-02-Language-Basics): learn the shape of a
   `.cell` file.
3. [Resources and Cell Effects](https://github.com/tsukifune-kosei/CellScript/wiki/Tutorial-03-Resources-and-Cell-Effects):
   understand how values move through a Cell transaction.
4. [Cookbook Recipes](https://github.com/tsukifune-kosei/CellScript/wiki/Cookbook-Recipes): copy small patterns once the basic
   vocabulary is familiar.
5. [Packages and CLI Workflow](https://github.com/tsukifune-kosei/CellScript/wiki/Tutorial-04-Packages-and-CLI-Workflow):
   create a package, build it, check it, and inspect reports.
6. [CKB Target Profiles](https://github.com/tsukifune-kosei/CellScript/wiki/Tutorial-05-CKB-Target-Profiles): choose the CKB
   runtime assumptions before compiling.
7. [Metadata, Verification, and Production Gates](https://github.com/tsukifune-kosei/CellScript/wiki/Tutorial-06-Metadata-Verification-and-Production-Gates):
   learn what artifact verification proves, and what still needs chain
   evidence.
8. [LSP and Tooling](https://github.com/tsukifune-kosei/CellScript/wiki/Tutorial-07-LSP-and-Tooling): use editor feedback and
   command-backed reports.
9. [Bundled Example Contracts](https://github.com/tsukifune-kosei/CellScript/wiki/Tutorial-08-Bundled-Example-Contracts): study
   the examples in a useful order.

## The Core Idea

CellScript tries to keep the CKB model visible. A contract should not look like
an account database if it is really spending input Cells and creating output
Cells.

That is why the language has:

- `resource`, `shared`, and `receipt` for persistent Cell-backed values;
- explicit effects such as `consume`, `create`, `read_ref`, `transfer`,
  `destroy`, `claim`, and `settle`;
- `action` entries for type-script style state transitions;
- `lock` entries for spend-boundary predicates;
- `protected`, `witness`, and `require` so lock source data and failure points
  are visible in source;
- metadata sidecars that describe schema, ABI, constraints, runtime
  requirements, and verifier obligations.

The wiki uses the same rule throughout: if something is only compiler evidence,
it is described as compiler evidence. If something needs a builder-backed CKB
transaction, the wiki says so.

## First Run

The fastest way to get oriented is to compile the token example:

```bash
git clone https://github.com/tsukifune-kosei/CellScript.git
cd CellScript
cargo test --locked
cargo run --locked --bin cellc -- examples/token.cell --target riscv64-elf --target-profile ckb -o /tmp/token.elf
cargo run --locked --bin cellc -- verify-artifact /tmp/token.elf --expect-target-profile ckb
```

The compile step writes two files:

```text
/tmp/token.elf
/tmp/token.elf.meta.json
```

The ELF is the executable artifact. The metadata sidecar is the explanation:
where the source came from, which profile was used, what schema was produced,
and which obligations still need review.

## Before You Call It Production

`cellc verify-artifact` is an important first check, but it is not the whole
story. It proves that an artifact and its metadata agree. It does not prove that
a concrete CKB transaction can spend the right inputs, serialize the right
witness, fit capacity rules, pass dry-run, and commit.

Keep two levels separate:

- compiler evidence: source, artifact, metadata, and selected policy flags
  agree;
- CKB chain evidence: builder-generated transactions were checked on a local CKB
  chain with cycles, transaction size, capacity, and positive/negative behavior
  evidence.

Release-facing CKB evidence comes from the repository root:

```bash
./scripts/ckb_cellscript_acceptance.sh --production
python3 scripts/validate_ckb_cellscript_production_evidence.py \
  target/ckb-cellscript-acceptance/<run>/ckb-cellscript-acceptance-report.json
```

The bundled examples are covered by the current local production evidence suite.
New external contracts still need their own metadata review, builder evidence,
security review, and chain acceptance evidence before they should be called
production-ready.

## Reference Examples

- [CKB hashing workflow](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/examples/ckb_hashing.md)
- [Collections matrix](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/examples/collections_matrix.md)
- [Deployment manifest](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/examples/deployment_manifest.md)
- [Mutate append](https://github.com/tsukifune-kosei/CellScript/blob/main/docs/examples/mutate_append.md)
