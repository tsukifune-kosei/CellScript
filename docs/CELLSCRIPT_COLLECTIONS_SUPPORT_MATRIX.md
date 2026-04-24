# CellScript Collections Support Matrix

**Status**: production boundary document for CellScript 0.12.

CellScript supports dynamic data in several different layers. These layers must
not be collapsed into one generic "collections are supported" claim.

## Support By Layer

| Feature | Schema/ABI | IR construction | Runtime verifier helper | Production status |
|---|---:|---:|---:|---|
| `Vec<u8>` | Yes | Targeted | Targeted create/mutate verification | Supported for documented witness and cell-data paths |
| `String` | Yes | Targeted | Byte-vector verification | Supported as UTF-8 bytes at the schema boundary |
| `Vec<Address>` | Yes | Targeted | Fixed-element vector verification | Supported where metadata marks a Molecule dynamic field |
| `Vec<Hash>` | Yes | Targeted | Fixed-element vector verification | Supported where metadata marks a Molecule dynamic field |
| Fixed byte arrays | Yes | Yes | Exact-size verification | Supported |
| `Vec<Vec<u8>>` | Boundary | Boundary | No generic helper | Must fail closed unless a concrete lowering is added |
| `HashMap<u64, u64>` | Limited | Limited | U64-oriented helper only | Experimental/internal; not a production contract |
| `HashMap<Hash, Token>` | No | No | No | Unsupported; must fail closed |
| Cell-backed resource collections | No executable ownership model | No | No | Unsupported until a linear collection ownership primitive exists |

## Production Rule

Supported dynamic values must have deterministic Molecule metadata and verifier
evidence:

- `molecule_schema_manifest` entry
- dynamic field declaration where applicable
- generated create or mutate verifier marker
- constraints or production-gate evidence for the entrypoint that uses it

Unsupported generic collections must not silently compile into a weaker runtime
shape. They must produce one of:

- compile-time diagnostic
- structured blocker in metadata/constraints
- explicit fail-closed runtime path with a registered runtime error

## Authoring Guidance

Use dynamic vectors for data that is still a single cell field, such as signer
lists, proposal payload bytes, NFT attributes, or launch distributions.

Do not model ownership of multiple independent linear cells as a generic vector
or map. Use explicit action parameters and explicit `consume`, `transfer`,
`destroy`, or `mutate` operations until the language gains a verifier-backed
collection ownership primitive.

Future candidates include `consume_each`, typed collection destructuring, and
membership proofs tied to Molecule schema manifests.

