use camino::{Utf8Path, Utf8PathBuf};
use cellscript::{
    codegen::{analyze_backend_shape, BackendShapeMetrics},
    compile_file, compile_file_with_entry_action, compile_file_with_entry_lock, compile_metadata_with_diagnostics, compile_path,
    compile_path_with_executable_surface_policy, ArtifactFormat, CompileEntryScope, CompileMetadata, CompileOptions, CompileResult,
    EntryWitnessArg, ExecutableSurfacePolicy, ProofPlanMetadata,
};
use std::collections::BTreeSet;

const BUNDLED_EXAMPLES: [&str; 9] = [
    "amm_pool.cell",
    "atomic_swap.cell",
    "launch.cell",
    "multi_phase_dao.cell",
    "multisig.cell",
    "nft.cell",
    "timelock.cell",
    "token.cell",
    "vesting.cell",
];
const PACKAGE_EXAMPLES: [&str; 10] =
    ["amm_pool", "atomic_swap", "launch", "multi_phase_dao", "multisig", "nft", "registry", "timelock", "token", "vesting"];
const TEMPORAL_BUSINESS_EXAMPLES: [(&str, &str); 6] = [
    ("timelock.cell", "timelock"),
    ("multi_phase_dao.cell", "DAO"),
    ("vesting.cell", "vesting"),
    ("nft.cell", "NFT expiry"),
    ("multisig.cell", "governance"),
    ("atomic_swap.cell", "atomic swap"),
];
const BACKEND_SHAPE_BASELINE_JSON: &str = include_str!("backend_shape_baseline.json");

const BUNDLED_EXAMPLE_ELF_SIZE_BUDGETS: [(&str, usize); 9] = [
    ("amm_pool.cell", 96 * 1024),
    ("atomic_swap.cell", 80 * 1024),
    ("launch.cell", 48 * 1024),
    ("multi_phase_dao.cell", 80 * 1024),
    ("multisig.cell", 108 * 1024),
    ("nft.cell", 96 * 1024),
    ("timelock.cell", 96 * 1024),
    ("token.cell", 18 * 1024),
    ("vesting.cell", 52 * 1024),
];

const ARTIFACT_SIZE_EXPERIMENT_EXAMPLES: [&str; 4] = ["amm_pool.cell", "nft.cell", "token.cell", "vesting.cell"];

// The 0.26 metadata envelope carries both the canonical typed-semantic record
// and its independently checked semantic foundation (provenance, roles,
// dispositions, claims, and layered identities). These caps include that
// security boundary while remaining within roughly 5-7% of measured compact
// full-package outputs; they must not be raised for unrelated feature growth.
const FULL_METADATA_SIZE_BUDGETS: [(&str, FullMetadataSizeBudget); 4] = [
    (
        "amm_pool.cell",
        FullMetadataSizeBudget {
            max_compact_metadata_bytes: 448 * 1024,
            max_proof_plan_records: 42,
            max_compact_proof_plan_bytes: 36 * 1024,
            max_source_units: 2,
            max_compact_source_units_bytes: 512,
        },
    ),
    (
        "nft.cell",
        FullMetadataSizeBudget {
            max_compact_metadata_bytes: 768 * 1024,
            // Typed HeaderDep epoch observation and checked Since construction
            // add two explicit CKB-runtime proof records to the listing path.
            max_proof_plan_records: 92,
            max_compact_proof_plan_bytes: 84 * 1024,
            max_source_units: 2,
            max_compact_source_units_bytes: 512,
        },
    ),
    (
        "token.cell",
        FullMetadataSizeBudget {
            max_compact_metadata_bytes: 192 * 1024,
            max_proof_plan_records: 30,
            max_compact_proof_plan_bytes: 24 * 1024,
            max_source_units: 1,
            max_compact_source_units_bytes: 256,
        },
    ),
    (
        "vesting.cell",
        FullMetadataSizeBudget {
            max_compact_metadata_bytes: 416 * 1024,
            // Five epoch-aware entry paths now retain their HeaderDep reads;
            // grant_vesting also records checked EpochDuration arithmetic.
            max_proof_plan_records: 64,
            max_compact_proof_plan_bytes: 58 * 1024,
            max_source_units: 2,
            max_compact_source_units_bytes: 512,
        },
    ),
];

const FULL_METADATA_ENTRY_COUNTS: [(&str, FullMetadataEntryCounts); 4] = [
    ("amm_pool.cell", FullMetadataEntryCounts { actions: 4, locks: 0 }),
    ("nft.cell", FullMetadataEntryCounts { actions: 10, locks: 5 }),
    ("token.cell", FullMetadataEntryCounts { actions: 4, locks: 0 }),
    ("vesting.cell", FullMetadataEntryCounts { actions: 5, locks: 1 }),
];

// Entry scoping removes unrelated executable entries, but retains the
// complete checker-facing foundation for the selected entry and any required
// helpers. Keep these caps within roughly 5-10% of the largest measured entry.
const ENTRY_ARTIFACT_SIZE_BUDGETS: [(&str, EntryArtifactSizeBudget); 4] = [
    (
        "amm_pool.cell",
        EntryArtifactSizeBudget {
            max_elf_bytes: 40 * 1024,
            max_compact_metadata_bytes: 156 * 1024,
            max_proof_plan_records: 11,
            max_compact_proof_plan_bytes: 10 * 1024,
            max_actions: 2,
            max_locks: 0,
        },
    ),
    (
        "nft.cell",
        EntryArtifactSizeBudget {
            max_elf_bytes: 48 * 1024,
            max_compact_metadata_bytes: 204 * 1024,
            max_proof_plan_records: 30,
            max_compact_proof_plan_bytes: 32 * 1024,
            max_actions: 1,
            max_locks: 1,
        },
    ),
    (
        "token.cell",
        EntryArtifactSizeBudget {
            max_elf_bytes: 12 * 1024,
            max_compact_metadata_bytes: 84 * 1024,
            max_proof_plan_records: 10,
            max_compact_proof_plan_bytes: 9 * 1024,
            max_actions: 1,
            max_locks: 0,
        },
    ),
    (
        "vesting.cell",
        EntryArtifactSizeBudget {
            max_elf_bytes: 28 * 1024,
            max_compact_metadata_bytes: 148 * 1024,
            max_proof_plan_records: 20,
            max_compact_proof_plan_bytes: 20 * 1024,
            max_actions: 1,
            max_locks: 1,
        },
    ),
];

const BUNDLED_EXAMPLE_ASM_SHAPE_BUDGETS: [(&str, AssemblyShapeBudget); 9] = [
    (
        "amm_pool.cell",
        AssemblyShapeBudget {
            max_lines: 22_000,
            max_fail_handlers: 32,
            max_shared_epilogues: 8,
            max_text_bytes: 92 * 1024,
            max_relaxed_branches: 4,
            max_cond_branch_abs_distance: 6_400,
            max_machine_blocks: 2_600,
            max_machine_block_bytes: 512,
            max_cfg_edges: 4_900,
            max_call_edges: 1_100,
            max_unreachable_machine_blocks: 2_300,
        },
    ),
    (
        "launch.cell",
        AssemblyShapeBudget {
            max_lines: 7_200,
            max_fail_handlers: 16,
            max_shared_epilogues: 4,
            max_text_bytes: 30 * 1024,
            max_relaxed_branches: 4,
            max_cond_branch_abs_distance: 9_500,
            max_machine_blocks: 860,
            max_machine_block_bytes: 2_048,
            max_cfg_edges: 1_500,
            max_call_edges: 250,
            max_unreachable_machine_blocks: 600,
        },
    ),
    (
        "multisig.cell",
        AssemblyShapeBudget {
            max_lines: 24_500,
            max_fail_handlers: 64,
            max_shared_epilogues: 20,
            // The v2 placement parser adds 68 bytes to the full multisig text
            // surface while the focused transfer entry remains below 7 KiB.
            max_text_bytes: 93 * 1024,
            max_relaxed_branches: 4,
            max_cond_branch_abs_distance: 7_700,
            max_machine_blocks: 3_600,
            max_machine_block_bytes: 512,
            max_cfg_edges: 5_800,
            max_call_edges: 360,
            max_unreachable_machine_blocks: 3_400,
        },
    ),
    (
        "nft.cell",
        AssemblyShapeBudget {
            max_lines: 22_000,
            max_fail_handlers: 80,
            max_shared_epilogues: 18,
            max_text_bytes: 90 * 1024,
            max_relaxed_branches: 4,
            max_cond_branch_abs_distance: 12_800,
            max_machine_blocks: 3_300,
            max_machine_block_bytes: 512,
            max_cfg_edges: 5_800,
            max_call_edges: 950,
            max_unreachable_machine_blocks: 3_100,
        },
    ),
    (
        "timelock.cell",
        AssemblyShapeBudget {
            max_lines: 21_000,
            max_fail_handlers: 64,
            max_shared_epilogues: 22,
            max_text_bytes: 84 * 1024,
            max_relaxed_branches: 4,
            max_cond_branch_abs_distance: 4_500,
            max_machine_blocks: 2_400,
            max_machine_block_bytes: 21_000,
            max_cfg_edges: 4_200,
            // Chain-bound timepoints and Token release checks intentionally add
            // helper calls while keeping the complete example within this budget.
            max_call_edges: 700,
            max_unreachable_machine_blocks: 2_300,
        },
    ),
    (
        "token.cell",
        AssemblyShapeBudget {
            max_lines: 3_400,
            max_fail_handlers: 24,
            max_shared_epilogues: 6,
            max_text_bytes: 13 * 1024,
            max_relaxed_branches: 4,
            max_cond_branch_abs_distance: 1_800,
            max_machine_blocks: 550,
            max_machine_block_bytes: 320,
            max_cfg_edges: 900,
            max_call_edges: 160,
            max_unreachable_machine_blocks: 280,
        },
    ),
    (
        "vesting.cell",
        AssemblyShapeBudget {
            max_lines: 10_000,
            max_fail_handlers: 36,
            max_shared_epilogues: 8,
            max_text_bytes: 42 * 1024,
            max_relaxed_branches: 4,
            max_cond_branch_abs_distance: 8_000,
            max_machine_blocks: 1_250,
            max_machine_block_bytes: 512,
            max_cfg_edges: 2_200,
            max_call_edges: 500,
            max_unreachable_machine_blocks: 1_150,
        },
    ),
    (
        "atomic_swap.cell",
        AssemblyShapeBudget {
            max_lines: 18_000,
            max_fail_handlers: 48,
            max_shared_epilogues: 12,
            max_text_bytes: 74 * 1024,
            max_relaxed_branches: 4,
            max_cond_branch_abs_distance: 9_600,
            max_machine_blocks: 2_600,
            max_machine_block_bytes: 21_000,
            max_cfg_edges: 4_200,
            max_call_edges: 800,
            max_unreachable_machine_blocks: 2_400,
        },
    ),
    (
        "multi_phase_dao.cell",
        AssemblyShapeBudget {
            max_lines: 15_000,
            max_fail_handlers: 48,
            max_shared_epilogues: 12,
            max_text_bytes: 60 * 1024,
            max_relaxed_branches: 4,
            max_cond_branch_abs_distance: 9_600,
            max_machine_blocks: 2_200,
            max_machine_block_bytes: 21_000,
            max_cfg_edges: 3_600,
            max_call_edges: 800,
            max_unreachable_machine_blocks: 2_000,
        },
    ),
];

#[derive(Debug, Clone, Copy, serde::Serialize)]
struct AssemblyShapeBudget {
    max_lines: usize,
    max_fail_handlers: usize,
    max_shared_epilogues: usize,
    max_text_bytes: usize,
    max_relaxed_branches: usize,
    max_cond_branch_abs_distance: u64,
    max_machine_blocks: usize,
    max_machine_block_bytes: usize,
    max_cfg_edges: usize,
    max_call_edges: usize,
    max_unreachable_machine_blocks: usize,
}

#[derive(Debug, Clone, Copy)]
struct FullMetadataSizeBudget {
    max_compact_metadata_bytes: usize,
    max_proof_plan_records: usize,
    max_compact_proof_plan_bytes: usize,
    max_source_units: usize,
    max_compact_source_units_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
struct FullMetadataEntryCounts {
    actions: usize,
    locks: usize,
}

#[derive(Debug, Clone, Copy)]
struct EntryArtifactSizeBudget {
    max_elf_bytes: usize,
    max_compact_metadata_bytes: usize,
    max_proof_plan_records: usize,
    max_compact_proof_plan_bytes: usize,
    max_actions: usize,
    max_locks: usize,
}

#[derive(Debug, serde::Serialize)]
struct BackendShapeReportRow {
    example: &'static str,
    line_count: usize,
    fail_handlers: usize,
    shared_epilogues: usize,
    fixed_byte_compare_helpers: usize,
    fixed_byte_zero_helpers: usize,
    min_size_guard_helpers: usize,
    exact_size_guard_helpers: usize,
    leaked_assembler_overflow_diagnostic: bool,
    budget: AssemblyShapeBudget,
    metrics: BackendShapeMetrics,
}

#[derive(Debug, serde::Serialize)]
struct MoleculeSchemaManifestReportRow {
    example: &'static str,
    type_count: usize,
    fixed_type_count: usize,
    dynamic_type_count: usize,
    manifest_hash: String,
    entries: Vec<String>,
}

fn example_path(name: &str) -> Utf8PathBuf {
    // Workspace packages: each example lives in examples/<name>/src/main.cell
    let trimmed = name.strip_suffix(".cell").unwrap_or(name);
    Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples").join(trimmed).join("src/main.cell")
}

fn language_example_path(name: &str) -> Utf8PathBuf {
    Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples").join("language").join(name)
}

fn docs_example_path(name: &str) -> Utf8PathBuf {
    Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs").join("examples").join(name)
}

fn markdown_cellscript_blocks(path: &Utf8Path) -> Vec<String> {
    let source = std::fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"));
    let mut blocks = Vec::new();
    let mut in_block = false;
    let mut cellscript_block = false;
    let mut current = Vec::new();

    for line in source.lines() {
        if let Some(lang) = line.strip_prefix("```") {
            if in_block {
                if cellscript_block {
                    blocks.push(current.join("\n"));
                }
                in_block = false;
                cellscript_block = false;
                current.clear();
            } else {
                in_block = true;
                cellscript_block = matches!(lang.trim(), "cellscript" | "cell");
            }
        } else if in_block && cellscript_block {
            current.push(line.to_string());
        }
    }

    blocks
}

fn write_wrapped_doc_snippet(temp_root: &Utf8Path, name: &str, source: &str) -> Utf8PathBuf {
    let path = temp_root.join(format!("{name}.cell"));
    let wrapped = format!("module docs::{name}\n\n{source}\n");
    std::fs::write(&path, wrapped).unwrap_or_else(|err| panic!("failed to write {path}: {err}"));
    path
}

fn checked_in_example_cell_files() -> Vec<Utf8PathBuf> {
    let examples_root = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples");
    let mut files = Vec::new();
    let entries = std::fs::read_dir(&examples_root).unwrap_or_else(|err| panic!("failed to read {examples_root}: {err}"));
    for entry in entries {
        let path = Utf8PathBuf::from_path_buf(entry.expect("example directory entry should be readable").path())
            .expect("example path should be valid UTF-8");
        if path.is_file() && path.extension() == Some("cell") {
            files.push(path);
        }
    }
    collect_language_example_cell_files(&examples_root.join("language"), &mut files);
    files.sort();
    files
}

fn collect_language_example_cell_files(root: &Utf8Path, output: &mut Vec<Utf8PathBuf>) {
    let entries = std::fs::read_dir(root).unwrap_or_else(|err| panic!("failed to read {root}: {err}"));
    for entry in entries {
        let path = Utf8PathBuf::from_path_buf(entry.expect("language example directory entry should be readable").path())
            .expect("language example path should be valid UTF-8");
        if path.is_dir() {
            collect_language_example_cell_files(&path, output);
        } else if path.is_file() && path.extension() == Some("cell") {
            output.push(path);
        }
    }
}

#[test]
fn canonical_examples_are_the_single_checked_in_business_source() {
    let examples_root = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples");
    assert!(!examples_root.join("business").exists(), "examples/business should not be checked in");
    assert!(!examples_root.join("acceptance").exists(), "examples/acceptance should not be checked in");

    for example in BUNDLED_EXAMPLES {
        let flat_path = example_path(example);
        let flat = std::fs::read_to_string(&flat_path).unwrap_or_else(|err| panic!("failed to read {flat_path}: {err}"));
        assert!(!flat.contains("#[effect("), "{flat_path} should not expose effect profile attributes");
        assert!(!flat.contains("#[scheduler_hint("), "{flat_path} should not expose scheduler profile attributes");
        compile_file(&flat_path, CompileOptions::default())
            .unwrap_or_else(|err| panic!("canonical example {example} should compile: {}", err.message));
    }
}

#[test]
fn package_examples_exactly_mirror_the_top_level_reading_sources() {
    let examples_root = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples");
    for package in PACKAGE_EXAMPLES {
        let flat_path = examples_root.join(format!("{package}.cell"));
        let package_path = examples_root.join(package).join("src/main.cell");
        let flat = std::fs::read_to_string(&flat_path).unwrap_or_else(|err| panic!("failed to read {flat_path}: {err}"));
        let packaged = std::fs::read_to_string(&package_path).unwrap_or_else(|err| panic!("failed to read {package_path}: {err}"));
        assert_eq!(packaged, flat, "package source {package_path} drifted from canonical reading source {flat_path}");
    }
}

#[test]
fn all_checked_in_cell_examples_compile() {
    let files = checked_in_example_cell_files();
    assert_eq!(
        files.len(),
        BUNDLED_EXAMPLES.len() + 1 + 22,
        "expected bundled examples, top-level registry.cell, and language examples"
    );

    for path in files {
        compile_file(&path, CompileOptions::default()).unwrap_or_else(|err| panic!("{path} should compile: {}", err.message));
    }
}

#[test]
fn dynamic_batch_examples_are_production_closed_runtime_contracts() {
    let cases = [
        ("batches/batch_claim.cell", "claim_many", 64_usize, 64_usize),
        ("batches/atomic_order_settlement.cell", "settle_orders", 16, 16),
        ("batches/cell_merge.cell", "merge_cells", 128, 1),
        ("batches/bridge_rollup_batch.cell", "execute_bridge_batch", 64, 64),
    ];

    for (file, action_name, input_max, output_max) in cases {
        let path = language_example_path(file);
        let result = compile_path_with_executable_surface_policy(
            &path,
            CompileOptions {
                target: Some("riscv64-elf".to_string()),
                target_profile: Some("ckb".to_string()),
                ..CompileOptions::default()
            },
            Some(CompileEntryScope::Action(action_name.to_string())),
            ExecutableSurfacePolicy::DenyFailClosed,
        )
        .unwrap_or_else(|err| panic!("{path} must pass the production executable-surface policy: {}", err.message));

        let action = result.metadata.actions.iter().find(|action| action.name == action_name).expect("scoped batch action");
        assert!(action.fail_closed_runtime_features.is_empty(), "{file} unexpectedly retained fail-closed features");
        let collections = &result.metadata.runtime.collection_instantiations;
        assert!(collections.iter().any(|item| {
            item.ownership == "linear-cell-set"
                && item.max_elements == input_max
                && item.helpers.iter().any(|helper| helper == cellscript::ir::BOUNDED_TYPE_GROUP_INPUTS_V1)
        }));
        let output_collection = collections.iter().find(|item| {
            item.ownership == "bounded-output-plan"
                && item.max_elements == output_max
                && item.helpers.iter().any(|helper| helper == cellscript::ir::BOUNDED_OUTPUT_PLAN_V1)
        });
        assert!(output_collection.is_some());
        let output_collection = output_collection.expect("checked above");
        let plan = cellscript::encode_bounded_output_plan_v1(
            &[vec![0; output_collection.element_width_bytes]],
            output_collection.element_width_bytes,
            output_collection.max_elements,
        )
        .expect("example plan shape must be encodable");
        let entry_payload = action
            .entry_witness_args(&[EntryWitnessArg::Bytes(plan)])
            .expect("the Cell-bound input set must not consume a positional witness argument");
        assert_eq!(&entry_payload[..8], b"CSARGv1\0");
        assert!(
            action
                .proof_plan
                .iter()
                .filter(|plan| plan.feature.starts_with("consume_each:") || plan.feature.starts_with("create_each:"))
                .all(|plan| {
                    plan.on_chain_checked
                        && plan.evidence_tier == cellscript::EvidenceTier::CheckedRuntime
                        && plan.coverage.iter().any(|item| item.starts_with("outer-numeric-accumulator-updated-once-per-element:"))
                }),
            "{file} must not describe checked batch behavior as builder-only evidence"
        );
    }
}

#[test]
fn docs_examples_cellscript_blocks_match_declared_compile_boundary() {
    let collections = markdown_cellscript_blocks(&docs_example_path("collections_matrix.md"));
    assert_eq!(
        collections.len(),
        3,
        "collections_matrix.md should have local-helper, schema-boundary, and rejected CellScript blocks"
    );
    let output_append = markdown_cellscript_blocks(&docs_example_path("output_append.md"));
    assert_eq!(output_append.len(), 1, "output_append.md should have one conceptual CellScript block");

    let temp = tempfile::tempdir().expect("tempdir should be available");
    let temp_root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).expect("temp path should be UTF-8");
    let positive_collections = write_wrapped_doc_snippet(&temp_root, "collections_positive", &collections[0]);
    compile_file(&positive_collections, CompileOptions::default())
        .unwrap_or_else(|err| panic!("{positive_collections} should compile: {}", err.message));

    let output_append_path = write_wrapped_doc_snippet(&temp_root, "output_append", &output_append[0]);
    compile_file(&output_append_path, CompileOptions::default())
        .unwrap_or_else(|err| panic!("{output_append_path} should compile: {}", err.message));

    let schema_boundary_collections = write_wrapped_doc_snippet(&temp_root, "collections_schema_boundary", &collections[1]);
    let schema_boundary_result = compile_file(&schema_boundary_collections, CompileOptions::default())
        .unwrap_or_else(|err| panic!("{schema_boundary_collections} should compile as a schema-boundary example: {}", err.message));
    let nested_dynamic = schema_boundary_result
        .metadata
        .molecule_schema_manifest
        .entries
        .iter()
        .find(|entry| entry.type_name == "NestedDynamic")
        .expect("negative collections block should expose NestedDynamic schema metadata");
    assert_eq!(nested_dynamic.layout, "molecule-table-v1");
    assert!(
        nested_dynamic.dynamic_fields.iter().any(|field| field == "rows"),
        "NestedDynamic should keep rows as an explicit dynamic schema field: {nested_dynamic:?}"
    );
    assert!(
        schema_boundary_result.metadata.runtime.collection_instantiations.is_empty(),
        "schema-boundary example must not be reported as stack-backed local collection helper support: {:?}",
        schema_boundary_result.metadata.runtime.collection_instantiations
    );

    let rejected_collections = write_wrapped_doc_snippet(&temp_root, "collections_rejected", &collections[2]);
    let rejected_source = std::fs::read_to_string(&rejected_collections).expect("rejected collection snippet should be readable");
    let rejected_report = compile_metadata_with_diagnostics(&rejected_source, cellscript::CURRENT_EDITION, None);
    assert!(
        rejected_report.diagnostics.iter().any(|diagnostic| {
            diagnostic.message.contains("type 'Vec<Token>' cannot store a cell-backed resource")
                && diagnostic.message.contains("use a source-aware BoundedCellSet<T, N> with explicit ownership")
        }),
        "cell-backed collection snippet should fail closed with source-aware guidance: {:?}",
        rejected_report.diagnostics
    );
}

#[test]
fn token_amm_bootstrap_docs_cover_builder_friction_boundary() {
    let bootstrap =
        std::fs::read_to_string(docs_example_path("token_amm_bootstrap.md")).expect("token/AMM bootstrap guide should be readable");
    let bootstrap_text = bootstrap.split_whitespace().collect::<Vec<_>>().join(" ");
    for needle in [
        "`examples/token.cell` is the fungible-token state machine. It is not the genesis authority contract",
        "Its `mint_with_authority` action consumes an existing `MintAuthority` input Cell",
        "launch_token` materialises the Pool and LP receipt topology directly",
        "Do not rely on \"the first action runs on creation\" as a protocol rule",
        "Cell-bound inputs and outputs are transaction Cells, not witness payload args",
        "place the payload in `input_type` before any lock-script signer runs",
        "Never submit the raw `CSARGv1` payload as a transaction witness",
        "Strict v0.16 ProofPlan checks compile the bundled token, AMM, and launch actions as original scoped entries",
    ] {
        assert!(bootstrap_text.contains(needle), "bootstrap guide should contain `{needle}`");
    }
    for needle in [
        "cellc entry-witness examples/launch.cell",
        "cellc entry-witness examples/token.cell",
        "cellc entry-witness examples/amm_pool.cell",
        "./scripts/ckb_cellscript_acceptance.sh --bounded --stateful-scenarios",
    ] {
        assert!(bootstrap.contains(needle), "bootstrap guide should contain `{needle}`");
    }
    assert!(
        !bootstrap.contains("Do not wrap it in `WitnessArgs.input_type`"),
        "bootstrap guide must not reintroduce the retired raw-witness placement guidance"
    );

    let flows = std::fs::read_to_string(
        Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs").join("CELLSCRIPT_EXAMPLE_BUSINESS_FLOWS.md"),
    )
    .expect("business flow guide should be readable");
    assert!(
        flows.contains("[`docs/examples/token_amm_bootstrap.md`](examples/token_amm_bootstrap.md)"),
        "business flow guide should link the bootstrap guide"
    );
    assert!(
        flows.contains("Materialise Pool and LPReceipt outputs"),
        "launch flow should describe direct Pool and LPReceipt output materialisation"
    );
    assert!(flows.contains("all 43 business actions"), "business flow guide should track the full production action count");
    assert!(
        flows.contains("Use `create_collection` to materialise the first live `Collection` Cell"),
        "NFT flow should document the Collection bootstrap action"
    );
    assert!(flows.contains("`create_collection -> mint ->"), "NFT flow should describe the stateful Collection-to-mint handoff");
    assert!(!flows.contains("Call seed_pool pattern"), "launch flow must not imply that launch_token calls amm_pool::seed_pool");
}

#[test]
fn release_examples_are_free_of_placeholder_hashes_and_formatter_artifacts() {
    for example in BUNDLED_EXAMPLES {
        let path = example_path(example);
        let source = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"));
        assert!(!source.contains("Hash::zero()"), "{path} should not use placeholder hash constants");
        assert!(!source.contains("fn hash_wallet"), "{path} should not hide wallet identity behind stub hashing");
        assert!(!source.contains("fn hash_lock"), "{path} should not hide lock identity behind stub hashing");
        assert!(
            !source.contains("{ { {") && !source.contains("} } }"),
            "{path} should not contain formatter/parser artifact brace nesting"
        );
    }
}

fn bundled_example_elf_size_budget(name: &str) -> usize {
    BUNDLED_EXAMPLE_ELF_SIZE_BUDGETS
        .iter()
        .find_map(|(example, budget)| (*example == name).then_some(*budget))
        .expect("missing bundled example ELF size budget")
}

fn bundled_example_asm_shape_budget(name: &str) -> AssemblyShapeBudget {
    BUNDLED_EXAMPLE_ASM_SHAPE_BUDGETS
        .iter()
        .find_map(|(example, budget)| (*example == name).then_some(*budget))
        .expect("missing bundled example assembly shape budget")
}

fn full_metadata_size_budget(name: &str) -> FullMetadataSizeBudget {
    FULL_METADATA_SIZE_BUDGETS
        .iter()
        .find_map(|(example, budget)| (*example == name).then_some(*budget))
        .expect("missing full metadata size budget")
}

fn full_metadata_entry_counts(name: &str) -> FullMetadataEntryCounts {
    FULL_METADATA_ENTRY_COUNTS
        .iter()
        .find_map(|(example, counts)| (*example == name).then_some(*counts))
        .expect("missing full metadata entry counts")
}

fn entry_artifact_size_budget(name: &str) -> EntryArtifactSizeBudget {
    ENTRY_ARTIFACT_SIZE_BUDGETS
        .iter()
        .find_map(|(example, budget)| (*example == name).then_some(*budget))
        .expect("missing entry artifact size budget")
}

fn ckb_elf_options() -> CompileOptions {
    CompileOptions { target: Some("riscv64-elf".to_string()), target_profile: Some("ckb".to_string()), ..CompileOptions::default() }
}

fn compact_json_len<T: serde::Serialize>(value: &T) -> usize {
    serde_json::to_vec(value).expect("metadata should serialize as compact JSON").len()
}

fn assert_source_units_are_not_source_archives(example: &str, metadata: &CompileMetadata, budget: FullMetadataSizeBudget) {
    assert!(
        metadata.source_units.len() <= budget.max_source_units,
        "{} metadata source_units grew past budget: {} > {}; source_units={:?}",
        example,
        metadata.source_units.len(),
        budget.max_source_units,
        metadata.source_units
    );
    let source_units_bytes = compact_json_len(&metadata.source_units);
    assert!(
        source_units_bytes <= budget.max_compact_source_units_bytes,
        "{} metadata source_units JSON grew past budget: {} > {}; source_units={:?}",
        example,
        source_units_bytes,
        budget.max_compact_source_units_bytes,
        metadata.source_units
    );

    let value = serde_json::to_value(&metadata.source_units).expect("source_units should serialize");
    let units = value.as_array().expect("source_units should serialize as an array");
    for unit in units {
        let object = unit.as_object().expect("source unit should serialize as an object");
        let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
        let expected = ["hash", "path", "role", "size_bytes"].into_iter().collect::<BTreeSet<_>>();
        assert_eq!(keys, expected, "{} source_units must stay as path/hash/size records, not source archives: {}", example, unit);
    }
}

fn assert_proof_plan_is_bounded(example: &str, entry: &str, metadata: &CompileMetadata, max_records: usize, max_json_bytes: usize) {
    let proof_plan = &metadata.runtime.proof_plan;
    let proof_plan_bytes = compact_json_len(proof_plan);
    assert!(
        proof_plan.len() <= max_records,
        "{} {} ProofPlan record count grew past budget: {} > {}; proof_plan={:?}",
        example,
        entry,
        proof_plan.len(),
        max_records,
        proof_plan
    );
    assert!(
        proof_plan_bytes <= max_json_bytes,
        "{} {} compact ProofPlan JSON grew past budget: {} > {} bytes",
        example,
        entry,
        proof_plan_bytes,
        max_json_bytes
    );

    let obligation_bound = metadata.runtime.verifier_obligations.len() + metadata.runtime.pool_primitives.len();
    assert!(
        proof_plan.len() <= obligation_bound,
        "{} {} ProofPlan records exceed verifier obligations plus pool primitives: {} > {}",
        example,
        entry,
        proof_plan.len(),
        obligation_bound
    );
    assert_eq!(
        metadata.runtime.proof_plan_soundness.issue_count, 0,
        "{} {} ProofPlan soundness must not report issues: {:?}",
        example, entry, metadata.runtime.proof_plan_soundness
    );

    let mut seen = BTreeSet::new();
    for plan in proof_plan {
        let key = (&plan.origin, &plan.category, &plan.feature, &plan.status, &plan.detail);
        assert!(seen.insert(key), "{} {} contains duplicate ProofPlan record: {:?}", example, entry, plan);
    }
}

fn assert_full_metadata_size_budget(example: &str, metadata: &CompileMetadata) {
    let budget = full_metadata_size_budget(example);
    let expected_counts = full_metadata_entry_counts(example);
    let metadata_bytes = compact_json_len(metadata);
    assert!(
        metadata_bytes <= budget.max_compact_metadata_bytes,
        "{} compact metadata JSON grew past budget: {} > {} bytes",
        example,
        metadata_bytes,
        budget.max_compact_metadata_bytes
    );
    assert_eq!(
        metadata.actions.len(),
        expected_counts.actions,
        "{} full metadata must retain every action entry; actions={:?}",
        example,
        metadata.actions.iter().map(|action| action.name.as_str()).collect::<Vec<_>>()
    );
    assert_eq!(
        metadata.locks.len(),
        expected_counts.locks,
        "{} full metadata must retain every lock entry; locks={:?}",
        example,
        metadata.locks.iter().map(|lock| lock.name.as_str()).collect::<Vec<_>>()
    );
    assert_proof_plan_is_bounded(example, "full", metadata, budget.max_proof_plan_records, budget.max_compact_proof_plan_bytes);
    assert_source_units_are_not_source_archives(example, metadata, budget);
}

fn assert_entry_artifact_size_budget(example: &str, entry_kind: &str, entry_name: &str, result: &CompileResult) {
    let budget = entry_artifact_size_budget(example);
    let entry = format!("{entry_kind}:{entry_name}");
    assert_eq!(result.artifact_format, ArtifactFormat::RiscvElf, "{} {} should compile to ELF", example, entry);
    assert!(
        result.artifact_bytes.len() <= budget.max_elf_bytes,
        "{} {} ELF artifact grew past budget: {} > {} bytes",
        example,
        entry,
        result.artifact_bytes.len(),
        budget.max_elf_bytes
    );
    assert_eq!(
        result.metadata.artifact_size_bytes,
        Some(result.artifact_bytes.len()),
        "{} {} metadata artifact_size_bytes must match emitted ELF",
        example,
        entry
    );
    assert_eq!(
        result.metadata.constraints.artifact.artifact_size_bytes,
        result.artifact_bytes.len(),
        "{} {} constraints artifact size must match emitted ELF",
        example,
        entry
    );

    let metadata_bytes = compact_json_len(&result.metadata);
    assert!(
        metadata_bytes <= budget.max_compact_metadata_bytes,
        "{} {} compact metadata JSON grew past budget: {} > {} bytes",
        example,
        entry,
        metadata_bytes,
        budget.max_compact_metadata_bytes
    );
    assert!(
        result.metadata.actions.len() <= budget.max_actions,
        "{} {} entry-scoped metadata retained too many actions: {} > {}; actions={:?}",
        example,
        entry,
        result.metadata.actions.len(),
        budget.max_actions,
        result.metadata.actions.iter().map(|action| action.name.as_str()).collect::<Vec<_>>()
    );
    assert!(
        result.metadata.locks.len() <= budget.max_locks,
        "{} {} entry-scoped metadata retained too many locks: {} > {}; locks={:?}",
        example,
        entry,
        result.metadata.locks.len(),
        budget.max_locks,
        result.metadata.locks.iter().map(|lock| lock.name.as_str()).collect::<Vec<_>>()
    );
    match entry_kind {
        "action" => assert!(
            result.metadata.actions.iter().any(|action| action.name == entry_name),
            "{} {} metadata must retain selected action",
            example,
            entry
        ),
        "lock" => assert!(
            result.metadata.locks.iter().any(|lock| lock.name == entry_name),
            "{} {} metadata must retain selected lock",
            example,
            entry
        ),
        other => panic!("unknown entry kind {other}"),
    }
    assert_proof_plan_is_bounded(
        example,
        &entry,
        &result.metadata,
        budget.max_proof_plan_records,
        budget.max_compact_proof_plan_bytes,
    );
}

fn count_lines_containing(assembly: &str, needle: &str) -> usize {
    assembly.lines().filter(|line| line.contains(needle)).count()
}

fn count_lines_with_prefix_and_contains(assembly: &str, prefix: &str, needle: &str) -> usize {
    assembly.lines().filter(|line| line.starts_with(prefix) && line.contains(needle)).count()
}

fn bundled_example_backend_shape_report_rows() -> Vec<BackendShapeReportRow> {
    BUNDLED_EXAMPLES
        .into_iter()
        .map(|example| {
            let result = compile_file(
                example_path(example),
                CompileOptions { target: Some("riscv64-asm".to_string()), ..CompileOptions::default() },
            )
            .unwrap_or_else(|e| panic!("{} should compile to assembly: {}", example, e.message));
            let assembly = std::str::from_utf8(&result.artifact_bytes)
                .unwrap_or_else(|e| panic!("{} emitted invalid utf-8 assembly: {}", example, e));
            let metrics =
                analyze_backend_shape(assembly).unwrap_or_else(|e| panic!("{} backend shape analysis failed: {}", example, e));

            BackendShapeReportRow {
                example,
                line_count: assembly.lines().count(),
                fail_handlers: count_lines_with_prefix_and_contains(assembly, ".L", "_fail_"),
                shared_epilogues: count_lines_with_prefix_and_contains(assembly, ".L", "_epilogue:"),
                fixed_byte_compare_helpers: count_lines_containing(assembly, "__cellscript_memcmp_fixed:"),
                fixed_byte_zero_helpers: count_lines_containing(assembly, "__cellscript_memzero_fixed:"),
                min_size_guard_helpers: count_lines_containing(assembly, "__cellscript_require_min_size:"),
                exact_size_guard_helpers: count_lines_containing(assembly, "__cellscript_require_exact_size:"),
                leaked_assembler_overflow_diagnostic: assembly.contains("immediate '"),
                budget: bundled_example_asm_shape_budget(example),
                metrics,
            }
        })
        .collect()
}

fn backend_shape_baseline_rows() -> Vec<serde_json::Value> {
    serde_json::from_str(BACKEND_SHAPE_BASELINE_JSON).expect("backend shape baseline JSON should parse")
}

fn json_u64(row: &serde_json::Value, field: &str) -> u64 {
    row.get(field)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| panic!("baseline row is missing integer field {field}: {row}"))
}

fn metric_u64(row: &BackendShapeReportRow, field: &str) -> u64 {
    let value = serde_json::to_value(row).expect("backend row should serialize");
    match field {
        "line_count" => value[field].as_u64().unwrap(),
        _ => value["metrics"][field].as_u64().unwrap_or_else(|| panic!("backend row is missing metric field {field}: {value}")),
    }
}

fn assert_with_regression_margin(example: &str, field: &str, actual: u64, baseline: u64) {
    let margin = match field {
        "relaxed_branch_count" => 1,
        "max_cond_branch_abs_distance" => 256,
        "max_machine_block_size" => 128,
        _ => (baseline / 20).max(16),
    };
    assert!(
        actual <= baseline + margin,
        "{} backend {} regressed past baseline margin: actual {} > baseline {} + margin {}",
        example,
        field,
        actual,
        baseline,
        margin
    );
}

fn action<'a>(metadata: &'a cellscript::CompileMetadata, name: &str) -> &'a cellscript::ActionMetadata {
    metadata.actions.iter().find(|action| action.name == name).unwrap_or_else(|| panic!("missing {name} action metadata"))
}

#[test]
fn registry_example_uses_bounded_local_vec_helpers_without_collection_debt() {
    let result = compile_file(language_example_path("collections/registry.cell"), CompileOptions::default())
        .expect("registry example should compile");
    let asm = String::from_utf8(result.artifact_bytes.clone()).expect("registry asm should be utf8");

    for marker in [
        "# cellscript abi: stack collection push element_size=32",
        "# cellscript abi: stack collection insert element_size=32",
        "# cellscript abi: stack collection remove element_size=32",
        "# cellscript abi: stack collection contains element_size=32",
        "# cellscript abi: stack collection pop element_size=32",
        "# cellscript abi: stack collection reverse element_size=32",
        "# cellscript abi: stack collection swap element_size=32",
        "# cellscript abi: stack collection truncate",
    ] {
        assert!(asm.contains(marker), "registry example should lower bounded Vec helper marker {marker}:\n{asm}");
    }

    for name in ["local_registry_membership", "local_registry_key_roundtrip"] {
        let action = action(&result.metadata, name);
        assert!(
            action.fail_closed_runtime_features.is_empty(),
            "registry {name} should not carry collection fail-closed debt: {:?}",
            action.fail_closed_runtime_features
        );
    }

    let membership_vec = result
        .metadata
        .runtime
        .collection_instantiations
        .iter()
        .find(|instantiation| {
            instantiation.scope_kind == "action"
                && instantiation.scope_name == "local_registry_membership"
                && instantiation.collection_ty == "Vec<Address>"
        })
        .expect("registry membership should expose Vec<Address> monomorphization metadata");
    assert_eq!(membership_vec.element_ty, "Address");
    assert_eq!(membership_vec.element_width_bytes, 32);
    assert_eq!(membership_vec.max_elements, 8);
    for helper in ["with_capacity", "push", "insert", "swap", "remove", "truncate", "set", "contains", "index"] {
        assert!(
            membership_vec.helpers.contains(&helper.to_string()),
            "Vec<Address> metadata should expose helper {helper}: {:?}",
            membership_vec.helpers
        );
    }
    assert!(
        !membership_vec.helpers.contains(&"new".to_string()),
        "Vec<Address> metadata should preserve Vec::with_capacity instead of collapsing it to new: {:?}",
        membership_vec.helpers
    );

    let hash_vec = result
        .metadata
        .constraints
        .collection_instantiations
        .iter()
        .find(|instantiation| {
            instantiation.scope_kind == "action"
                && instantiation.scope_name == "local_registry_key_roundtrip"
                && instantiation.collection_ty == "Vec<Hash>"
        })
        .expect("registry key roundtrip should expose Vec<Hash> constraints metadata");
    assert_eq!(hash_vec.element_ty, "Hash");
    assert_eq!(hash_vec.element_width_bytes, 32);
    assert_eq!(hash_vec.backing, "stack-fixed-buffer:256");
    for helper in ["new", "push", "pop", "swap", "reverse", "index", "len"] {
        assert!(
            hash_vec.helpers.contains(&helper.to_string()),
            "Vec<Hash> constraints metadata should expose helper {helper}: {:?}",
            hash_vec.helpers
        );
    }
}

#[test]
fn registry_example_with_insert_contains_compiles_to_elf() {
    let result = compile_file(
        language_example_path("collections/registry.cell"),
        CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() },
    )
    .expect("registry example should compile to ELF through the internal assembler");

    assert!(!result.artifact_bytes.is_empty(), "registry ELF artifact should be non-empty");
}

#[test]
fn order_book_language_example_uses_local_vec_helpers_without_collection_debt() {
    let result = compile_file(language_example_path("collections/order_book.cell"), CompileOptions::default())
        .expect("order book example should compile");
    let asm = String::from_utf8(result.artifact_bytes.clone()).expect("order book asm should be utf8");

    for marker in [
        "# cellscript abi: stack collection push element_size=56",
        "# cellscript abi: stack collection insert element_size=56",
        "# cellscript abi: stack collection contains element_size=56",
        "# cellscript abi: stack collection remove element_size=56",
        "# cellscript abi: stack collection pop element_size=56",
        "# cellscript abi: stack collection reverse element_size=56",
        "# cellscript abi: stack collection swap element_size=56",
        "# cellscript abi: stack collection clear",
    ] {
        assert!(asm.contains(marker), "order book example should lower bounded Vec helper marker {marker}:\n{asm}");
    }

    for name in ["local_book_seed", "local_bid_priority", "local_cancel_order", "local_match_quote"] {
        let action = action(&result.metadata, name);
        assert!(
            action.fail_closed_runtime_features.is_empty(),
            "order book {name} should not carry collection fail-closed debt: {:?}",
            action.fail_closed_runtime_features
        );
    }

    let order_vecs = result
        .metadata
        .runtime
        .collection_instantiations
        .iter()
        .filter(|instantiation| instantiation.collection_ty == "Vec<Order>")
        .collect::<Vec<_>>();
    assert!(!order_vecs.is_empty(), "order book should expose Vec<Order> monomorphization metadata");
    for instantiation in &order_vecs {
        assert_eq!(instantiation.element_ty, "Order");
        assert_eq!(instantiation.element_width_bytes, 56);
        assert_eq!(instantiation.backing, "stack-fixed-buffer:256");
        assert_eq!(instantiation.status, "checked-runtime");
    }

    let bid_priority = order_vecs
        .iter()
        .find(|instantiation| instantiation.scope_name == "local_bid_priority")
        .expect("bid priority should expose Vec<Order> metadata");
    for helper in ["new", "push", "insert", "swap", "reverse", "index", "len"] {
        assert!(
            bid_priority.helpers.contains(&helper.to_string()),
            "order book bid priority should expose helper {helper}: {:?}",
            bid_priority.helpers
        );
    }

    let cancel = order_vecs
        .iter()
        .find(|instantiation| instantiation.scope_name == "local_cancel_order")
        .expect("cancel should expose Vec<Order> metadata");
    for helper in ["new", "push", "contains", "remove", "clear", "len"] {
        assert!(cancel.helpers.contains(&helper.to_string()), "order book cancel should expose helper {helper}: {:?}", cancel.helpers);
    }

    let elf = compile_file(
        language_example_path("collections/order_book.cell"),
        CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() },
    )
    .expect("order book example should compile to ELF through the internal assembler");
    assert!(!elf.artifact_bytes.is_empty(), "order book ELF artifact should be non-empty");
}

#[test]
fn stdlib_language_example_compiles_with_all_patterns() {
    let result =
        compile_file(language_example_path("core/stdlib.cell"), CompileOptions::default()).expect("stdlib example should compile");
    assert!(!result.artifact_bytes.is_empty(), "stdlib artifact should be non-empty");
    let asm = String::from_utf8(result.artifact_bytes.clone()).expect("stdlib asm should be utf8");

    assert!(
        result.metadata.actions.iter().any(|action| action.name == "coin_preserve_type"),
        "stdlib example should expose coin_preserve_type action"
    );
    assert!(
        result.metadata.actions.iter().any(|action| action.name == "coin_same_lock"),
        "stdlib example should expose coin_same_lock action"
    );
    assert!(
        result.metadata.actions.iter().any(|action| action.name == "coin_preserve_lock"),
        "stdlib example should expose coin_preserve_lock action"
    );
    assert!(
        result.metadata.actions.iter().any(|action| action.name == "coin_preserve_capacity"),
        "stdlib example should expose coin_preserve_capacity action"
    );
    assert!(
        result.metadata.actions.iter().any(|action| action.name == "coin_conserved"),
        "stdlib example should expose coin_conserved action"
    );
    assert!(
        result.metadata.actions.iter().any(|action| action.name == "transfer_coin"),
        "stdlib example should expose transfer_coin action"
    );
    assert!(
        result.metadata.actions.iter().any(|action| action.name == "claim_voucher"),
        "stdlib example should expose claim_voucher action"
    );
    assert!(
        result.metadata.actions.iter().any(|action| action.name == "settle_voucher"),
        "stdlib example should expose settle_voucher action"
    );

    let transfer_coin = result.metadata.actions.iter().find(|action| action.name == "transfer_coin").expect("transfer_coin action");
    assert_eq!(transfer_coin.effect_class, "Mutating");
    assert!(
        transfer_coin.consume_set.iter().any(|pattern| pattern.operation == "consume" && pattern.binding == "coin"),
        "transfer_coin should consume the input coin: {:?}",
        transfer_coin.consume_set
    );
    let transfer_outputs = transfer_coin
        .create_set
        .iter()
        .filter(|pattern| pattern.operation == "output" && pattern.binding == "next_coin")
        .collect::<Vec<_>>();
    assert_eq!(
        transfer_outputs.len(),
        1,
        "transfer_coin should expose exactly one canonical output constraint: {:?}",
        transfer_coin.create_set
    );
    assert!(transfer_outputs[0].has_lock, "transfer stdlib output must bind the destination lock");
    assert_eq!(
        transfer_outputs[0].fields,
        vec!["amount".to_string(), "nonce".to_string()],
        "transfer stdlib output should preserve the full example output field set"
    );

    let same_lock = result.metadata.actions.iter().find(|action| action.name == "coin_same_lock").expect("coin_same_lock action");
    assert!(same_lock.fail_closed_runtime_features.is_empty());
    assert!(
        same_lock.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "cell-metadata-equality:lock_hash:coin_after:coin_before"
                && requirement.component == "cell-metadata-lock_hash"
                && requirement.status == "checked-runtime"
                && requirement.source == "InputOutput"
                && requirement.binding == "coin_after:coin_before"
                && requirement.field.as_deref() == Some("lock_hash")
                && requirement.abi == "cell-metadata-lock-hash-equality-32"
                && requirement.byte_len == Some(32)
        }),
        "coin_same_lock should expose checked lock-hash metadata requirements: {:?}",
        same_lock.transaction_runtime_input_requirements
    );
    let preserve_lock =
        result.metadata.actions.iter().find(|action| action.name == "coin_preserve_lock").expect("coin_preserve_lock action");
    assert!(
        preserve_lock.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "cell-metadata-equality:lock_hash:coin_after:coin_before"
                && requirement.component == "cell-metadata-lock_hash"
                && requirement.status == "checked-runtime"
                && requirement.byte_len == Some(32)
        }),
        "coin_preserve_lock should share the checked lock-hash metadata lowering: {:?}",
        preserve_lock.transaction_runtime_input_requirements
    );

    let preserve_capacity =
        result.metadata.actions.iter().find(|action| action.name == "coin_preserve_capacity").expect("coin_preserve_capacity action");
    assert!(preserve_capacity.fail_closed_runtime_features.is_empty());
    assert!(
        preserve_capacity.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "cell-metadata-equality:capacity:coin_after:coin_before"
                && requirement.component == "cell-metadata-capacity"
                && requirement.status == "checked-runtime"
                && requirement.source == "InputOutput"
                && requirement.binding == "coin_after:coin_before"
                && requirement.field.as_deref() == Some("capacity")
                && requirement.abi == "cell-metadata-capacity-equality-8"
                && requirement.byte_len == Some(8)
        }),
        "coin_preserve_capacity should expose checked capacity metadata requirements: {:?}",
        preserve_capacity.transaction_runtime_input_requirements
    );
    assert!(
        asm.contains("# cellscript abi: LOAD_CELL_BY_FIELD reason=cell_metadata_left_lock_hash source=Output index=0 field=3")
            && asm.contains("# cellscript abi: LOAD_CELL_BY_FIELD reason=cell_metadata_right_lock_hash source=Input index=0 field=3")
            && asm.contains("# cellscript abi: verify cell metadata lock_hash equality Output#0 == Input#0 size=32"),
        "lock metadata stdlib helpers should lower to canonical cell field syscalls:\n{}",
        asm
    );
    assert!(
        asm.contains("# cellscript abi: LOAD_CELL_BY_FIELD reason=cell_metadata_left_capacity source=Output index=0 field=0")
            && asm.contains("# cellscript abi: LOAD_CELL_BY_FIELD reason=cell_metadata_right_capacity source=Input index=0 field=0")
            && asm.contains("# cellscript abi: verify cell metadata capacity equality Output#0 == Input#0 size=8"),
        "capacity metadata stdlib helper should lower to canonical cell field syscalls:\n{}",
        asm
    );

    let claim_voucher = result.metadata.actions.iter().find(|action| action.name == "claim_voucher").expect("claim_voucher action");
    assert_eq!(claim_voucher.effect_class, "Mutating");
    assert!(
        claim_voucher.consume_set.iter().any(|pattern| pattern.binding == "voucher"),
        "claim_voucher should consume the input voucher: {:?}",
        claim_voucher.consume_set
    );
    assert!(
        claim_voucher.create_set.iter().any(|pattern| pattern.operation == "output" && pattern.binding == "coin" && pattern.has_lock),
        "claim_voucher should create and lock the canonical claim output: {:?}",
        claim_voucher.create_set
    );
    let claim_output = claim_voucher
        .create_set
        .iter()
        .find(|pattern| pattern.operation == "output" && pattern.binding == "coin")
        .expect("claim output metadata");
    assert_eq!(
        claim_output.fields,
        vec!["amount".to_string(), "nonce".to_string()],
        "claim_voucher should preserve every Coin field present in the example output"
    );

    let settle_voucher = result.metadata.actions.iter().find(|action| action.name == "settle_voucher").expect("settle_voucher action");
    assert!(
        settle_voucher.create_set.iter().any(|pattern| pattern.operation == "output" && pattern.binding == "coin" && pattern.has_lock),
        "settle_voucher should create and lock the canonical settle output: {:?}",
        settle_voucher.create_set
    );
    let settle_output = settle_voucher
        .create_set
        .iter()
        .find(|pattern| pattern.operation == "output" && pattern.binding == "coin")
        .expect("settle output metadata");
    assert_eq!(
        settle_output.fields,
        vec!["amount".to_string(), "nonce".to_string()],
        "settle_voucher should preserve every Coin field present in the example output"
    );

    let elf = compile_file(
        language_example_path("core/stdlib.cell"),
        CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() },
    )
    .expect("stdlib example should compile to ELF through the internal assembler");
    assert!(!elf.artifact_bytes.is_empty(), "stdlib ELF artifact should be non-empty");
}

fn assert_create(action: &cellscript::ActionMetadata, ty: &str, context: &str) {
    assert!(
        action.create_set.iter().any(|pattern| pattern.ty == ty && matches!(pattern.operation.as_str(), "create" | "output")),
        "{} should expose a create output for {}: {:?}",
        context,
        ty,
        action.create_set
    );
}

fn assert_destroy(action: &cellscript::ActionMetadata, binding: &str, context: &str) {
    assert!(
        action.consume_set.iter().any(|pattern| pattern.binding == binding && pattern.operation == "destroy"),
        "{} should expose destroy input '{}': {:?}",
        context,
        binding,
        action.consume_set
    );
}

fn assert_input_output_binding(
    action: &cellscript::ActionMetadata,
    ty: &str,
    input_binding: &str,
    output_binding: &str,
    context: &str,
) {
    assert!(
        action.consume_set.iter().any(|pattern| pattern.operation == "input" && pattern.binding == input_binding),
        "{} should expose input '{}': {:?}",
        context,
        input_binding,
        action.consume_set
    );
    assert!(
        action.create_set.iter().any(|pattern| pattern.ty == ty && pattern.operation == "output" && pattern.binding == output_binding),
        "{} should expose output '{}': {:?}",
        context,
        output_binding,
        action.create_set
    );
}

fn assert_runtime_requirement(action: &cellscript::ActionMetadata, feature: &str, status: &str, component: &str, context: &str) {
    assert!(
        action.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == feature && requirement.status == status && requirement.component == component
        }),
        "{} should expose {} {} runtime requirement for {}: {:?}",
        context,
        status,
        component,
        feature,
        action.transaction_runtime_input_requirements
    );
}

fn assert_no_runtime_requirement(action: &cellscript::ActionMetadata, feature: &str, component: &str, context: &str) {
    assert!(
        !action
            .transaction_runtime_input_requirements
            .iter()
            .any(|requirement| { requirement.feature == feature && requirement.component == component }),
        "{} should not expose {} runtime requirement for {}: {:?}",
        context,
        component,
        feature,
        action.transaction_runtime_input_requirements
    );
}

#[test]
fn bundled_examples_compile_to_non_empty_assembly() {
    for example in BUNDLED_EXAMPLES {
        let result = compile_file(example_path(example), CompileOptions::default()).unwrap_or_else(|err| {
            panic!("failed to compile {}: {}", example, err);
        });

        assert_eq!(result.artifact_format, ArtifactFormat::RiscvAssembly, "unexpected artifact format for {}", example);
        assert!(!result.artifact_bytes.is_empty(), "empty artifact for {}", example);
        assert!(result.metadata.artifact_hash.is_some(), "missing artifact hash metadata for {}", example);
        assert!(result.metadata.artifact_size_bytes.is_some(), "missing artifact size metadata for {}", example);
        assert_eq!(result.metadata.constraints.target_profile, "ckb", "missing CKB constraints profile for {}", example);
        assert!(result.metadata.constraints.artifact.artifact_size_bytes > 0, "missing artifact constraints size for {}", example);
        assert!(!result.metadata.constraints.entry_abi.is_empty(), "missing entry ABI constraints for {}", example);
        assert!(result.metadata.constraints.ckb.is_some(), "missing CKB constraints for {}", example);
        assert!(!result.metadata.actions.is_empty(), "missing action metadata for {}", example);
    }
}

#[test]
fn temporal_business_examples_use_the_typed_header_epoch_api() {
    for (example, business_family) in TEMPORAL_BUSINESS_EXAMPLES {
        let source = std::fs::read_to_string(example_path(example)).expect("read temporal business example");
        let diagnostics = cellscript::frontend::legacy_temporal_migration_diagnostics(&source);
        assert!(
            diagnostics.iter().all(|diagnostic| diagnostic.code.as_deref() != Some("W3012")),
            "{business_family} still uses a legacy raw temporal API: {:?}",
            diagnostics
        );
        let metadata = compile_file(example_path(example), CompileOptions::default())
            .unwrap_or_else(|error| panic!("{business_family} typed temporal example must compile: {error}"))
            .metadata;
        assert!(
            metadata.runtime.ckb_runtime_features.contains(&"ckb-header-epoch-number".to_string()),
            "{business_family} must retain the typed HeaderDep epoch read"
        );
        assert!(
            !metadata.runtime.ckb_runtime_features.contains(&"load-header-timepoint".to_string()),
            "{business_family} must not fall back to env::current_timepoint"
        );
    }
}

#[test]
fn bundled_package_examples_compile_with_cross_package_source_units() {
    for package in PACKAGE_EXAMPLES {
        let package_root = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples").join(package);
        let result = compile_path(&package_root, CompileOptions::default()).unwrap_or_else(|err| {
            panic!("failed to compile package example {}: {}", package, err);
        });
        let roles = result.metadata.source_units.iter().map(|unit| unit.role.as_str()).collect::<BTreeSet<_>>();
        assert!(roles.contains("entry"), "{} should bind its entry source unit", package);
        if ["amm_pool", "atomic_swap", "launch", "multi_phase_dao", "nft", "timelock", "vesting"].contains(&package) {
            assert!(roles.contains("dependency"), "{} should bind dependency source units", package);
            assert!(
                result.metadata.source_units.iter().any(|unit| unit.path.contains("examples/token/src/main.cell")),
                "{} should include token package source evidence",
                package
            );
        }
    }
}

#[test]
fn non_production_business_examples_model_token_custody_explicitly() {
    let swap = compile_file(example_path("atomic_swap.cell"), CompileOptions::default()).expect("atomic swap should compile");
    assert!(
        action(&swap.metadata, "initiate_swap")
            .consume_set
            .iter()
            .any(|pattern| pattern.binding == "token" && pattern.operation == "consume"),
        "atomic swap initiation should consume the locked Token"
    );
    assert_create(action(&swap.metadata, "claim_with_preimage"), "Token", "atomic swap claim");
    assert_create(action(&swap.metadata, "refund_after_timeout"), "Token", "atomic swap refund");

    let dao = compile_file(example_path("multi_phase_dao.cell"), CompileOptions::default()).expect("DAO example should compile");
    let cast_vote = action(&dao.metadata, "cast_vote");
    assert!(
        cast_vote.consume_set.iter().any(|pattern| pattern.operation == "consume" && pattern.binding == "proposal_before"),
        "DAO vote accounting should consume the prior Proposal: {:?}",
        cast_vote.consume_set
    );
    assert!(
        cast_vote
            .create_set
            .iter()
            .any(|pattern| { pattern.ty == "Proposal" && pattern.operation == "output" && pattern.binding == "proposal_after" }),
        "DAO vote accounting should create the updated Proposal: {:?}",
        cast_vote.create_set
    );
    assert!(
        cast_vote.consume_set.iter().any(|pattern| pattern.binding == "voting_token" && pattern.operation == "consume"),
        "DAO vote custody should consume the voting Token"
    );
    assert_create(cast_vote, "VoteReceipt", "DAO vote custody");
    let redeem_vote = action(&dao.metadata, "redeem_vote");
    assert!(
        redeem_vote.consume_set.iter().any(|pattern| pattern.binding == "vote" && pattern.operation == "consume"),
        "DAO vote redemption should consume the VoteReceipt"
    );
    assert_create(redeem_vote, "Token", "DAO vote redemption");
}

#[test]
fn ecosystem_identity_adapter_packages_compile() {
    for package in ["spore-identity-adapter", "rgbpp-identity-adapter"] {
        let package_root = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples").join("ecosystem").join(package);
        let result =
            compile_path(&package_root, CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() })
                .unwrap_or_else(|err| panic!("failed to compile ecosystem adapter {package}: {err}"));
        assert!(
            !result.metadata.actions.is_empty() || !result.metadata.locks.is_empty(),
            "ecosystem adapter {package} must expose an executable entry"
        );
    }
}

#[test]
fn bundled_examples_compile_to_elf() {
    for example in BUNDLED_EXAMPLES {
        let result = compile_file(
            example_path(example),
            CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() },
        )
        .unwrap_or_else(|e| panic!("{} should compile to ELF: {}", example, e.message));

        assert!(!result.artifact_bytes.is_empty(), "ELF artifact for {} should be non-empty", example);
        assert!(
            result.artifact_bytes.len() <= bundled_example_elf_size_budget(example),
            "ELF artifact for {} grew past its backend shape budget: {} > {} bytes",
            example,
            result.artifact_bytes.len(),
            bundled_example_elf_size_budget(example)
        );
    }
}

#[test]
fn bundled_ckb_artifact_size_experiment_keeps_entry_artifacts_and_metadata_bounded() {
    for example in ARTIFACT_SIZE_EXPERIMENT_EXAMPLES {
        let path = example_path(example);
        let full_result = compile_file(&path, ckb_elf_options())
            .unwrap_or_else(|err| panic!("{example} should compile to full CKB ELF: {}", err.message));
        assert_full_metadata_size_budget(example, &full_result.metadata);

        let actions = full_result.metadata.actions.iter().map(|action| action.name.clone()).collect::<Vec<_>>();
        let locks = full_result.metadata.locks.iter().map(|lock| lock.name.clone()).collect::<Vec<_>>();
        assert!(!actions.is_empty(), "{example} must expose at least one action for entry-size testing");

        for action in actions {
            let result = compile_file_with_entry_action(&path, ckb_elf_options(), action.clone())
                .unwrap_or_else(|err| panic!("{example} action {action} should compile to entry CKB ELF: {}", err.message));
            assert_entry_artifact_size_budget(example, "action", &action, &result);
        }

        for lock in locks {
            let result = compile_file_with_entry_lock(&path, ckb_elf_options(), lock.clone())
                .unwrap_or_else(|err| panic!("{example} lock {lock} should compile to entry CKB ELF: {}", err.message));
            assert_entry_artifact_size_budget(example, "lock", &lock, &result);
        }

        let cached_full_result = compile_file(&path, ckb_elf_options())
            .unwrap_or_else(|err| panic!("{example} should keep full CKB ELF metadata after entry compiles: {}", err.message));
        assert_full_metadata_size_budget(example, &cached_full_result.metadata);
    }
}

#[test]
fn ckb_scoped_entry_keeps_called_action_helpers() {
    let result = compile_file_with_entry_action(
        example_path("amm_pool.cell"),
        CompileOptions {
            target: Some("riscv64-asm".to_string()),
            target_profile: Some("ckb".to_string()),
            ..CompileOptions::default()
        },
        "seed_pool",
    )
    .expect("seed_pool scoped CKB artifact should compile");
    let assembly = std::str::from_utf8(&result.artifact_bytes).expect("assembly should be utf-8");

    assert!(assembly.contains("\nisqrt:\n"), "scoped seed_pool artifact should retain called pure helper isqrt");
    assert_eq!(result.metadata.constraints.target_profile, "ckb");
    assert!(result.metadata.constraints.ckb.is_some(), "CKB scoped artifact should expose CKB production constraints");
    assert!(result.metadata.constraints.ckb.is_some(), "CKB scoped artifact should report CKB constraints");
    let ckb = result.metadata.constraints.ckb.as_ref().unwrap();
    assert!(ckb.max_tx_verify_cycles > 0);
    assert!(ckb.min_code_cell_data_capacity_shannons > 0);
    assert!(ckb.dry_run_required_for_production);
}

#[test]
fn bundled_examples_stay_within_backend_shape_budgets() {
    for row in bundled_example_backend_shape_report_rows() {
        let example = row.example;
        let budget = row.budget;
        let backend_shape = row.metrics;

        assert!(
            row.line_count <= budget.max_lines,
            "{} assembly grew past its backend shape budget: {} > {} lines",
            example,
            row.line_count,
            budget.max_lines
        );
        assert!(
            row.fail_handlers <= budget.max_fail_handlers,
            "{} emitted too many shared fail handlers: {} > {}",
            example,
            row.fail_handlers,
            budget.max_fail_handlers
        );
        assert!(
            row.shared_epilogues <= budget.max_shared_epilogues,
            "{} emitted too many shared epilogues: {} > {}",
            example,
            row.shared_epilogues,
            budget.max_shared_epilogues
        );
        assert_eq!(
            backend_shape.covered_text_op_count, backend_shape.executable_text_op_count,
            "{} machine-block coverage should cover every executable text op exactly once: {:?}",
            example, backend_shape
        );
        assert_eq!(
            backend_shape.layout_order_block_count, backend_shape.machine_block_count,
            "{} layout order should include every machine block: {:?}",
            example, backend_shape
        );
        assert_eq!(
            backend_shape.layout_order_text_size, backend_shape.text_size,
            "{} planned layout size should match text size: {:?}",
            example, backend_shape
        );
        assert!(
            backend_shape.text_size <= budget.max_text_bytes,
            "{} text section grew past its backend shape budget: {} > {} bytes ({:?})",
            example,
            backend_shape.text_size,
            budget.max_text_bytes,
            backend_shape
        );
        assert!(
            backend_shape.relaxed_branch_count <= budget.max_relaxed_branches,
            "{} emitted too many relaxed conditional branches: {} > {} ({:?})",
            example,
            backend_shape.relaxed_branch_count,
            budget.max_relaxed_branches,
            backend_shape
        );
        assert!(
            backend_shape.max_cond_branch_abs_distance <= budget.max_cond_branch_abs_distance,
            "{} conditional branch displacement grew past its backend budget: {} > {} ({:?})",
            example,
            backend_shape.max_cond_branch_abs_distance,
            budget.max_cond_branch_abs_distance,
            backend_shape
        );
        assert!(
            backend_shape.machine_block_count <= budget.max_machine_blocks,
            "{} machine block count grew past its backend shape budget: {} > {} ({:?})",
            example,
            backend_shape.machine_block_count,
            budget.max_machine_blocks,
            backend_shape
        );
        assert!(
            backend_shape.max_machine_block_size <= budget.max_machine_block_bytes,
            "{} machine block size grew past its backend shape budget: {} > {} bytes ({:?})",
            example,
            backend_shape.max_machine_block_size,
            budget.max_machine_block_bytes,
            backend_shape
        );
        assert!(
            backend_shape.machine_cfg_edge_count <= budget.max_cfg_edges,
            "{} CFG edge count grew past its backend shape budget: {} > {} ({:?})",
            example,
            backend_shape.machine_cfg_edge_count,
            budget.max_cfg_edges,
            backend_shape
        );
        assert!(
            backend_shape.machine_call_edge_count <= budget.max_call_edges,
            "{} call edge count grew past its backend shape budget: {} > {} ({:?})",
            example,
            backend_shape.machine_call_edge_count,
            budget.max_call_edges,
            backend_shape
        );
        assert!(
            backend_shape.unreachable_machine_block_count <= budget.max_unreachable_machine_blocks,
            "{} unreachable machine block count grew past its backend shape budget: {} > {} ({:?})",
            example,
            backend_shape.unreachable_machine_block_count,
            budget.max_unreachable_machine_blocks,
            backend_shape
        );
        assert_eq!(row.fixed_byte_compare_helpers, 1, "{} should emit one fixed-byte comparison helper", example);
        assert_eq!(row.fixed_byte_zero_helpers, 1, "{} should emit one fixed-byte zero helper", example);
        assert_eq!(row.min_size_guard_helpers, 1, "{} should emit one minimum-size guard helper", example);
        assert_eq!(row.exact_size_guard_helpers, 1, "{} should emit one exact-size guard helper", example);
        assert!(
            !row.leaked_assembler_overflow_diagnostic,
            "{} assembly should not contain a leaked assembler overflow diagnostic",
            example
        );
    }
}

#[test]
fn bundled_examples_backend_shape_report_serializes() {
    let rows = bundled_example_backend_shape_report_rows();
    assert_eq!(rows.len(), BUNDLED_EXAMPLES.len(), "backend shape report should cover every bundled example");
    for (row, expected) in rows.iter().zip(BUNDLED_EXAMPLES) {
        assert_eq!(row.example, expected, "backend shape report should preserve bundled example order");
    }

    let json = serde_json::to_string_pretty(&rows).expect("backend shape report should serialize to JSON");
    assert!(json.contains("\"max_machine_block_bytes\""), "shape report should include machine-block size budgets");
    assert!(json.contains("\"max_call_edges\""), "shape report should include call-edge budgets");
    assert!(json.contains("\"unreachable_machine_block_count\""), "shape report should include unreachable-block metrics");
    assert!(json.contains("\"machine_call_edge_count\""), "shape report should include call-edge metrics");
    assert!(json.contains("\"fixed_byte_compare_helpers\""), "shape report should include helper dedup metrics");

    if let Ok(path) = std::env::var("CELLSCRIPT_BACKEND_SHAPE_REPORT") {
        std::fs::write(&path, json).unwrap_or_else(|e| panic!("failed to write backend shape report to {}: {}", path, e));
    }
}

#[test]
fn bundled_examples_stay_near_backend_shape_release_baseline() {
    let rows = bundled_example_backend_shape_report_rows();
    let baseline = backend_shape_baseline_rows();
    assert_eq!(baseline.len(), BUNDLED_EXAMPLES.len(), "backend shape baseline must cover every bundled example");

    let fields = [
        "line_count",
        "text_size",
        "relaxed_branch_count",
        "max_cond_branch_abs_distance",
        "machine_block_count",
        "max_machine_block_size",
        "machine_cfg_edge_count",
        "machine_call_edge_count",
        "unreachable_machine_block_count",
    ];
    for (row, baseline_row) in rows.iter().zip(baseline.iter()) {
        assert_eq!(baseline_row["example"].as_str(), Some(row.example), "backend shape baseline order changed");
        for field in fields {
            assert_with_regression_margin(row.example, field, metric_u64(row, field), json_u64(baseline_row, field));
        }
    }
}

#[test]
fn bundled_examples_emit_molecule_schema_manifest_report() {
    let rows = BUNDLED_EXAMPLES
        .into_iter()
        .map(|example| {
            let result = compile_file(example_path(example), CompileOptions::default())
                .unwrap_or_else(|e| panic!("{} should compile for schema manifest reporting: {}", example, e.message));
            let manifest = &result.metadata.molecule_schema_manifest;
            let schema_type_count = result.metadata.types.iter().filter(|ty| ty.molecule_schema.is_some()).count();
            assert_eq!(manifest.schema, "cellscript-molecule-schema-manifest-v1");
            assert_eq!(manifest.abi, "molecule");
            assert_eq!(manifest.target_profile, "ckb");
            assert_eq!(manifest.type_count, schema_type_count, "{} manifest type count should match metadata types", example);
            assert_eq!(manifest.entries.len(), schema_type_count, "{} manifest entry count should match metadata types", example);
            assert!(manifest.type_count > 0, "{} should expose at least one Molecule schema entry", example);
            assert_eq!(manifest.fixed_type_count + manifest.dynamic_type_count, manifest.type_count);
            assert_eq!(
                manifest.entries.iter().map(|entry| entry.type_name.as_str()).collect::<Vec<_>>(),
                {
                    let mut names = manifest.entries.iter().map(|entry| entry.type_name.as_str()).collect::<Vec<_>>();
                    names.sort_unstable();
                    names
                },
                "{} schema manifest entries must be sorted for release diffs",
                example
            );
            assert_eq!(manifest.manifest_hash.len(), 64, "{} manifest hash should be canonical hex", example);
            for entry in &manifest.entries {
                let ty = result
                    .metadata
                    .types
                    .iter()
                    .find(|ty| ty.name == entry.type_name)
                    .unwrap_or_else(|| panic!("{} manifest entry {} should match a metadata type", example, entry.type_name));
                let schema = ty.molecule_schema.as_ref().expect("manifest entries only point at schema-backed types");
                assert_eq!(entry.schema_hash, schema.schema_hash);
                assert_eq!(
                    entry.field_offsets.len(),
                    ty.fields.len(),
                    "{} {} field manifest should cover every field",
                    example,
                    entry.type_name
                );
            }

            MoleculeSchemaManifestReportRow {
                example,
                type_count: manifest.type_count,
                fixed_type_count: manifest.fixed_type_count,
                dynamic_type_count: manifest.dynamic_type_count,
                manifest_hash: manifest.manifest_hash.clone(),
                entries: manifest.entries.iter().map(|entry| entry.type_name.clone()).collect(),
            }
        })
        .collect::<Vec<_>>();

    let json = serde_json::to_string_pretty(&rows).expect("Molecule schema manifest report should serialize to JSON");
    assert!(json.contains("manifest_hash"));
    if let Ok(path) = std::env::var("CELLSCRIPT_MOLECULE_SCHEMA_MANIFEST_REPORT") {
        std::fs::write(&path, json).unwrap_or_else(|e| panic!("failed to write Molecule schema manifest report to {}: {}", path, e));
    }
}

#[test]
fn vesting_read_ref_params_are_scheduler_visible() {
    let result = compile_file(example_path("vesting.cell"), CompileOptions::default()).expect("vesting example should compile");
    let grant_vesting = result.metadata.actions.iter().find(|action| action.name == "grant_vesting").expect("grant_vesting metadata");

    assert!(
        grant_vesting.read_refs.iter().any(|pattern| pattern.binding == "config"),
        "read_ref parameter was not recorded in read_refs: {:?}",
        grant_vesting.read_refs
    );
    assert!(
        grant_vesting
            .ckb_runtime_accesses
            .iter()
            .any(|access| access.operation == "read_ref" && access.source == "CellDep" && access.binding == "config"),
        "read_ref parameter was not exposed as a CellDep access: {:?}",
        grant_vesting.ckb_runtime_accesses
    );
    assert!(
        grant_vesting.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "read-ref:config#0"
                && requirement.component == "read-ref-cell-dep-data"
                && requirement.status == "checked-runtime"
                && requirement.source == "CellDep"
                && requirement.binding == "config"
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }),
        "read_ref parameter was not exposed as checked CellDep data requirement: {:?}",
        grant_vesting.transaction_runtime_input_requirements
    );
    assert!(grant_vesting.ckb_runtime_features.contains(&"read-cell-dep".to_string()));
    assert!(!grant_vesting.touches_shared.is_empty(), "shared read_ref should be scheduler-visible");
}

#[test]
fn vesting_phase2_remaining_obligations_are_explicit() {
    let result = compile_file(example_path("vesting.cell"), CompileOptions::default()).expect("vesting example should compile");

    let create_vesting_config =
        result.metadata.actions.iter().find(|action| action.name == "create_vesting_config").expect("create_vesting_config metadata");
    assert!(
        create_vesting_config.fail_closed_runtime_features.is_empty(),
        "create_vesting_config should now have complete fixed-byte parameter output and lock verification: {:?}",
        create_vesting_config.fail_closed_runtime_features
    );
    assert!(create_vesting_config.params[0].fixed_byte_pointer_abi);
    assert!(create_vesting_config.params[0].fixed_byte_length_abi);
    assert_eq!(create_vesting_config.params[0].fixed_byte_len, Some(32));
    assert!(
        result.metadata.types.iter().any(|ty| ty.name == "Token" && ty.fields.iter().any(|field| field.name == "symbol")),
        "imported Token layout should be present for verifier output checks"
    );

    for action in &result.metadata.actions {
        assert!(
            !action.fail_closed_runtime_features.contains(&"output-lock-verification-incomplete".to_string()),
            "{} lock verification should now be covered by constants, schema-backed aliases, or fixed-byte parameters",
            action.name
        );
    }

    let grant_vesting = result.metadata.actions.iter().find(|action| action.name == "grant_vesting").expect("grant_vesting metadata");
    assert!(
        !grant_vesting.fail_closed_runtime_features.contains(&"output-verification-incomplete".to_string()),
        "grant_vesting create output should now be covered by imported Token layout, timepoint prelude, and fixed-byte parameters"
    );
    assert!(
        !grant_vesting.fail_closed_runtime_features.contains(&"fixed-byte-comparison".to_string()),
        "grant_vesting fixed-byte equality should now be lowered when both sides are schema-backed"
    );
    assert!(
        grant_vesting.fail_closed_runtime_features.is_empty(),
        "grant_vesting should no longer carry Phase 2 fail-closed verifier debt: {:?}",
        grant_vesting.fail_closed_runtime_features
    );

    let claim_vested = result.metadata.actions.iter().find(|action| action.name == "claim_vested").expect("claim_vested metadata");
    assert!(
        !claim_vested.fail_closed_runtime_features.contains(&"output-verification-incomplete".to_string()),
        "claim_vested source-order create verification should cover computed scalar fields and schema-backed fixed bytes"
    );
    assert!(
        !claim_vested.fail_closed_runtime_features.contains(&"field-access".to_string()),
        "claim_vested field preservation should not require generic field-access fail-closed paths"
    );
    assert!(
        claim_vested.fail_closed_runtime_features.is_empty(),
        "claim_vested should no longer carry fail-closed verifier debt: {:?}",
        claim_vested.fail_closed_runtime_features
    );
    assert_create(claim_vested, "Token", "vesting partial claim");
    assert_create(claim_vested, "VestingGrant", "vesting partial claim");
    let vesting_grant = result.metadata.types.iter().find(|ty| ty.name == "VestingGrant").expect("VestingGrant metadata");
    assert!(
        vesting_grant.flow_transitions.iter().any(|transition| transition.from == "Active" && transition.to == "Active"),
        "repeatable partial claims must declare the runtime-checked Active -> Active transition"
    );
    assert!(
        claim_vested.verifier_obligations.iter().any(|obligation| {
            obligation.category == "state-transition"
                && obligation.feature == "VestingGrant.state"
                && obligation.status == "checked-runtime"
        }),
        "claim_vested should expose the runtime-checked Active -> Active transition"
    );
    assert!(
        claim_vested.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "consume-input:VestingGrant:grant"
                && requirement.status == "checked-runtime"
                && requirement.component == "consume-input-data"
                && requirement.source == "Input"
                && requirement.binding == "grant"
                && requirement.field.as_deref() == Some("data")
                && requirement.abi == "consume-load-cell-input"
        }),
        "claim_vested should expose structured consume-input runtime requirements: {:?}",
        claim_vested.transaction_runtime_input_requirements
    );

    let claim_fully_vested =
        result.metadata.actions.iter().find(|action| action.name == "claim_fully_vested").expect("claim_fully_vested metadata");
    assert!(
        claim_fully_vested.fail_closed_runtime_features.is_empty(),
        "claim_fully_vested should not carry fail-closed verifier debt: {:?}",
        claim_fully_vested.fail_closed_runtime_features
    );
    assert_create(claim_fully_vested, "Token", "vesting terminal claim");
    assert_create(claim_fully_vested, "VestingGrant", "vesting terminal claim");
    assert!(
        claim_fully_vested.verifier_obligations.iter().any(|obligation| {
            obligation.category == "state-transition"
                && obligation.feature == "VestingGrant.state"
                && obligation.status == "checked-runtime"
        }),
        "claim_fully_vested should expose the runtime-checked Active -> FullyClaimed transition"
    );
    assert!(
        claim_vested.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "create-output:Token:tokens"
                && requirement.status == "checked-runtime"
                && requirement.component == "create-output-lock"
                && requirement.source == "Output"
                && requirement.field.as_deref() == Some("lock_hash")
                && requirement.abi == "create-output-lock-hash-32"
                && requirement.byte_len == Some(32)
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }),
        "claim_vested should expose structured create-output lock-hash requirements: {:?}",
        claim_vested.transaction_runtime_input_requirements
    );
    assert!(
        claim_vested.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "create-output:VestingGrant:updated_grant"
                && requirement.status == "checked-runtime"
                && requirement.component == "create-output-lock"
                && requirement.source == "Output"
                && requirement.field.as_deref() == Some("lock_hash")
                && requirement.abi == "create-output-lock-hash-32"
                && requirement.byte_len == Some(32)
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }),
        "claim_vested should expose structured create-output VestingGrant lock-hash requirements: {:?}",
        claim_vested.transaction_runtime_input_requirements
    );

    let revoke_grant = result.metadata.actions.iter().find(|action| action.name == "revoke_grant").expect("revoke_grant metadata");
    assert!(
        revoke_grant.fail_closed_runtime_features.is_empty(),
        "revoke_grant output fields and locks should now be verifier-coverable: {:?}",
        revoke_grant.fail_closed_runtime_features
    );
}

#[test]
fn token_mint_authority_input_output_binding_is_explicit() {
    let result = compile_file(example_path("token.cell"), CompileOptions::default()).expect("token example should compile");
    let asm = String::from_utf8(result.artifact_bytes.clone()).expect("token asm should be utf8");
    let mint =
        result.metadata.actions.iter().find(|action| action.name == "mint_with_authority").expect("mint_with_authority metadata");

    assert_eq!(mint.effect_class, "Mutating");
    assert_input_output_binding(mint, "MintAuthority", "auth_before", "auth_after", "token mint");
    assert!(
        mint.create_set.iter().any(|pattern| pattern.ty == "Token" && pattern.operation == "output" && pattern.binding == "token"),
        "token mint should expose a named Token output binding: {:?}",
        mint.create_set
    );
    assert!(
        mint.fail_closed_runtime_features.is_empty(),
        "mint authority input/output binding should be verifier-coverable, not a fail-closed lowering path: {:?}",
        mint.fail_closed_runtime_features
    );
    assert!(mint.ckb_runtime_accesses.iter().any(|access| {
        access.operation == "input" && access.source == "Input" && access.index == 0 && access.binding == "auth_before"
    }));
    assert!(mint.ckb_runtime_accesses.iter().any(|access| {
        access.operation == "output" && access.source == "Output" && access.index == 0 && access.binding == "auth_after"
    }));
    assert!(
        asm.contains("# cellscript abi: LOAD_CELL_DATA reason=input source=Input index=0")
            && asm.contains("# cellscript abi: LOAD_CELL_DATA reason=output_param source=Output index=0")
            && asm.contains("# cellscript abi: verify output field MintAuthority.minted offset=16 size=8"),
        "mint should bind authority input/output and verify minted through explicit require checks:\n{}",
        asm
    );
}

#[test]
fn nft_core_actions_expose_action_specific_builder_metadata() {
    let result = compile_file(example_path("nft.cell"), CompileOptions::default()).expect("nft example should compile");
    let ckb_result = compile_file(
        example_path("nft.cell"),
        CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() },
    )
    .expect("nft CKB profile should compile");
    let asm = String::from_utf8(result.artifact_bytes.clone()).expect("nft asm should be utf8");

    let create_collection = action(&result.metadata, "create_collection");
    assert_eq!(create_collection.effect_class, "Creating");
    assert!(create_collection.parallelizable);
    assert!(create_collection.fail_closed_runtime_features.is_empty(), "nft create_collection should not carry fail-closed debt");
    assert_create(create_collection, "Collection", "nft create_collection");
    assert_runtime_requirement(
        create_collection,
        "create-output:Collection:collection",
        "checked-runtime",
        "create-output-fields",
        "nft create_collection",
    );
    assert_runtime_requirement(
        create_collection,
        "create-output:Collection:collection",
        "checked-runtime",
        "create-output-lock",
        "nft create_collection",
    );

    let mint = action(&result.metadata, "mint");
    assert_eq!(mint.effect_class, "Mutating");
    assert!(mint.parallelizable);
    assert!(mint.fail_closed_runtime_features.is_empty(), "nft mint should not carry fail-closed debt");
    assert_input_output_binding(mint, "Collection", "collection_before", "collection_after", "nft mint");
    assert_create(mint, "NFT", "nft mint");
    assert!(
        asm.contains("# cellscript abi: LOAD_CELL_DATA reason=input source=Input index=0")
            && asm.contains("# cellscript abi: LOAD_CELL_DATA reason=output_param source=Output index=0"),
        "nft mint should bind Collection input/output deterministically:\n{}",
        asm
    );
    assert!(
        asm.contains("# cellscript abi: schema field Collection.total_supply"),
        "nft mint should verify Collection total_supply through explicit output requirements:\n{}",
        asm
    );

    let transfer = action(&result.metadata, "transfer");
    assert_eq!(transfer.effect_class, "Mutating");
    assert!(transfer.fail_closed_runtime_features.is_empty(), "nft transfer should not carry fail-closed debt");
    assert_input_output_binding(transfer, "NFT", "nft_before", "nft_after", "nft transfer");
    assert!(
        !transfer
            .transaction_runtime_input_requirements
            .iter()
            .any(|requirement| { requirement.feature == "mutable-cell:NFT" && requirement.status == "runtime-required" }),
        "nft transfer should have no remaining mutable-cell runtime-required debt: {:?}",
        transfer.transaction_runtime_input_requirements
    );

    let burn = action(&result.metadata, "burn");
    assert_eq!(burn.effect_class, "Destroying");
    assert!(burn.fail_closed_runtime_features.is_empty(), "nft burn should not carry fail-closed debt");
    assert_destroy(burn, "nft", "nft burn");
    assert_runtime_requirement(burn, "destroy-input:NFT:nft", "checked-runtime", "destroy-input-data", "nft burn");
    assert_runtime_requirement(burn, "destroy-output-scan:NFT", "checked-runtime", "destroy-output-absence", "nft burn");

    for settlement in ["buy_from_listing", "accept_offer"] {
        let settlement = action(&result.metadata, settlement);
        assert_eq!(
            settlement
                .consume_set
                .iter()
                .filter(|pattern| matches!(pattern.binding.as_str(), "royalty_payment" | "seller_payment"))
                .count(),
            2
        );
        assert_eq!(settlement.create_set.iter().filter(|pattern| pattern.ty == "Token").count(), 2);
        assert!(
            settlement.fail_closed_runtime_features.is_empty(),
            "{} should keep typed Token settlement verifier-covered: {:?}",
            settlement.name,
            settlement.fail_closed_runtime_features
        );
        let ckb_settlement = action(&ckb_result.metadata, settlement.name.as_str());
        assert!(
            ckb_settlement.verifier_obligations.iter().any(|obligation| {
                obligation.feature == "resource-conservation:Token"
                    && obligation.status == "checked-runtime"
                    && obligation.detail.contains("preserved into 2 paired Outputs")
            }),
            "{} should classify the two payment/payout pairs as checked conservation: {:?}",
            settlement.name,
            ckb_settlement.verifier_obligations
        );
    }
}

#[test]
fn timelock_core_actions_expose_time_and_release_metadata() {
    let result = compile_file(example_path("timelock.cell"), CompileOptions::default()).expect("timelock example should compile");
    let asm = String::from_utf8(result.artifact_bytes.clone()).expect("timelock asm should be utf8");

    let create_absolute_lock = action(&result.metadata, "create_absolute_lock");
    assert_eq!(create_absolute_lock.effect_class, "Creating");
    assert_create(create_absolute_lock, "TimeLock", "timelock create_absolute_lock");
    assert_runtime_requirement(
        create_absolute_lock,
        "create-output:TimeLock:created_lock",
        "checked-runtime",
        "create-output-fields",
        "timelock create_absolute_lock",
    );
    let create_relative_lock = action(&result.metadata, "create_relative_lock");
    assert_create(create_relative_lock, "TimeLock", "timelock create_relative_lock");
    assert_runtime_requirement(
        create_relative_lock,
        "create-output:TimeLock:created_lock",
        "checked-runtime",
        "create-output-fields",
        "timelock create_relative_lock",
    );

    let request_release = action(&result.metadata, "request_release");
    assert_create(request_release, "ReleaseRequest", "timelock request_release");
    assert_runtime_requirement(
        request_release,
        "create-output:ReleaseRequest:request",
        "checked-runtime",
        "create-output-fields",
        "timelock request_release",
    );

    let execute_release = action(&result.metadata, "execute_release");
    assert_eq!(execute_release.effect_class, "Mutating");
    assert_destroy(execute_release, "time_lock", "timelock execute_release");
    assert_destroy(execute_release, "locked_asset", "timelock execute_release");
    assert_destroy(execute_release, "request", "timelock execute_release");
    assert_create(execute_release, "ReleaseRecord", "timelock execute_release");
    assert_create(execute_release, "Token", "timelock execute_release");
    assert_runtime_requirement(
        execute_release,
        "destroy-input:TimeLock:time_lock",
        "checked-runtime",
        "destroy-input-data",
        "timelock execute_release",
    );
    assert_runtime_requirement(
        execute_release,
        "destroy-input:LockedAsset:locked_asset",
        "checked-runtime",
        "destroy-input-data",
        "timelock execute_release",
    );
    assert_runtime_requirement(
        execute_release,
        "destroy-input:ReleaseRequest:request",
        "checked-runtime",
        "destroy-input-data",
        "timelock execute_release",
    );
    assert_runtime_requirement(
        execute_release,
        "create-output:ReleaseRecord:record",
        "checked-runtime",
        "create-output-fields",
        "timelock execute_release",
    );
    let execute_emergency_release = action(&result.metadata, "execute_emergency_release");
    assert_create(execute_emergency_release, "ReleaseRecord", "timelock execute_emergency_release");
    assert_create(execute_emergency_release, "Token", "timelock execute_emergency_release");
    assert_runtime_requirement(
        execute_emergency_release,
        "create-output:ReleaseRecord:record",
        "checked-runtime",
        "create-output-fields",
        "timelock execute_emergency_release",
    );

    let extend_lock = action(&result.metadata, "extend_lock");
    assert!(extend_lock.fail_closed_runtime_features.is_empty(), "extend_lock should not carry fail-closed debt");
    assert_input_output_binding(extend_lock, "TimeLock", "time_lock_before", "time_lock_after", "timelock extend_lock");
    assert!(
        asm.contains("# cellscript abi: verify output field TimeLock.unlock_height"),
        "timelock extend_lock should verify unlock_height through explicit output requirements:\n{}",
        asm
    );
    assert!(
        !asm.contains("call can_unlock schema param time_lock has no tracked ABI length")
            && !asm.contains("call hash_lock schema param time_lock has no tracked ABI length"),
        "timelock helper calls should preserve schema pointer length through ref/deref aliases:\n{}",
        asm
    );

    let lock_id_commitment =
        result.metadata.locks.iter().find(|lock| lock.name == "lock_id_commitment").expect("timelock lock_id_commitment metadata");
    assert!(
        lock_id_commitment.ckb_runtime_accesses.iter().any(|access| access.operation == "hash-blake2b"),
        "timelock lock_id_commitment should cover real CKB Blake2b runtime access: {:?}",
        lock_id_commitment.ckb_runtime_accesses
    );
}

#[test]
fn multisig_core_actions_expose_threshold_flow_metadata() {
    let result = compile_file(example_path("multisig.cell"), CompileOptions::default()).expect("multisig example should compile");
    let asm = String::from_utf8(result.artifact_bytes.clone()).expect("multisig asm should be utf8");

    let create_wallet = action(&result.metadata, "create_wallet");
    assert_eq!(create_wallet.effect_class, "Creating");
    assert_create(create_wallet, "MultisigWallet", "multisig create_wallet");
    assert_runtime_requirement(
        create_wallet,
        "create-output:MultisigWallet:wallet",
        "checked-runtime",
        "create-output-fields",
        "multisig create_wallet",
    );
    assert!(
        asm.contains("# cellscript abi: verify output dynamic field MultisigWallet.signers as Molecule bytes"),
        "multisig create_wallet should verify dynamic signer vector output bytes:\n{}",
        asm
    );
    assert!(
        asm.contains("# cellscript abi: verify output Molecule table bytes field MultisigWallet.wallet_id index=0 size=32")
            && asm.contains("# cellscript abi: verify output Molecule table scalar field MultisigWallet.threshold index=2 size=1")
            && asm.contains("# cellscript abi: verify output Molecule table scalar field MultisigWallet.nonce index=3 size=8")
            && asm.contains("# cellscript abi: verify output Molecule table scalar field MultisigWallet.created_at index=4 size=8"),
        "multisig create_wallet should verify fixed fields through Molecule table offsets, not fixed-struct offsets:\n{}",
        asm
    );

    let propose_transfer = action(&result.metadata, "propose_transfer");
    assert_eq!(propose_transfer.effect_class, "Mutating");
    assert_input_output_binding(propose_transfer, "MultisigWallet", "wallet_before", "wallet_after", "multisig propose_transfer");
    assert_create(propose_transfer, "Proposal", "multisig propose_transfer");
    assert!(
        asm.contains("# cellscript abi: LOAD_CELL_DATA reason=input source=Input index=0")
            && asm.contains("# cellscript abi: LOAD_CELL_DATA reason=output_param source=Output index=0"),
        "multisig propose_transfer should bind wallet input/output deterministically:\n{}",
        asm
    );
    assert!(
        asm.contains("# cellscript abi: schema field MultisigWallet.nonce"),
        "multisig propose_transfer should verify wallet nonce through explicit output requirements:\n{}",
        asm
    );
    assert!(
        asm.contains("# cellscript abi: verify output dynamic field Proposal.data as constructed Molecule byte vector len=0")
            && asm.contains("# cellscript abi: verify output dynamic field Proposal.approvals as empty Molecule vector"),
        "multisig propose_transfer should verify empty Molecule vector output fields:\n{}",
        asm
    );
    assert!(
        asm.contains("# cellscript abi: verify output Molecule table scalar field Proposal.proposal_id index=1 size=8")
            && asm.contains("# cellscript abi: preserve output table scalar before expected expression"),
        "multisig propose_transfer should preserve created Proposal scalar fields across expected expression evaluation:\n{}",
        asm
    );

    let record_approval = action(&result.metadata, "record_approval");
    assert_eq!(record_approval.effect_class, "Mutating");
    assert_create(record_approval, "ApprovalConfirmation", "multisig record_approval");
    assert_no_runtime_requirement(record_approval, "mutable-cell:Proposal", "mutate-field-equality", "multisig record_approval");
    assert_no_runtime_requirement(record_approval, "mutable-cell:Proposal", "mutate-field-transition", "multisig record_approval");
    assert_input_output_binding(record_approval, "Proposal", "proposal_before", "proposal_after", "multisig record_approval");
    assert!(
        record_approval.consume_set.iter().any(|pattern| pattern.operation == "input" && pattern.binding == "proposal_before")
            && record_approval.create_set.iter().any(|pattern| pattern.operation == "output" && pattern.binding == "proposal_after"),
        "multisig record_approval should expose Proposal input/output bindings: {:?} {:?}",
        record_approval.consume_set,
        record_approval.create_set
    );

    let propose_add_signer = action(&result.metadata, "propose_add_signer");
    assert_eq!(propose_add_signer.effect_class, "Mutating");
    assert_input_output_binding(propose_add_signer, "MultisigWallet", "wallet_before", "wallet_after", "multisig propose_add_signer");
    assert_create(propose_add_signer, "Proposal", "multisig propose_add_signer");
    assert!(
        !propose_add_signer.fail_closed_runtime_features.contains(&"output-verification-incomplete".to_string()),
        "multisig propose_add_signer should verify constructed Proposal.data bytes without fail-closed debt: {:?}",
        propose_add_signer.fail_closed_runtime_features
    );
    assert!(
        asm.contains("# cellscript abi: verify output dynamic field Proposal.data as constructed Molecule byte vector len=32")
            && asm.contains("# cellscript abi: collection extend is covered by create-output vector verifier"),
        "multisig propose_add_signer should verify Proposal.data as a constructed Molecule byte vector:\n{}",
        asm
    );

    let propose_change_threshold = action(&result.metadata, "propose_change_threshold");
    assert_eq!(propose_change_threshold.effect_class, "Mutating");
    assert_input_output_binding(
        propose_change_threshold,
        "MultisigWallet",
        "wallet_before",
        "wallet_after",
        "multisig propose_change_threshold",
    );
    assert_create(propose_change_threshold, "Proposal", "multisig propose_change_threshold");
    assert!(
        propose_change_threshold.fail_closed_runtime_features.is_empty(),
        "multisig propose_change_threshold should verify scalar byte-vector construction without fail-closed debt: {:?}",
        propose_change_threshold.fail_closed_runtime_features
    );
    assert!(
        asm.contains("# cellscript abi: verify output dynamic field Proposal.data as constructed Molecule byte vector len=1")
            && asm.contains("# cellscript abi: collection push is covered by create-output vector verifier"),
        "multisig propose_change_threshold should verify Proposal.data as a one-byte Molecule vector:\n{}",
        asm
    );

    let execute_proposal = action(&result.metadata, "execute_proposal");
    assert_eq!(execute_proposal.effect_class, "Mutating");
    assert_destroy(execute_proposal, "proposal", "multisig execute_proposal");
    assert_create(execute_proposal, "ExecutionRecord", "multisig execute_proposal");
    assert_runtime_requirement(
        execute_proposal,
        "destroy-input:Proposal:proposal",
        "checked-runtime",
        "destroy-input-data",
        "multisig execute_proposal",
    );
    assert_runtime_requirement(
        execute_proposal,
        "create-output:ExecutionRecord:record",
        "checked-runtime",
        "create-output-fields",
        "multisig execute_proposal",
    );
    assert!(
        asm.contains("# cellscript abi: retain consumed input pointer for post-destroy output verification")
            && asm.contains("# cellscript abi: verify output field ExecutionRecord.success offset=48 size=1")
            && asm.contains("# cellscript abi: preserve output scalar before expected expression"),
        "multisig execute_proposal should retain destroyed Proposal input bytes and compare runtime scalar outputs:\n{}",
        asm
    );

    let cancel_proposal = action(&result.metadata, "cancel_proposal");
    assert_eq!(cancel_proposal.effect_class, "Destroying");
    assert_destroy(cancel_proposal, "proposal", "multisig cancel_proposal");
    assert_runtime_requirement(
        cancel_proposal,
        "destroy-output-scan:Proposal",
        "checked-runtime",
        "destroy-output-absence",
        "multisig cancel_proposal",
    );
}

#[test]
fn amm_pool_input_output_params_are_scheduler_visible() {
    let result = compile_file(example_path("amm_pool.cell"), CompileOptions::default()).expect("amm_pool example should compile");
    let asm = String::from_utf8(result.artifact_bytes.clone()).expect("amm_pool asm should be utf8");

    for (action_name, input_binding, output_binding, extra_created_ty) in [
        ("swap_a_for_b", "pool_before", "pool_after", "Token"),
        ("add_liquidity", "pool_before", "pool_after", "LPReceipt"),
        ("remove_liquidity", "pool_before", "pool_after", "Token"),
    ] {
        let action = result.metadata.actions.iter().find(|action| action.name == action_name).expect("amm action metadata");
        assert_input_output_binding(action, "Pool", input_binding, output_binding, action_name);
        assert_create(action, extra_created_ty, action_name);
        assert!(
            !action.touches_shared.is_empty(),
            "{} updates shared Pool state and must expose the Pool type hash to the scheduler",
            action_name
        );
        assert!(!action.parallelizable, "{} updates shared Pool state and should not default to parallel execution", action_name);
        assert_eq!(action.effect_class, "Mutating", "{} should be classified as mutating shared state", action_name);
        assert!(
            action.fail_closed_runtime_features.is_empty(),
            "{} should keep explicit output requirements verifier-coverable: {:?}",
            action_name,
            action.fail_closed_runtime_features
        );
        assert!(
            action.verifier_obligations.iter().all(|obligation| obligation.status != "runtime-required"),
            "{} should be strict v0.16 clean with no runtime-required Pool or resource blockers: {:?}",
            action_name,
            action.verifier_obligations
        );
        assert!(
            action.verifier_obligations.iter().any(|obligation| {
                obligation.status == "checked-runtime"
                    && (obligation.feature.starts_with("guard-equality:pool_after.")
                        || obligation.feature.starts_with("resource-conservation:Token")
                        || obligation.feature.starts_with(&format!("create-output:{extra_created_ty}:")))
            }),
            "{} should retain checked AMM accounting evidence separately from scheduler binding: {:?}",
            action_name,
            action.verifier_obligations
        );
    }

    assert!(
        asm.contains("# cellscript abi: LOAD_CELL_DATA reason=input source=Input index=0")
            && asm.contains("# cellscript abi: LOAD_CELL_DATA reason=output_param source=Output index=0"),
        "AMM input/output bindings should bind Pool input/output parameters through transaction cells:\n{}",
        asm
    );
    for field in ["token_a_type", "token_b_type", "reserve_a", "reserve_b", "total_lp"] {
        assert!(
            asm.contains(&format!("# cellscript abi: schema field Pool.{field}"))
                || asm.contains(&format!("# cellscript abi: verify output field Pool.{field}"))
                || asm.contains(&format!("# cellscript abi: verify output bytes field Pool.{field}"))
                || asm.contains(&format!("# cellscript abi: expected field Pool.{field}")),
            "AMM input/output bindings should verify Pool {field} through explicit require checks:\n{}",
            asm
        );
    }
    assert!(
        asm.contains("# cellscript abi: verify output bytes field LPReceipt.pool_id offset=0 size=32 against loaded bytes"),
        "LPReceipt.pool_id should be checked against loaded Pool TypeHash bytes:\n{}",
        asm
    );
}

#[test]
fn launch_seed_pool_composition_is_scheduler_visible() {
    let result = compile_file(example_path("launch.cell"), CompileOptions::default()).expect("launch example should compile");
    let asm = String::from_utf8(result.artifact_bytes.clone()).expect("launch asm should be utf8");
    let launch_token = result.metadata.actions.iter().find(|action| action.name == "launch_token").expect("launch_token metadata");

    assert!(
        !asm.contains("\nseed_pool:\n") && asm.contains("\nisqrt:\n"),
        "launch_token should materialise Pool outputs directly while retaining its local pure isqrt helper"
    );
    assert!(!asm.contains("\nadd_liquidity:\n"), "launch_token should not link unrelated AMM actions");
    assert!(!asm.contains("\nremove_liquidity:\n"), "launch_token should not link unrelated AMM actions");

    assert!(
        !launch_token.touches_shared.is_empty(),
        "launch_token creates Pool output, so shared Pool touch metadata must not be lost"
    );
    assert!(!launch_token.parallelizable, "launch_token composes Pool creation and should not default to parallel execution");
    assert_create(launch_token, "MintAuthority", "launch_token");
    assert_create(launch_token, "Pool", "launch_token");
    assert_create(launch_token, "LPReceipt", "launch_token");
    let distribution = launch_token.params.iter().find(|param| param.name == "distribution").expect("distribution param metadata");
    assert!(distribution.fixed_byte_pointer_abi);
    assert!(distribution.fixed_byte_length_abi);
    assert_eq!(distribution.fixed_byte_len, Some(160));
    assert!(
        !launch_token.fail_closed_runtime_features.contains(&"index-access".to_string()),
        "fixed tuple-array distribution indexes should lower through the pointer+length ABI"
    );
    assert!(
        !launch_token.fail_closed_runtime_features.contains(&"output-lock-verification-incomplete".to_string()),
        "recipient locks loaded from fixed tuple-array distribution should be verifier-coverable"
    );
    assert!(
        launch_token.fail_closed_runtime_features.is_empty(),
        "launch_token named outputs and fixed tuple-array distribution should be verifier-coverable: {:?}",
        launch_token.fail_closed_runtime_features
    );
    assert!(
        launch_token.verifier_obligations.iter().all(|obligation| obligation.status != "runtime-required"),
        "launch_token should be strict v0.16 clean as an original scoped action: {:?}",
        launch_token.verifier_obligations
    );
    assert!(
        launch_token.verifier_obligations.iter().any(|obligation| {
            obligation.feature == "resource-conservation:Token"
                && obligation.status == "checked-runtime"
                && obligation.detail.contains("launch verifier checks")
        }),
        "launch_token should classify launch issuance and paired-token Pool accounting as checked: {:?}",
        launch_token.verifier_obligations
    );
    assert!(
        asm.contains("# cellscript abi: verify output bytes field LPReceipt.pool_id offset=0 size=32 against loaded bytes"),
        "launch_token should bind LPReceipt.pool_id to the named Pool output TypeHash:\n{}",
        asm
    );
    assert!(
        !asm.contains("field access fail-closed runtime path"),
        "launch example should not fall back to generic field-access fail-closed lowering:\n{}",
        asm
    );

    let bootstrap_token =
        result.metadata.actions.iter().find(|action| action.name == "bootstrap_token").expect("bootstrap_token metadata");
    assert!(
        bootstrap_token.touches_shared.is_empty(),
        "bootstrap_token does not compose Pool creation and should not inherit launch_token's shared touch"
    );
    let recipients = bootstrap_token.params.iter().find(|param| param.name == "recipients").expect("recipients param metadata");
    assert!(recipients.fixed_byte_pointer_abi);
    assert!(recipients.fixed_byte_length_abi);
    assert_eq!(recipients.fixed_byte_len, Some(80));
    assert!(
        bootstrap_token.fail_closed_runtime_features.is_empty(),
        "bootstrap_token fixed tuple-array distribution and recipient locks should be fully verifier-coverable: {:?}",
        bootstrap_token.fail_closed_runtime_features
    );
    assert!(
        !asm.contains("schema field byte source is not addressable"),
        "bootstrap_token recipient lock verification must compare fixed tuple-array address fields without fail-closed traps:\n{}",
        asm
    );
    assert!(
        !asm.contains("expression verifier temp stack is exhausted"),
        "bootstrap_token remaining-output verifier must have enough expression temp slots for the fixed recipient sum:\n{}",
        asm
    );
    assert!(
        bootstrap_token.verifier_obligations.iter().all(|obligation| obligation.category != "pool-pattern"),
        "bootstrap_token does not compose a Pool and should not inherit pool-pattern obligations: {:?}",
        bootstrap_token.verifier_obligations
    );
}

#[test]
fn canonical_examples_compile_under_primitive_strict_015() {
    let strict_options = CompileOptions { primitive_compat: Some("0.15".to_string()), ..CompileOptions::default() };
    for example in BUNDLED_EXAMPLES {
        let path = example_path(example);
        compile_file(&path, strict_options.clone())
            .unwrap_or_else(|err| panic!("canonical example {example} should compile under --primitive-strict=0.15: {}", err.message));
    }
}

fn assert_proof_plan_invariant_record(
    proof_plan: &[ProofPlanMetadata],
    category: &str,
    trigger: &str,
    scope: &str,
    coverage_status: &str,
    status: &str,
    on_chain_checked: bool,
) -> ProofPlanMetadata {
    let record = proof_plan
        .iter()
        .find(|plan| plan.category == category)
        .unwrap_or_else(|| panic!("no ProofPlan record with category '{}' found: {:?}", category, proof_plan));
    assert_eq!(record.trigger, trigger, "wrong trigger for {category}: expected {trigger}, got {}", record.trigger);
    assert_eq!(record.scope, scope, "wrong scope for {category}: expected {scope}, got {}", record.scope);
    assert_eq!(
        record.codegen_coverage_status, coverage_status,
        "wrong coverage for {category}: expected {coverage_status}, got {}",
        record.codegen_coverage_status
    );
    assert_eq!(record.status, status, "wrong status for {category}: expected {status}, got {}", record.status);
    assert_eq!(record.on_chain_checked, on_chain_checked, "wrong on_chain_checked for {category}");
    record.clone()
}

#[test]
fn v0_15_scoped_invariant_example_compiles_and_produces_proof_plan() {
    let result = compile_file(
        language_example_path("verification/scoped_invariant.cell"),
        CompileOptions { primitive_compat: Some("0.15".to_string()), ..CompileOptions::default() },
    )
    .expect("v0_15_scoped_invariant should compile under --primitive-strict=0.15");

    let proof_plan = &result.metadata.runtime.proof_plan;
    assert!(!proof_plan.is_empty(), "scoped invariant example must emit ProofPlan records");

    // The 0.21 xUDT amount sum pattern is helper-covered; the remaining
    // aggregate primitives in this example stay explicit metadata-only gaps.
    let declared = assert_proof_plan_invariant_record(
        proof_plan,
        "declared-invariant",
        "type_group",
        "group",
        "covered",
        "checked-runtime",
        true,
    );
    assert_eq!(declared.name, "token_amount_conservation");

    // All 5 aggregate invariant primitives must appear in ProofPlan
    let aggregate_names: Vec<&str> =
        proof_plan.iter().filter(|plan| plan.category == "aggregate-invariant").map(|plan| plan.feature.as_str()).collect();
    assert!(aggregate_names.iter().any(|name| name.starts_with("assert_sum:")), "missing assert_sum aggregate: {:?}", aggregate_names);
    assert!(
        aggregate_names.iter().any(|name| name.starts_with("assert_conserved:")),
        "missing assert_conserved aggregate: {:?}",
        aggregate_names
    );
    assert!(
        aggregate_names.iter().any(|name| name.starts_with("assert_delta:")),
        "missing assert_delta aggregate: {:?}",
        aggregate_names
    );
    assert!(
        aggregate_names.iter().any(|name| name.starts_with("assert_distinct:")),
        "missing assert_distinct aggregate: {:?}",
        aggregate_names
    );
    assert!(
        aggregate_names.iter().any(|name| name.starts_with("assert_singleton:")),
        "missing assert_singleton aggregate: {:?}",
        aggregate_names
    );

    let helper_checked_aggregate = proof_plan
        .iter()
        .find(|plan| plan.category == "aggregate-invariant" && plan.feature.starts_with("assert_sum:"))
        .expect("missing helper-covered assert_sum aggregate");
    assert_eq!(helper_checked_aggregate.codegen_coverage_status, "covered");
    assert_eq!(helper_checked_aggregate.status, "checked-runtime");
    assert!(helper_checked_aggregate.on_chain_checked);

    // The other aggregate primitives must keep explicit runtime-required gaps.
    for aggregate in proof_plan.iter().filter(|plan| plan.category == "aggregate-invariant") {
        if aggregate.feature.starts_with("assert_sum:") {
            continue;
        }
        assert!(
            matches!(aggregate.codegen_coverage_status.as_str(), "gap:metadata-only" | "gap:runtime-helper-required"),
            "aggregate must remain an explicit gap: {:?}",
            aggregate
        );
        assert_eq!(aggregate.status, "runtime-required", "aggregate must be runtime-required: {:?}", aggregate);
        assert!(!aggregate.on_chain_checked, "aggregate must not be on_chain_checked: {:?}", aggregate);
    }

    // lock_group + transaction must produce coverage diagnostics
    let lock_tx_invariant = proof_plan.iter().find(|plan| plan.trigger == "lock_group" && plan.scope == "transaction");
    if let Some(record) = lock_tx_invariant {
        assert!(
            record
                .diagnostics
                .iter()
                .any(|diag| diag.severity == "warning" && diag.message.contains("do not imply type-group conservation")),
            "lock_group + transaction must warn about coverage: {:?}",
            record.diagnostics
        );
    }
}

#[test]
fn v0_15_identity_lifecycle_example_compiles_and_produces_proof_plan() {
    let result = compile_file(
        language_example_path("ownership/identity_lifecycle.cell"),
        CompileOptions { primitive_compat: Some("0.15".to_string()), ..CompileOptions::default() },
    )
    .expect("v0_15_identity_lifecycle should compile under --primitive-strict=0.15");

    let proof_plan = &result.metadata.runtime.proof_plan;
    assert!(!proof_plan.is_empty(), "identity lifecycle example must emit ProofPlan records");

    // create_unique and replace_unique must appear as transaction-invariant obligations
    let create_unique_records = proof_plan.iter().filter(|plan| plan.feature.starts_with("create-unique-output:")).collect::<Vec<_>>();
    assert!(!create_unique_records.is_empty(), "missing create_unique ProofPlan records");

    let replace_unique_records =
        proof_plan.iter().filter(|plan| plan.feature.starts_with("replace-unique-output:")).collect::<Vec<_>>();
    assert!(!replace_unique_records.is_empty(), "missing replace_unique ProofPlan records");

    // Identity lifecycle policy must appear in ProofPlan records
    let identity_records = proof_plan.iter().filter(|plan| plan.identity_lifecycle_policy != "none").collect::<Vec<_>>();
    assert!(!identity_records.is_empty(), "missing identity lifecycle policy records");

    // Destruction policy records must appear
    let destroy_records = proof_plan
        .iter()
        .filter(|plan| {
            plan.feature.starts_with("destroy-output-scan:")
                || plan.feature.starts_with("destroy-unique:")
                || plan.feature.starts_with("destroy-instance:")
                || plan.feature.starts_with("burn-amount:")
        })
        .collect::<Vec<_>>();
    assert!(!destroy_records.is_empty(), "missing destruction policy ProofPlan records");
}

#[test]
fn token_cell_has_no_metadata_only_declared_invariant_debt() {
    let result = compile_file(example_path("token.cell"), CompileOptions::default()).expect("token.cell should compile");

    let proof_plan = &result.metadata.runtime.proof_plan;
    assert!(!proof_plan.is_empty(), "token.cell must emit ProofPlan records");

    assert!(
        proof_plan.iter().all(|plan| plan.category != "declared-invariant" && plan.codegen_coverage_status != "gap:metadata-only"),
        "token.cell must not carry strict-blocking metadata-only declared invariant debt: {proof_plan:?}"
    );

    // Action obligations must still be present
    let action_obligations =
        proof_plan.iter().filter(|plan| plan.category != "declared-invariant" && plan.category != "aggregate-invariant").count();
    assert!(action_obligations > 0, "token.cell action obligations must still appear in ProofPlan");
}
