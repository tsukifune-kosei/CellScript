//! Production CKB acceptance-evidence validation.
//!
//! This is the Rust implementation of the release-critical validator that
//! historically lived in the script-based release harness.
//! Keep the evidence schema and all fail-closed checks stable: old reports are
//! part of the repository's audit trail.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::crypto::{ckb_blake2b256, hex0x, sha256_hex};

pub(crate) const SOURCE_PROVENANCE_SCHEMA: &str = "cellscript-ckb-acceptance-source-provenance-v0.22";
pub(crate) const BUILD_REPORT_SCHEMA: &str = "cellscript-ckb-build-report-v0.20";
const EXPECTED_STATUS: &str = "passed";
const EXPECTED_MODE: &str = "production";
const EXPECTED_ACTION_COUNT: u64 = 43;

pub(crate) const SOURCE_PROVENANCE_PATHS: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    ".github/workflows/release.yml",
    "src",
    "examples",
    "scripts/cellscript_gate.sh",
    "scripts/cellscript_ckb_release_gate.sh",
    "scripts/ckb_acceptance_pin.json",
    "scripts/ckb_cellscript_acceptance.sh",
    "crates/cellscript-tools/fixtures/ckb_acceptance/transactions-v0.23.json",
    "crates/cellscript-tools/src/ckb_acceptance.rs",
    "crates/cellscript-tools/src/ckb_acceptance_live.rs",
    "crates/cellscript-tools/src/production_evidence.rs",
];

pub(crate) const EXPECTED_EXAMPLES: &[&str] =
    &["amm_pool.cell", "launch.cell", "multisig.cell", "nft.cell", "timelock.cell", "token.cell", "vesting.cell"];

pub(crate) const EXPECTED_NON_PRODUCTION_EXAMPLES: &[&str] = &["registry.cell", "atomic_swap.cell", "multi_phase_dao.cell"];

pub(crate) const EXPECTED_LANGUAGE_EXAMPLES: &[&str] = &[
    "core/canonical_style.cell",
    "core/stdlib.cell",
    "ckb/capacity_time.cell",
    "ckb/type_id_create.cell",
    "ckb/delegate_verify.cell",
    "ckb/blake2b_hash.cell",
    "ckb/multi_step_pipeline.cell",
    "ckb/witness_source.cell",
    "ownership/identity_lifecycle.cell",
    "ownership/semantic_foundation.cell",
    "ownership/borrow.cell",
    "verification/scoped_invariant.cell",
    "verification/transaction_views.cell",
    "collections/order_book.cell",
    "collections/registry.cell",
    "collections/bounded_lifecycle.cell",
    "batches/batch_claim.cell",
    "batches/atomic_order_settlement.cell",
    "batches/cell_merge.cell",
    "batches/bridge_rollup_batch.cell",
];

pub(crate) const EXPECTED_CRITICAL_ELF_ABI_EXAMPLES: &[&str] = &["launch.cell", "token.cell", "amm_pool.cell"];

pub(crate) const EXPECTED_END_TO_END_STATEFUL_SCENARIOS: &[&str] = &[
    "token.mint-with-authority-transfer-mint-with-authority-merge-burn",
    "nft.mint-list-transfer-by-listing",
    "timelock.create-lock-lock-asset-request-release-execute",
    "launch.launch-token-then-mint-with-authority",
    "amm.seed-add-swap-remove",
    "vesting.create-config-grant-revoke",
    "multisig.create-propose-approve-approve-execute",
];

pub(crate) const ACTION_RUNS: &[(&str, &str, &[&str])] = &[
    ("token_action_runs", "token.cell", &["mint_with_authority", "transfer_token", "burn", "merge"]),
    (
        "nft_action_runs",
        "nft.cell",
        &[
            "create_collection",
            "mint",
            "transfer",
            "create_listing",
            "cancel_listing",
            "buy_from_listing",
            "create_offer",
            "accept_offer",
            "burn",
            "batch_mint",
        ],
    ),
    (
        "timelock_action_runs",
        "timelock.cell",
        &[
            "create_absolute_lock",
            "create_relative_lock",
            "lock_asset",
            "request_release",
            "request_emergency_release",
            "approve_emergency_release",
            "extend_lock",
            "execute_release",
            "execute_emergency_release",
            "batch_create_locks",
        ],
    ),
    (
        "multisig_action_runs",
        "multisig.cell",
        &[
            "create_wallet",
            "propose_transfer",
            "record_approval",
            "execute_proposal",
            "cancel_proposal",
            "propose_add_signer",
            "propose_remove_signer",
            "propose_change_threshold",
        ],
    ),
    (
        "vesting_action_runs",
        "vesting.cell",
        &["create_vesting_config", "grant_vesting", "claim_vested", "claim_fully_vested", "revoke_grant"],
    ),
    ("amm_action_runs", "amm_pool.cell", &["seed_pool", "swap_a_for_b", "add_liquidity", "remove_liquidity"]),
    ("launch_action_runs", "launch.cell", &["launch_token", "bootstrap_token"]),
];

pub(crate) const PUBLIC_TIMELOCK_ACTIONS: &[&str] = &[
    "create_absolute_lock",
    "create_relative_lock",
    "lock_asset",
    "request_release",
    "execute_release",
    "request_emergency_release",
    "approve_emergency_release",
    "execute_emergency_release",
    "extend_lock",
    "batch_create_locks",
];

pub(crate) const LOCKS: &[(&str, &[&str])] = &[
    ("multisig.cell", &["is_signer_lock", "can_execute", "can_cancel", "has_enough_approvals", "not_expired"]),
    ("nft.cell", &["nft_ownership", "listing_seller", "offer_buyer", "valid_royalty", "collection_creator"]),
    ("timelock.cell", &["can_unlock_lock", "is_owner", "lock_id_commitment", "asset_matches", "not_expired", "emergency_approved"]),
    ("vesting.cell", &["vesting_admin"]),
];

fn invalid(message: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("invalid CKB CellScript production evidence: {message}")
}

fn require(condition: bool, message: impl std::fmt::Display) -> Result<()> {
    if !condition {
        bail!(invalid(message));
    }
    Ok(())
}

fn object<'a>(value: &'a Value, context: &str) -> Result<&'a Map<String, Value>> {
    value.as_object().ok_or_else(|| invalid(format!("{context} must be an object")))
}

fn array<'a>(value: Option<&'a Value>, context: &str) -> Result<&'a Vec<Value>> {
    value.and_then(Value::as_array).ok_or_else(|| invalid(format!("{context} must be a list")))
}

fn nonempty_string<'a>(value: Option<&'a Value>, context: &str) -> Result<&'a str> {
    let value = value.and_then(Value::as_str).ok_or_else(|| invalid(format!("{context} must be a non-empty string")))?;
    require(!value.is_empty(), format!("{context} must be a non-empty string"))?;
    Ok(value)
}

fn require_field(mapping: &Map<String, Value>, key: &str, expected: Value, context: &str) -> Result<()> {
    let actual = mapping.get(key).unwrap_or(&Value::Null);
    let prefix = if context.is_empty() { String::new() } else { format!("{context}.") };
    require(actual == &expected, format!("{prefix}{key} must be {expected:?}, got {actual:?}"))
}

fn require_empty(mapping: &Map<String, Value>, key: &str, context: &str) -> Result<()> {
    require_field(mapping, key, json!([]), context)
}

fn positive(value: Option<&Value>, context: &str) -> Result<u64> {
    let number = value.and_then(Value::as_u64).filter(|number| *number > 0);
    number.ok_or_else(|| invalid(format!("{context} must be a positive integer, got {:?}", value.unwrap_or(&Value::Null))))
}

fn boolean(value: Option<&Value>, context: &str) -> Result<bool> {
    value
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid(format!("{context} must be a boolean, got {:?}", value.unwrap_or(&Value::Null))))
}

fn hex_hash<'a>(value: Option<&'a Value>, context: &str) -> Result<&'a str> {
    let value = value.and_then(Value::as_str).unwrap_or_default();
    require(
        value.len() == 66 && value.starts_with("0x") && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit()),
        format!("{context} must be a 32-byte 0x-prefixed hex hash, got {value:?}"),
    )?;
    Ok(value)
}

fn load_json(path: &Path) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("missing CKB production evidence: {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes).with_context(|| format!("invalid JSON in {}", path.display()))?;
    require(value.is_object(), format!("{} must contain a JSON object", path.display()))?;
    Ok(value)
}

fn git_stdout(repo_root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo_root)
        .output()
        .with_context(|| format!("failed to query git source provenance in {}", repo_root.display()))?;
    require(
        output.status.success(),
        format!(
            "failed to query git source provenance in {}: {}",
            repo_root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    )?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn file_sha256(path: &Path) -> Result<String> {
    Ok(sha256_hex(&fs::read(path).with_context(|| format!("failed to read {}", path.display()))?))
}

fn expected_action_ids() -> Vec<Value> {
    let mut ids = ACTION_RUNS
        .iter()
        .flat_map(|(_, example, actions)| actions.iter().map(move |action| Value::String(format!("{example}:{action}"))))
        .collect::<Vec<_>>();
    ids.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
    ids
}

fn expected_lock_names() -> Vec<String> {
    LOCKS.iter().flat_map(|(example, locks)| locks.iter().map(move |lock| format!("{example}:{lock}"))).collect()
}

fn expected_lock_scope() -> Value {
    let mut map = Map::new();
    for (example, locks) in LOCKS {
        map.insert((*example).to_owned(), json!(locks));
    }
    Value::Object(map)
}

fn expected_lock_count() -> u64 {
    LOCKS.iter().map(|(_, locks)| locks.len() as u64).sum()
}

fn public_actions(example: &str) -> &'static [&'static str] {
    if example == "timelock.cell" {
        return PUBLIC_TIMELOCK_ACTIONS;
    }
    ACTION_RUNS.iter().find(|(_, candidate, _)| *candidate == example).map(|(_, _, actions)| *actions).unwrap_or(&[])
}

fn validate_elf_entry_abi_gate(report: &Map<String, Value>) -> Result<()> {
    let gate = object(report.get("ckb_elf_entry_abi_gate").unwrap_or(&Value::Null), "ckb_elf_entry_abi_gate")?;
    for (key, expected) in [
        ("schema", json!("cellscript-ckb-elf-entry-abi-gate-v0.22")),
        ("status", json!(EXPECTED_STATUS)),
        ("requires_ckb_vm_stack_pointer_preserved", json!(true)),
        ("requires_entry_trampoline_call_sequence", json!(true)),
        ("requires_rx_only_executable_segment", json!(true)),
        ("requires_no_fake_stack_load_segment", json!(true)),
        ("critical_examples", json!(EXPECTED_CRITICAL_ELF_ABI_EXAMPLES)),
    ] {
        require_field(gate, key, expected, "ckb_elf_entry_abi_gate")?;
    }
    require_empty(gate, "failures", "ckb_elf_entry_abi_gate")?;
    positive(gate.get("audited_artifact_count"), "ckb_elf_entry_abi_gate.audited_artifact_count")?;

    let critical = object(gate.get("critical_example_gate").unwrap_or(&Value::Null), "ckb_elf_entry_abi_gate.critical_example_gate")?;
    for example in EXPECTED_CRITICAL_ELF_ABI_EXAMPLES {
        let context = format!("ckb_elf_entry_abi_gate.critical_example_gate.{example}");
        let row = object(critical.get(*example).unwrap_or(&Value::Null), &context)?;
        require_field(row, "status", json!(EXPECTED_STATUS), &context)?;
        require_field(row, "missing", json!(false), &context)?;
        require_empty(row, "failures", &context)?;
        positive(row.get("artifact_count"), &format!("{context}.artifact_count"))?;
    }

    let rows = array(gate.get("rows"), "ckb_elf_entry_abi_gate.rows")?;
    require(!rows.is_empty(), "ckb_elf_entry_abi_gate.rows must be a non-empty list")?;
    for (index, value) in rows.iter().enumerate() {
        let context = format!("ckb_elf_entry_abi_gate.rows[{index}]");
        let row = object(value, &context)?;
        for (key, expected) in [
            ("status", json!(EXPECTED_STATUS)),
            ("preserves_ckb_vm_stack_pointer", json!(true)),
            ("entry_trampoline_calls_with_ra", json!(true)),
            ("executable_segment_rx_only", json!(true)),
            ("executable_segment_file_size_equals_memory_size", json!(true)),
            ("first_instruction_le_hex", json!("0x00000097")),
            ("trampoline_instructions_le_hex", json!(["0x00000097", "0x014080e7", "0x000008b7", "0x05d88893", "0x00000073"])),
            ("trampoline_bytes_hex", json!("97000000e7804001b70800009388d80573000000")),
            ("exit_syscall_number", json!(93)),
            ("exit_sequence_exact", json!(true)),
        ] {
            require_field(row, key, expected, &context)?;
        }
        nonempty_string(row.get("artifact"), &format!("{context}.artifact"))?;
        require_field(row, "call_target", row.get("expected_call_target").cloned().unwrap_or(Value::Null), &context)?;
    }
    Ok(())
}

fn tracked_source_files(repo_root: &Path) -> Result<Vec<String>> {
    let mut args = vec!["ls-files", "--"];
    args.extend(SOURCE_PROVENANCE_PATHS);
    Ok(git_stdout(repo_root, &args)?
        .lines()
        .filter(|line| !line.is_empty() && repo_root.join(line).is_file())
        .map(str::to_owned)
        .collect())
}

fn tracked_source_sha256(repo_root: &Path, files: &[String]) -> Result<String> {
    let mut digest = Sha256::new();
    for relative in files {
        digest.update(relative.as_bytes());
        digest.update([0]);
        digest.update(file_sha256(&repo_root.join(relative))?.as_bytes());
        digest.update(b"\n");
    }
    Ok(format!("0x{}", hex::encode(digest.finalize())))
}

pub(crate) fn current_source_provenance(repo_root: &Path) -> Result<Map<String, Value>> {
    let files = tracked_source_files(repo_root)?;
    let mut current = Map::new();
    current.insert("repo_commit".into(), json!(git_stdout(repo_root, &["rev-parse", "HEAD"])?));
    current.insert("git_dirty".into(), json!(!git_stdout(repo_root, &["status", "--porcelain", "--untracked-files=all"])?.is_empty()));
    current.insert("tracked_source_paths".into(), json!(SOURCE_PROVENANCE_PATHS));
    current.insert("tracked_source_files".into(), json!(files));
    current.insert("tracked_source_file_count".into(), json!(files.len()));
    current.insert("tracked_source_sha256".into(), json!(tracked_source_sha256(repo_root, &files)?));
    current.insert(
        "acceptance_script_sha256".into(),
        json!(format!("0x{}", file_sha256(&repo_root.join("scripts/ckb_cellscript_acceptance.sh"))?)),
    );
    current.insert(
        "validator_script_sha256".into(),
        json!(format!("0x{}", file_sha256(&repo_root.join("crates/cellscript-tools/src/production_evidence.rs"))?)),
    );
    Ok(current)
}

fn validate_source_provenance(report: &Map<String, Value>, repo_root: &Path) -> Result<()> {
    let provenance = object(report.get("source_provenance").unwrap_or(&Value::Null), "source_provenance")?;
    require_field(provenance, "schema", json!(SOURCE_PROVENANCE_SCHEMA), "source_provenance")?;
    require(
        provenance.get("generated_at_utc").is_some_and(Value::is_string),
        "source_provenance.generated_at_utc must be a timestamp string",
    )?;
    require_field(provenance, "git_dirty", json!(false), "source_provenance")?;
    let current = current_source_provenance(repo_root)?;
    for key in [
        "repo_commit",
        "git_dirty",
        "tracked_source_paths",
        "tracked_source_files",
        "tracked_source_file_count",
        "tracked_source_sha256",
        "acceptance_script_sha256",
        "validator_script_sha256",
    ] {
        require_field(provenance, key, current.get(key).cloned().unwrap_or(Value::Null), "source_provenance")?;
    }
    Ok(())
}

fn recursive_files(root: &Path) -> Result<Vec<PathBuf>> {
    fn visit(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        let mut entries = fs::read_dir(path)?.collect::<std::result::Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                visit(&path, files)?;
            } else if path.is_file() {
                files.push(path);
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    visit(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn validate_public_builder_contracts(report: &Map<String, Value>) -> Result<()> {
    let gate = object(report.get("public_builder_contracts").unwrap_or(&Value::Null), "public_builder_contracts")?;
    for (key, expected) in [
        ("schema", json!("cellscript-public-builder-contract-gate-v0.22")),
        ("status", json!(EXPECTED_STATUS)),
        ("example_count", json!(EXPECTED_EXAMPLES.len())),
        ("action_count", json!(EXPECTED_ACTION_COUNT)),
        ("requires_gen_builder", json!(true)),
        ("requires_action_build", json!(true)),
        ("transaction_origin_claim", json!("acceptance-rust-harness-not-generated-builder")),
    ] {
        require_field(gate, key, expected, "public_builder_contracts")?;
    }
    let contracts = array(gate.get("contracts"), "public_builder_contracts.contracts")?;
    let actual_examples = contracts.iter().filter_map(|row| row.get("example")).cloned().collect::<Vec<_>>();
    require(
        actual_examples == json!(EXPECTED_EXAMPLES).as_array().cloned().unwrap(),
        "public builder examples must match exact release scope",
    )?;
    let mut seen_action_ids = Vec::new();
    for contract_value in contracts {
        let contract = object(contract_value, "public_builder_contracts.contracts[]")?;
        let example = nonempty_string(contract.get("example"), "public_builder_contracts.contracts[].example")?;
        let context = format!("public_builder_contracts.{example}");
        let actions = public_actions(example);
        for (key, expected) in [
            ("status", json!(EXPECTED_STATUS)),
            ("generator_schema", json!("cellscript-generated-builder-summary-v0.20")),
            ("builder_manifest_schema", json!("cellscript-generated-action-builder-v0.23-edition-2026")),
            ("target", json!("typescript")),
            ("target_profile", json!("ckb")),
            ("actions", json!(actions)),
            ("action_count", json!(actions.len())),
            ("runtime_adapter_execution", json!("not-proven-by-this-contract-gate")),
        ] {
            require_field(contract, key, expected, &context)?;
        }
        hex_hash(contract.get("manifest_sha256"), &format!("{context}.manifest_sha256"))?;
        hex_hash(contract.get("generated_tree_sha256"), &format!("{context}.generated_tree_sha256"))?;
        positive(contract.get("generated_file_count"), &format!("{context}.generated_file_count"))?;
        let manifest_path = PathBuf::from(contract.get("manifest_path").and_then(Value::as_str).unwrap_or_default());
        require(manifest_path.is_file(), format!("{context}.manifest_path does not exist: {}", manifest_path.display()))?;
        require_field(contract, "manifest_sha256", json!(format!("0x{}", file_sha256(&manifest_path)?)), &context)?;
        let manifest = load_json(&manifest_path)?;
        let manifest = object(&manifest, &format!("{context}.manifest"))?;
        let manifest_actions = array(manifest.get("actions"), &format!("{context}.manifest.actions"))?;
        let manifest_names =
            manifest_actions.iter().map(|value| value.get("name").cloned().unwrap_or(Value::Null)).collect::<Vec<_>>();
        require(manifest_names == json!(actions).as_array().cloned().unwrap(), format!("{context} manifest action mismatch"))?;

        let generated_files = recursive_files(manifest_path.parent().context("builder manifest has no parent directory")?)?;
        let mut tree_hash = Sha256::new();
        for path in &generated_files {
            let relative = path.strip_prefix(manifest_path.parent().unwrap())?.to_string_lossy().replace('\\', "/");
            tree_hash.update(relative.as_bytes());
            tree_hash.update([0]);
            tree_hash.update(Sha256::digest(fs::read(path)?));
        }
        require_field(contract, "generated_file_count", json!(generated_files.len()), &context)?;
        require_field(contract, "generated_tree_sha256", json!(format!("0x{}", hex::encode(tree_hash.finalize()))), &context)?;

        let plans = array(contract.get("action_plans"), &format!("{context}.action_plans"))?;
        require(plans.len() == actions.len(), format!("{context}.action_plans must cover every action"))?;
        for (plan_value, action) in plans.iter().zip(actions.iter()) {
            let plan = object(plan_value, &format!("{context}.action_plans.{action}"))?;
            let plan_context = format!("{context}.action_plans.{action}");
            let contract_id = format!("{example}:{action}");
            for (key, expected) in [
                ("action", json!(action)),
                ("contract_id", json!(contract_id)),
                ("policy", json!("cellscript-action-builder-plan-v1")),
                ("status", json!(EXPECTED_STATUS)),
            ] {
                require_field(plan, key, expected, &plan_context)?;
            }
            hex_hash(plan.get("plan_sha256"), &format!("{plan_context}.plan_sha256"))?;
            let plan_path = PathBuf::from(plan.get("plan_path").and_then(Value::as_str).unwrap_or_default());
            require(plan_path.is_file(), format!("{plan_context}.plan_path does not exist: {}", plan_path.display()))?;
            require_field(plan, "plan_sha256", json!(format!("0x{}", file_sha256(&plan_path)?)), &plan_context)?;
            let plan_json = load_json(&plan_path)?;
            let plan_json = object(&plan_json, &format!("{plan_context}.file"))?;
            for (key, expected) in [
                ("status", json!("ok")),
                ("policy", json!("cellscript-action-builder-plan-v1")),
                ("action", json!(action)),
                ("target_profile", json!("ckb")),
            ] {
                require_field(plan_json, key, expected, &format!("{plan_context}.file"))?;
            }
            seen_action_ids.push(Value::String(contract_id));
        }
    }
    seen_action_ids.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
    require(seen_action_ids == expected_action_ids(), "public builder action contracts must match the exact production action matrix")
}

fn validate_ckb_runtime_provenance(report: &Map<String, Value>, repo_root: &Path, report_dir: &Path) -> Result<()> {
    let pin_path = repo_root.join("scripts/ckb_acceptance_pin.json");
    let pin_value = load_json(&pin_path)?;
    let pin = object(&pin_value, "ckb_acceptance_pin")?;
    require_field(pin, "schema", json!("cellscript-ckb-acceptance-pin-v0.22"), "ckb_acceptance_pin")?;

    let provenance = object(report.get("ckb_runtime_provenance").unwrap_or(&Value::Null), "ckb_runtime_provenance")?;
    let context = "ckb_runtime_provenance";
    for (key, expected) in [
        ("schema", json!("cellscript-ckb-runtime-provenance-v0.22")),
        ("pin_schema", pin.get("schema").cloned().unwrap_or(Value::Null)),
        ("pin_file_sha256", json!(format!("0x{}", file_sha256(&pin_path)?))),
        ("repository", pin.get("repository").cloned().unwrap_or(Value::Null)),
        ("revision", pin.get("revision").cloned().unwrap_or(Value::Null)),
        ("repo_head", pin.get("revision").cloned().unwrap_or(Value::Null)),
        ("repo_dirty", json!(false)),
        ("version", pin.get("version").cloned().unwrap_or(Value::Null)),
        ("build_mode", json!("fresh-dedicated-cargo-target")),
        ("cxxflags", json!("-include cstdint")),
        ("cxx_compatibility_contract", json!("ckb-librocksdb-sys-8.5.4-explicit-cstdint-v1")),
        ("binary_archived_with_report", json!(true)),
    ] {
        require_field(provenance, key, expected, context)?;
    }
    let version = nonempty_string(pin.get("version"), "ckb_acceptance_pin.version")?;
    let revision = nonempty_string(pin.get("revision"), "ckb_acceptance_pin.revision")?;
    let version_output = nonempty_string(provenance.get("version_output"), &format!("{context}.version_output"))?;
    require(
        version_output.contains(version) && version_output.contains(&revision[..7]),
        format!("{context}.version_output must bind version and revision, got {version_output:?}"),
    )?;

    let ckb_repo = fs::canonicalize(PathBuf::from(report.get("ckb_repo").and_then(Value::as_str).unwrap_or_default()))
        .unwrap_or_else(|_| PathBuf::from(report.get("ckb_repo").and_then(Value::as_str).unwrap_or_default()));
    require(ckb_repo.is_dir(), format!("ckb_repo does not exist: {}", ckb_repo.display()))?;
    require(git_stdout(&ckb_repo, &["rev-parse", "HEAD"])? == revision, "current CKB checkout does not match pin")?;
    require(
        git_stdout(&ckb_repo, &["status", "--porcelain", "--untracked-files=all"])?.is_empty(),
        "current CKB checkout must be clean",
    )?;

    let binary_path = fs::canonicalize(PathBuf::from(provenance.get("binary_path").and_then(Value::as_str).unwrap_or_default()))
        .unwrap_or_else(|_| PathBuf::from(provenance.get("binary_path").and_then(Value::as_str).unwrap_or_default()));
    require(binary_path.is_file(), format!("{context}.binary_path does not exist: {}", binary_path.display()))?;
    let expected_binary = fs::canonicalize(report_dir.join("ckb-runtime/ckb")).unwrap_or_else(|_| report_dir.join("ckb-runtime/ckb"));
    require_field(provenance, "binary_path", json!(expected_binary.to_string_lossy()), context)?;
    require_field(provenance, "binary_sha256", json!(format!("0x{}", file_sha256(&binary_path)?)), context)?;
    let binary_version = Command::new(&binary_path)
        .arg("--version")
        .output()
        .with_context(|| format!("failed to execute {} --version", binary_path.display()))?;
    require(binary_version.status.success(), format!("{} --version failed", binary_path.display()))?;
    require_field(provenance, "version_output", json!(String::from_utf8_lossy(&binary_version.stdout).trim()), context)?;

    let templates = array(pin.get("template_paths"), "ckb_acceptance_pin.template_paths")?;
    require(templates.len() >= 2, "ckb_acceptance_pin.template_paths must contain config and spec paths")?;
    for (key, template) in [("source_template_path", &templates[0]), ("source_spec_path", &templates[1])] {
        let path = ckb_repo.join(nonempty_string(Some(template), &format!("ckb_acceptance_pin.{key}"))?);
        require_field(provenance, key, json!(path.to_string_lossy()), context)?;
        require(path.is_file(), format!("{context}.{key} does not exist: {}", path.display()))?;
        require_field(provenance, &key.replace("_path", "_sha256"), json!(format!("0x{}", file_sha256(&path)?)), context)?;
    }
    for key in ["effective_config", "effective_spec"] {
        let path = PathBuf::from(provenance.get(&format!("{key}_path")).and_then(Value::as_str).unwrap_or_default());
        require(path.is_file(), format!("{context}.{key}_path does not exist: {}", path.display()))?;
        require_field(provenance, &format!("{key}_sha256"), json!(format!("0x{}", file_sha256(&path)?)), context)?;
    }
    hex_hash(provenance.get("genesis_hash"), &format!("{context}.genesis_hash"))?;
    let onchain_genesis = report.get("onchain").and_then(|value| value.get("genesis_hash")).cloned().unwrap_or(Value::Null);
    require_field(provenance, "genesis_hash", onchain_genesis, context)
}

fn validate_build_reports(report: &Map<String, Value>, compile_only: bool) -> Result<()> {
    let build_index = object(report.get("cellscript_build_reports").unwrap_or(&Value::Null), "cellscript_build_reports")?;
    for (key, expected) in [
        ("schema", json!("cellscript-ckb-build-report-index-v0.20")),
        ("target_profile", json!("ckb")),
        ("vm_profile", json!("ckb-vm")),
        ("artifact_format", json!("riscv64-elf")),
        ("artifact_hash_algorithm", json!("ckb-blake2b256")),
        ("requires_exact_artifact_hash", json!(true)),
        ("requires_elf_entry_abi_gate", json!(true)),
        ("requires_live_code_cell_data_hash_match", json!(true)),
        ("status", json!(EXPECTED_STATUS)),
    ] {
        require_field(build_index, key, expected, "cellscript_build_reports")?;
    }
    let rows = array(build_index.get("reports"), "cellscript_build_reports.reports")?;
    require(!rows.is_empty(), "cellscript_build_reports.reports must be a non-empty list")?;
    require_field(build_index, "artifact_count", json!(rows.len()), "cellscript_build_reports")?;
    let elf_gate = report.get("ckb_elf_entry_abi_gate").and_then(Value::as_object).cloned().unwrap_or_default();
    require_field(
        build_index,
        "artifact_count",
        elf_gate.get("audited_artifact_count").cloned().unwrap_or(Value::Null),
        "cellscript_build_reports",
    )?;

    let mut seen_artifacts = BTreeSet::new();
    for (index, value) in rows.iter().enumerate() {
        let context = format!("cellscript_build_reports.reports[{index}]");
        let row = object(value, &context)?;
        for (key, expected) in [
            ("schema", json!(BUILD_REPORT_SCHEMA)),
            ("target_profile", json!("ckb")),
            ("vm_profile", json!("ckb-vm")),
            ("artifact_format", json!("riscv64-elf")),
            ("artifact_hash_algorithm", json!("ckb-blake2b256")),
            ("deployment_hash_type_used_by_gate", json!("data2")),
            ("verify_artifact_status", json!("passed")),
            ("verify_target_profile", json!("ckb")),
            ("elf_entry_abi_status", json!("passed")),
            ("abi_trailer_stripped", json!(true)),
        ] {
            require_field(row, key, expected, &context)?;
        }
        let artifact_size = positive(row.get("artifact_size_bytes"), &format!("{context}.artifact_size_bytes"))?;
        hex_hash(row.get("deployable_elf_hash"), &format!("{context}.deployable_elf_hash"))?;
        hex_hash(row.get("artifact_sha256"), &format!("{context}.artifact_sha256"))?;
        let artifact_path = nonempty_string(row.get("artifact_path"), &format!("{context}.artifact_path"))?;
        require(seen_artifacts.insert(artifact_path.to_owned()), format!("duplicate build report artifact_path: {artifact_path}"))?;
        let artifact = PathBuf::from(artifact_path);
        require(artifact.exists(), format!("{context}.artifact_path does not exist: {}", artifact.display()))?;
        let bytes = fs::read(&artifact)?;
        require(bytes.len() as u64 == artifact_size, format!("{context}.artifact_size_bytes does not match artifact"))?;
        require_field(row, "deployable_elf_hash", json!(hex0x(&ckb_blake2b256(&bytes)?)), &context)?;
        require_field(row, "artifact_sha256", json!(format!("0x{}", sha256_hex(&bytes))), &context)?;
        let deployments = array(row.get("onchain_deployments"), &format!("{context}.onchain_deployments"))?;
        if compile_only {
            require(deployments.is_empty(), format!("{context}.onchain_deployments must be empty for compile-only reports"))?;
        } else {
            require(!deployments.is_empty(), format!("{context}.onchain_deployments must contain live deployment evidence"))?;
            for (deployment_index, deployment_value) in deployments.iter().enumerate() {
                let deployment_context = format!("{context}.onchain_deployments[{deployment_index}]");
                let deployment = object(deployment_value, &deployment_context)?;
                for (key, expected) in [
                    ("code_cell_live", json!(true)),
                    ("live_code_cell_data_hash_matches_artifact", json!(true)),
                    ("artifact_ckb_data_hash_blake2b", row.get("deployable_elf_hash").cloned().unwrap_or(Value::Null)),
                    ("live_code_cell_data_hash", row.get("deployable_elf_hash").cloned().unwrap_or(Value::Null)),
                ] {
                    require_field(deployment, key, expected, &deployment_context)?;
                }
                let out_point =
                    object(deployment.get("out_point").unwrap_or(&Value::Null), &format!("{deployment_context}.out_point"))?;
                for key in ["tx_hash", "index"] {
                    let value = out_point.get(key).and_then(Value::as_str).unwrap_or_default();
                    require(value.starts_with("0x"), format!("{deployment_context}.out_point.{key} must be hex"))?;
                }
            }
        }
    }
    if compile_only {
        require(
            build_index.get("onchain_deployed_artifact_count").is_none_or(|value| value.is_null() || value == &json!(0)),
            "compile-only build reports must not record onchain deployments",
        )?;
    } else {
        require_field(build_index, "onchain_deployed_artifact_count", json!(rows.len()), "cellscript_build_reports")?;
        require_field(build_index, "live_code_cell_data_hash_match_count", json!(rows.len()), "cellscript_build_reports")?;
        for key in ["missing_onchain_deployments", "live_code_cell_data_hash_mismatches", "unexpected_onchain_artifacts"] {
            require_empty(build_index, key, "cellscript_build_reports")?;
        }
    }
    Ok(())
}

fn validate_compile_gate(report: &Map<String, Value>, compile_only: bool) -> Result<()> {
    for (key, expected) in [
        ("acceptance_mode", json!(EXPECTED_MODE)),
        ("status", json!(EXPECTED_STATUS)),
        ("production_ready", json!(!compile_only)),
        ("bundled_examples_count", json!(EXPECTED_EXAMPLES.len())),
        ("bundled_examples_exact_order", json!(EXPECTED_EXAMPLES)),
        ("non_production_examples", json!(EXPECTED_NON_PRODUCTION_EXAMPLES)),
        ("language_examples_count", json!(EXPECTED_LANGUAGE_EXAMPLES.len())),
        ("language_examples_exact_order", json!(EXPECTED_LANGUAGE_EXAMPLES)),
        ("original_scoped_action_count", json!(EXPECTED_ACTION_COUNT)),
        ("original_scoped_lock_count", json!(expected_lock_count())),
        ("original_scoped_action_fail_closed_count", json!(0)),
        ("original_scoped_lock_fail_closed_count", json!(0)),
    ] {
        require_field(report, key, expected, "")?;
    }
    for key in [
        "strict_original_ckb_compile_policy_fail_closed",
        "strict_original_ckb_compile_unexpected_failures",
        "original_scoped_action_fail_closed",
        "original_scoped_lock_fail_closed",
    ] {
        require_empty(report, key, "")?;
    }

    let gate = object(report.get("production_gate").unwrap_or(&Value::Null), "production_gate")?;
    for (key, expected) in [
        ("status", json!(EXPECTED_STATUS)),
        ("requires_original_scoped_harnesses", json!(true)),
        ("requires_no_expected_fail_closed_entries", json!(true)),
        ("requires_all_bundled_examples_strict_original_ckb", json!(true)),
        ("requires_ckb_elf_entry_abi_gate", json!(true)),
        ("requires_cellscript_build_reports", json!(true)),
        ("requires_public_builder_contracts", json!(true)),
    ] {
        require_field(gate, key, expected, "production_gate")?;
    }
    require_empty(gate, "failures", "production_gate")?;
    validate_elf_entry_abi_gate(report)?;
    validate_build_reports(report, compile_only)?;

    let coverage = object(report.get("ckb_business_coverage").unwrap_or(&Value::Null), "ckb_business_coverage")?;
    require_field(coverage, "strict_compile_coverage_complete", json!(true), "ckb_business_coverage")?;
    require_field(coverage, "expected_fail_closed_action_count", json!(0), "ckb_business_coverage")?;
    require_field(coverage, "expected_fail_closed_lock_count", json!(0), "ckb_business_coverage")?;
    if compile_only {
        for (key, expected) in [
            ("status", json!("incomplete")),
            ("onchain_action_coverage_complete", json!(false)),
            ("ckb_onchain_action_count", json!(0)),
        ] {
            require_field(coverage, key, expected, "ckb_business_coverage")?;
        }
        let onchain = object(report.get("onchain").unwrap_or(&Value::Null), "onchain")?;
        require_field(onchain, "status", json!("skipped"), "onchain")?;
        require_field(onchain, "reason", json!("compile-only"), "onchain")?;
    } else {
        require_field(coverage, "status", json!("complete"), "ckb_business_coverage")?;
        require_field(coverage, "onchain_action_coverage_complete", json!(true), "ckb_business_coverage")?;
        require_field(coverage, "ckb_onchain_action_count", json!(EXPECTED_ACTION_COUNT), "ckb_business_coverage")?;
        let missing = coverage.get("missing_ckb_onchain_actions").unwrap_or(&Value::Null);
        require(
            missing.is_null() || missing.as_object().is_some_and(Map::is_empty),
            format!("ckb_business_coverage.missing_ckb_onchain_actions must be empty, got {missing:?}"),
        )?;
    }

    let example_scope = object(report.get("example_scope").unwrap_or(&Value::Null), "example_scope")?;
    for (key, expected) in [
        ("production_bundled_examples", json!(EXPECTED_EXAMPLES)),
        ("non_production_top_level_examples", json!(EXPECTED_NON_PRODUCTION_EXAMPLES)),
        ("non_production_language_examples", json!(EXPECTED_LANGUAGE_EXAMPLES)),
    ] {
        require_field(example_scope, key, expected, "example_scope")?;
    }
    let scope_note = example_scope.get("production_scope_note").and_then(Value::as_str).unwrap_or_default();
    require(
        scope_note.contains("Only production_bundled_examples")
            && scope_note.contains("non_production_top_level_examples")
            && scope_note.contains("non_production_language_examples"),
        "example_scope.production_scope_note must state the production/non-production example boundary",
    )?;

    let source_layout = object(report.get("example_source_layout").unwrap_or(&Value::Null), "example_source_layout")?;
    require(
        source_layout.get("canonical_bundled_examples").is_some_and(Value::is_string),
        "example_source_layout must record canonical_bundled_examples",
    )?;
    require(
        source_layout.get("language_examples").is_some_and(Value::is_string),
        "example_source_layout must record language_examples",
    )?;
    require(
        !source_layout.contains_key("production_acceptance_examples")
            && !source_layout.contains_key("canonical_business_examples")
            && !source_layout.contains_key("flat_business_compatibility_examples"),
        "example_source_layout must not advertise the removed business/acceptance split",
    )?;
    let layout_note = source_layout.get("canonical_examples_note").and_then(Value::as_str).unwrap_or_default();
    require(
        layout_note.contains("top-level examples/*.cell directly")
            && layout_note.contains("examples/business and examples/acceptance"),
        "example_source_layout.canonical_examples_note must state the single-source example layout",
    )?;

    let lock_scope = object(report.get("lock_acceptance_scope").unwrap_or(&Value::Null), "lock_acceptance_scope")?;
    if lock_scope.get("onchain_lock_spend_matrix") == Some(&json!(true)) {
        require_field(lock_scope, "strict_compile_only", json!(false), "lock_acceptance_scope")?;
        require_field(lock_scope, "onchain_lock_spend_matrix_scope", expected_lock_scope(), "lock_acceptance_scope")?;
        require_field(lock_scope, "required_cases_per_lock", json!(["valid_spend", "invalid_spend"]), "lock_acceptance_scope")?;
    } else {
        require_field(lock_scope, "strict_compile_only", json!(true), "lock_acceptance_scope")?;
        require_field(lock_scope, "onchain_lock_spend_matrix", json!(false), "lock_acceptance_scope")?;
        require_field(lock_scope, "pending_onchain_lock_spend_matrix", expected_lock_scope(), "lock_acceptance_scope")?;
        require_field(
            lock_scope,
            "required_cases_per_lock_when_promoted",
            json!(["valid_spend", "invalid_spend"]),
            "lock_acceptance_scope",
        )?;
    }
    let lock_note = lock_scope.get("scope_note").and_then(Value::as_str).unwrap_or_default();
    require(lock_note.contains("strict-compiled"), "lock_acceptance_scope.scope_note must mention strict compilation")
}

fn all_action_runs(report: &Map<String, Value>) -> Result<Vec<&Map<String, Value>>> {
    let onchain = object(report.get("onchain").unwrap_or(&Value::Null), "onchain")?;
    let mut runs = Vec::new();
    for (key, _, expected_actions) in ACTION_RUNS {
        let values = array(onchain.get(*key), &format!("onchain.{key}"))?;
        let actual_actions = values
            .iter()
            .filter_map(Value::as_object)
            .map(|row| row.get("action").cloned().unwrap_or(Value::Null))
            .collect::<Vec<_>>();
        let mut sorted_actual = actual_actions.clone();
        sorted_actual.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
        let mut sorted_expected = json!(expected_actions).as_array().cloned().unwrap();
        sorted_expected.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
        require(
            sorted_actual == sorted_expected && actual_actions.len() == expected_actions.len(),
            format!("onchain.{key} actions must match the production matrix, got {actual_actions:?}"),
        )?;
        let unique = actual_actions.iter().filter_map(Value::as_str).collect::<BTreeSet<_>>();
        require(
            unique.len() == actual_actions.len(),
            format!("onchain.{key} must not contain duplicate actions, got {actual_actions:?}"),
        )?;
        for value in values {
            runs.push(object(value, &format!("onchain.{key} entries"))?);
        }
    }
    Ok(runs)
}

fn validate_code_section(row: &Map<String, Value>, name: &str) -> Result<()> {
    let code = object(row.get("code").unwrap_or(&Value::Null), &format!("{name}.code"))?;
    boolean(code.get("code_cell_live"), &format!("{name}.code.code_cell_live"))?;
    positive(code.get("artifact_size_bytes"), &format!("{name}.code.artifact_size_bytes"))?;
    require_field(code, "live_code_cell_data_hash_matches_artifact", json!(true), &format!("{name}.code"))?;
    hex_hash(code.get("artifact_ckb_data_hash_blake2b"), &format!("{name}.code.artifact_ckb_data_hash_blake2b"))?;
    require_field(
        code,
        "live_code_cell_data_hash",
        code.get("artifact_ckb_data_hash_blake2b").cloned().unwrap_or(Value::Null),
        &format!("{name}.code"),
    )
}

fn validate_measured_constraints(measured: &Map<String, Value>, name: &str, require_output_lists: bool) -> Result<()> {
    let context = format!("{name}.measured_constraints");
    for (key, expected) in [
        ("cycles_status", json!("dry-run-measured")),
        ("tx_size_status", json!("measured-by-cellscript-ckb-tx-measure")),
        ("occupied_capacity_status", json!("derived-by-cellscript-ckb-tx-measure")),
    ] {
        require_field(measured, key, expected, &context)?;
    }
    positive(measured.get("measured_cycles"), &format!("{context}.measured_cycles"))?;
    positive(measured.get("consensus_serialized_tx_size_bytes"), &format!("{context}.consensus_serialized_tx_size_bytes"))?;
    let occupied = positive(measured.get("occupied_capacity_shannons"), &format!("{context}.occupied_capacity_shannons"))?;
    let output_capacity = positive(measured.get("output_capacity_shannons"), &format!("{context}.output_capacity_shannons"))?;
    require(output_capacity >= occupied, format!("{name} output capacity is below occupied capacity"))?;
    if require_output_lists {
        let output_count = positive(measured.get("output_count"), &format!("{context}.output_count"))? as usize;
        let capacities =
            array(measured.get("measured_output_capacity_shannons"), &format!("{context}.measured_output_capacity_shannons"))?;
        let occupied_capacities =
            array(measured.get("output_occupied_capacity_shannons"), &format!("{context}.output_occupied_capacity_shannons"))?;
        require(capacities.len() == output_count, format!("{name} measured output capacity count does not match output_count"))?;
        require(
            occupied_capacities.len() == output_count,
            format!("{name} occupied output capacity count does not match output_count"),
        )?;
        for (index, (capacity, occupied_capacity)) in capacities.iter().zip(occupied_capacities).enumerate() {
            let capacity = positive(Some(capacity), &format!("{context}.measured_output_capacity_shannons[{index}]"))?;
            let occupied_capacity =
                positive(Some(occupied_capacity), &format!("{context}.output_occupied_capacity_shannons[{index}]"))?;
            require(capacity >= occupied_capacity, format!("{name} output {index} capacity is below occupied capacity"))?;
        }
    }
    require(measured.get("capacity_is_sufficient") == Some(&json!(true)), format!("{name} has insufficient capacity"))?;
    require(measured.get("under_capacity_output_indexes") == Some(&json!([])), format!("{name} has under-capacity outputs"))
}

fn validate_stateful_scenarios(onchain: &Map<String, Value>) -> Result<()> {
    let stateful = object(onchain.get("stateful_scenarios").unwrap_or(&Value::Null), "onchain.stateful_scenarios")?;
    require_field(stateful, "status", json!(EXPECTED_STATUS), "onchain.stateful_scenarios")?;
    let scenario_count = positive(stateful.get("scenario_count"), "onchain.stateful_scenarios.scenario_count")? as usize;
    positive(stateful.get("step_count"), "onchain.stateful_scenarios.step_count")?;
    require_field(
        stateful,
        "end_to_end_scenario_count",
        json!(EXPECTED_END_TO_END_STATEFUL_SCENARIOS.len()),
        "onchain.stateful_scenarios",
    )?;
    require_field(
        stateful,
        "action_branch_scenario_count",
        json!(scenario_count - EXPECTED_END_TO_END_STATEFUL_SCENARIOS.len()),
        "onchain.stateful_scenarios",
    )?;
    let coverage = object(
        stateful.get("stateful_action_coverage").unwrap_or(&Value::Null),
        "onchain.stateful_scenarios.stateful_action_coverage",
    )?;
    for (key, expected) in [
        ("status", json!(EXPECTED_STATUS)),
        ("required_action_count", json!(EXPECTED_ACTION_COUNT)),
        ("covered_action_count", json!(EXPECTED_ACTION_COUNT)),
        ("required_action_ids", Value::Array(expected_action_ids())),
        ("covered_action_ids", Value::Array(expected_action_ids())),
    ] {
        require_field(coverage, key, expected, "stateful_action_coverage")?;
    }
    for key in ["missing_action_ids", "missing_artifact_ids", "unexpected_artifact_ids"] {
        require_empty(coverage, key, "stateful_action_coverage")?;
    }
    let runs = array(stateful.get("runs"), "onchain.stateful_scenarios.runs")?;
    require(runs.len() == scenario_count, "stateful scenario runs must match scenario_count")?;
    let leading_names = runs
        .iter()
        .take(EXPECTED_END_TO_END_STATEFUL_SCENARIOS.len())
        .map(|run| run.get("name").cloned().unwrap_or(Value::Null))
        .collect::<Vec<_>>();
    require(
        leading_names == json!(EXPECTED_END_TO_END_STATEFUL_SCENARIOS).as_array().cloned().unwrap(),
        "stateful end-to-end scenario names/order must match the production matrix",
    )?;

    let expected_ids =
        expected_action_ids().into_iter().filter_map(|value| value.as_str().map(str::to_owned)).collect::<BTreeSet<_>>();
    let mut seen_names = BTreeSet::new();
    let mut main_action_ids = BTreeSet::new();
    let mut branch_action_ids = Vec::new();
    let mut observed_step_count = 0_usize;
    for (index, value) in runs.iter().enumerate() {
        let context = format!("onchain.stateful_scenarios.runs[{index}]");
        let run = object(value, &context)?;
        let name = nonempty_string(run.get("name"), &format!("{context}.name"))?;
        require(seen_names.insert(name.to_owned()), format!("duplicate stateful scenario name: {name}"))?;
        for (key, expected) in [
            ("status", json!(EXPECTED_STATUS)),
            ("builder_backed", json!(false)),
            ("transaction_origin", json!("acceptance-rust-harness")),
            ("harness_origin", json!("rust-transaction-recipe-replay")),
        ] {
            require_field(run, key, expected, &context)?;
        }
        nonempty_string(run.get("acceptance_harness_name"), &format!("{context}.acceptance_harness_name"))?;
        let action_ids = array(run.get("action_ids"), &format!("{context}.action_ids"))?;
        require(!action_ids.is_empty(), format!("{context}.action_ids must be a non-empty list"))?;
        let action_id_strings = action_ids.iter().filter_map(Value::as_str).map(str::to_owned).collect::<Vec<_>>();
        require(
            action_id_strings.len() == action_ids.len() && action_id_strings.iter().all(|action_id| expected_ids.contains(action_id)),
            format!("{context}.action_ids contains actions outside the production matrix"),
        )?;
        let steps = array(run.get("steps"), &format!("{context}.steps"))?;
        require(!steps.is_empty(), format!("{context}.steps must be a non-empty list"))?;
        observed_step_count += steps.len();
        if index < EXPECTED_END_TO_END_STATEFUL_SCENARIOS.len() {
            require_field(run, "kind", json!("stateful-scenario"), &context)?;
            require(steps.len() >= 2, format!("{context} end-to-end scenario must contain at least two committed steps"))?;
            main_action_ids.extend(action_id_strings);
        } else {
            require_field(run, "kind", json!("stateful-action-branch"), &context)?;
            require(
                action_ids.len() == 1 && steps.len() == 1,
                format!("{context} branch scenario must bind exactly one action and one step"),
            )?;
            branch_action_ids.extend(action_id_strings);
        }
        for (step_index, step_value) in steps.iter().enumerate() {
            let step_context = format!("{context}.steps[{step_index}]");
            let step = object(step_value, &step_context)?;
            nonempty_string(step.get("step"), &format!("{step_context}.step"))?;
            require_field(step, "status", json!(EXPECTED_STATUS), &step_context)?;
            let dry_run = object(step.get("dry_run").unwrap_or(&Value::Null), &format!("{step_context}.dry_run"))?;
            require(
                dry_run.get("cycles").and_then(Value::as_str).is_some_and(|value| value.starts_with("0x")),
                format!("{step_context}.dry_run.cycles must be a hex quantity"),
            )?;
            let commit = object(step.get("commit").unwrap_or(&Value::Null), &format!("{step_context}.commit"))?;
            hex_hash(commit.get("tx_hash"), &format!("{step_context}.commit.tx_hash"))?;
            let commit_status = object(commit.get("status").unwrap_or(&Value::Null), &format!("{step_context}.commit.status"))?;
            require_field(commit_status, "status", json!("committed"), &format!("{step_context}.commit.status"))?;
            let constraints =
                object(step.get("measured_constraints").unwrap_or(&Value::Null), &format!("{step_context}.measured_constraints"))?;
            positive(constraints.get("measured_cycles"), &format!("{step_context}.measured_constraints.measured_cycles"))?;
            positive(
                constraints.get("consensus_serialized_tx_size_bytes"),
                &format!("{step_context}.measured_constraints.consensus_serialized_tx_size_bytes"),
            )?;
            positive(
                constraints.get("occupied_capacity_shannons"),
                &format!("{step_context}.measured_constraints.occupied_capacity_shannons"),
            )?;
            require_field(constraints, "capacity_is_sufficient", json!(true), &format!("{step_context}.measured_constraints"))?;
            require_empty(constraints, "under_capacity_output_indexes", &format!("{step_context}.measured_constraints"))?;
            let consumed = array(step.get("consumed_inputs"), &format!("{step_context}.consumed_inputs"))?;
            require(
                consumed.iter().all(|cell| cell.as_object().is_some_and(|cell| cell.get("status") != Some(&json!("live")))),
                format!("{step_context}.consumed_inputs contains a still-live or malformed cell"),
            )?;
            let outputs_live = object(step.get("outputs_live").unwrap_or(&Value::Null), &format!("{step_context}.outputs_live"))?;
            require(
                outputs_live.values().all(|value| value == &json!(true)),
                format!("{step_context}.outputs_live contains a dead output"),
            )?;
        }
    }
    require_field(stateful, "step_count", json!(observed_step_count), "onchain.stateful_scenarios")?;
    let expected_branch_ids = expected_ids.difference(&main_action_ids).cloned().collect::<Vec<_>>();
    branch_action_ids.sort();
    require(
        branch_action_ids == expected_branch_ids,
        "stateful branch scenarios must cover every action absent from end-to-end flows exactly once",
    )
}

fn validate_action_runs(report: &Map<String, Value>) -> Result<()> {
    let runs = all_action_runs(report)?;
    require(
        runs.len() == EXPECTED_ACTION_COUNT as usize,
        format!("expected {EXPECTED_ACTION_COUNT} action runs, got {}", runs.len()),
    )?;
    let mut seen_names = BTreeSet::new();
    for run in runs {
        let name = nonempty_string(run.get("name"), "action run name")?;
        require(seen_names.insert(name.to_owned()), format!("duplicate action run name: {name}"))?;
        let action = nonempty_string(run.get("action"), &format!("{name}.action"))?;
        require(name.ends_with(&format!(":{action}")), format!("{name} must end with action suffix :{action}"))?;
        for (key, expected) in [
            ("status", json!(EXPECTED_STATUS)),
            ("builder_backed", json!(false)),
            ("transaction_origin", json!("acceptance-rust-harness")),
            ("harness_origin", json!("rust-transaction-recipe-replay")),
            ("public_builder_contract_id", json!(name)),
            ("public_builder_contract_verified", json!(true)),
        ] {
            require_field(run, key, expected, name)?;
        }
        nonempty_string(run.get("acceptance_harness_name"), &format!("{name}.acceptance_harness_name"))?;
        nonempty_string(run.get("acceptance_harness_implementation"), &format!("{name}.acceptance_harness_implementation"))?;
        validate_code_section(run, name)?;
        let valid_dry_run = object(run.get("valid_dry_run").unwrap_or(&Value::Null), &format!("{name}.valid_dry_run"))?;
        require(
            valid_dry_run.get("cycles").and_then(Value::as_str).is_some_and(|value| value.starts_with("0x")),
            format!("{name} missing hex dry-run cycles"),
        )?;
        object(run.get("valid_commit").unwrap_or(&Value::Null), &format!("{name}.valid_commit"))?;
        let malformed = object(run.get("malformed_transaction").unwrap_or(&Value::Null), &format!("{name}.malformed_transaction"))?;
        for (key, expected) in
            [("status", json!("rejected")), ("expected_reason_matched", json!(true)), ("policy_or_capacity_reason", json!(false))]
        {
            require_field(malformed, key, expected, &format!("{name}.malformed_transaction"))?;
        }
        let measured = object(run.get("measured_constraints").unwrap_or(&Value::Null), &format!("{name}.measured_constraints"))?;
        validate_measured_constraints(measured, name, true)?;
    }
    Ok(())
}

fn validate_lock_runs(onchain: &Map<String, Value>) -> Result<()> {
    let runs = array(onchain.get("lock_spend_matrix_runs"), "onchain.lock_spend_matrix_runs")?;
    let lock_names = runs
        .iter()
        .filter_map(Value::as_object)
        .map(|row| row.get("name").and_then(Value::as_str).unwrap_or_default().to_owned())
        .collect::<Vec<_>>();
    let mut actual_sorted = lock_names.clone();
    actual_sorted.sort();
    let mut expected_sorted = expected_lock_names();
    expected_sorted.sort();
    require(
        actual_sorted == expected_sorted && lock_names.len() == expected_lock_count() as usize,
        format!("lock spend matrix must cover {expected_sorted:?}, got {lock_names:?}"),
    )?;
    require(
        lock_names.iter().collect::<BTreeSet<_>>().len() == lock_names.len(),
        format!("lock spend matrix must not contain duplicates, got {lock_names:?}"),
    )?;
    for value in runs {
        let run = object(value, "lock spend matrix entry")?;
        let name = nonempty_string(run.get("name"), "lock run name")?;
        let lock = nonempty_string(run.get("lock"), &format!("{name}.lock"))?;
        require(name.ends_with(&format!(":{lock}")), format!("{name} must end with lock suffix :{lock}"))?;
        for (key, expected) in [
            ("status", json!(EXPECTED_STATUS)),
            ("builder_backed", json!(false)),
            ("transaction_origin", json!("acceptance-rust-harness")),
            ("harness_origin", json!("rust-transaction-recipe-replay")),
        ] {
            require_field(run, key, expected, name)?;
        }
        nonempty_string(run.get("acceptance_harness_name"), &format!("{name}.acceptance_harness_name"))?;
        nonempty_string(run.get("acceptance_harness_implementation"), &format!("{name}.acceptance_harness_implementation"))?;
        validate_code_section(run, name)?;

        let valid_spend = object(run.get("valid_spend").unwrap_or(&Value::Null), &format!("{name}.valid_spend"))?;
        require_field(valid_spend, "status", json!(EXPECTED_STATUS), &format!("{name}.valid_spend"))?;
        require_field(valid_spend, "output_live", json!(true), &format!("{name}.valid_spend"))?;
        let valid_dry_run = object(valid_spend.get("dry_run").unwrap_or(&Value::Null), &format!("{name}.valid_spend.dry_run"))?;
        require(
            valid_dry_run.get("cycles").and_then(Value::as_str).is_some_and(|value| value.starts_with("0x")),
            format!("{name}.valid_spend missing hex dry-run cycles"),
        )?;
        object(valid_spend.get("commit").unwrap_or(&Value::Null), &format!("{name}.valid_spend.commit"))?;

        let invalid_spend = object(run.get("invalid_spend").unwrap_or(&Value::Null), &format!("{name}.invalid_spend"))?;
        require_field(invalid_spend, "status", json!("rejected"), &format!("{name}.invalid_spend"))?;
        let rejection = object(invalid_spend.get("rejection").unwrap_or(&Value::Null), &format!("{name}.invalid_spend.rejection"))?;
        for (key, expected) in
            [("status", json!("rejected")), ("expected_reason_matched", json!(true)), ("policy_or_capacity_reason", json!(false))]
        {
            require_field(rejection, key, expected, &format!("{name}.invalid_spend.rejection"))?;
        }
        let reason = nonempty_string(rejection.get("reason"), &format!("{name}.invalid_spend.rejection.reason"))?;
        for fragment in ["source: Inputs[0].Lock", "ValidationFailure", "error code 5"] {
            require(
                reason.contains(fragment),
                format!("{name}.invalid_spend.rejection must show lock predicate error fragment {fragment:?}"),
            )?;
        }
        let live_after = array(
            invalid_spend.get("input_cells_live_after_rejection"),
            &format!("{name}.invalid_spend.input_cells_live_after_rejection"),
        )?;
        require(
            !live_after.is_empty() && live_after.iter().all(|value| value == &json!(true)),
            format!("{name}.invalid_spend must keep rejected input cells live"),
        )?;
        let measured = object(run.get("measured_constraints").unwrap_or(&Value::Null), &format!("{name}.measured_constraints"))?;
        validate_measured_constraints(measured, name, false)?;
    }
    Ok(())
}

fn validate_onchain_gate(report: &Map<String, Value>) -> Result<()> {
    let onchain = object(report.get("onchain").unwrap_or(&Value::Null), "onchain")?;
    for (key, expected) in [
        ("status", json!(EXPECTED_STATUS)),
        ("all_artifacts_deployed_and_spent", json!(true)),
        ("all_bundled_examples_deployed", json!(true)),
        ("bundled_examples_deployed", json!(EXPECTED_EXAMPLES)),
        ("all_token_actions_exercised", json!(true)),
        ("all_nft_actions_exercised", json!(true)),
        ("all_timelock_actions_exercised", json!(true)),
        ("all_multisig_actions_exercised", json!(true)),
        ("all_vesting_actions_exercised", json!(true)),
        ("all_amm_actions_exercised", json!(true)),
        ("all_launch_actions_exercised", json!(true)),
        ("builder_backed_action_count", json!(0)),
        ("acceptance_harness_action_count", json!(EXPECTED_ACTION_COUNT)),
        ("public_builder_contract_action_count", json!(EXPECTED_ACTION_COUNT)),
        ("measured_cycles_action_count", json!(EXPECTED_ACTION_COUNT)),
        ("tx_size_measured_action_count", json!(EXPECTED_ACTION_COUNT)),
        ("occupied_capacity_measured_action_count", json!(EXPECTED_ACTION_COUNT)),
        ("lock_spend_matrix_count", json!(expected_lock_count())),
        ("builder_backed_lock_spend_matrix_count", json!(0)),
        ("acceptance_harness_lock_spend_matrix_count", json!(expected_lock_count())),
        ("lock_valid_spend_count", json!(expected_lock_count())),
        ("lock_invalid_spend_count", json!(expected_lock_count())),
        ("measured_cycles_lock_count", json!(expected_lock_count())),
        ("tx_size_measured_lock_count", json!(expected_lock_count())),
        ("occupied_capacity_measured_lock_count", json!(expected_lock_count())),
        ("all_locks_behavior_exercised", json!(true)),
    ] {
        require_field(onchain, key, expected, "onchain")?;
    }
    let resource_scope =
        object(onchain.get("resource_identity_evidence_scope").unwrap_or(&Value::Null), "onchain.resource_identity_evidence_scope")?;
    for (key, expected) in [
        ("status", json!("fixture-only")),
        ("always_success_resource_types", json!(true)),
        ("production_resource_identity_proven", json!(false)),
    ] {
        require_field(resource_scope, key, expected, "onchain.resource_identity_evidence_scope")?;
    }

    let deployments = array(onchain.get("bundled_example_deployment_runs"), "onchain.bundled_example_deployment_runs")?;
    require(
        deployments.len() == EXPECTED_EXAMPLES.len(),
        format!("expected {} bundled example deployment runs, got {}", EXPECTED_EXAMPLES.len(), deployments.len()),
    )?;
    let deployment_names =
        deployments.iter().filter_map(Value::as_object).map(|row| row.get("name").cloned().unwrap_or(Value::Null)).collect::<Vec<_>>();
    require(
        deployment_names == json!(EXPECTED_EXAMPLES).as_array().cloned().unwrap(),
        format!("bundled example deployment order must match release scope, got {deployment_names:?}"),
    )?;
    for value in deployments {
        let run = object(value, "bundled example deployment run")?;
        let name = nonempty_string(run.get("name"), "bundled example deployment run name")?;
        require_field(run, "status", json!(EXPECTED_STATUS), name)?;
        require_field(run, "kind", json!("bundled-example-strict-original"), name)?;
        boolean(run.get("code_cell_live"), &format!("{name}.code_cell_live"))?;
        positive(run.get("artifact_size_bytes"), &format!("{name}.artifact_size_bytes"))?;
        require_field(run, "live_code_cell_data_hash_matches_artifact", json!(true), name)?;
        hex_hash(run.get("artifact_ckb_data_hash_blake2b"), &format!("{name}.artifact_ckb_data_hash_blake2b"))?;
        require_field(
            run,
            "live_code_cell_data_hash",
            run.get("artifact_ckb_data_hash_blake2b").cloned().unwrap_or(Value::Null),
            name,
        )?;
        let dry_run = object(run.get("valid_deploy_dry_run").unwrap_or(&Value::Null), &format!("{name}.valid_deploy_dry_run"))?;
        require(
            dry_run.get("cycles").and_then(Value::as_str).is_some_and(|value| value.starts_with("0x")),
            format!("{name} missing hex deploy dry-run cycles"),
        )?;
    }

    let final_gate = object(report.get("final_production_hardening_gate").unwrap_or(&Value::Null), "final_production_hardening_gate")?;
    for (key, expected) in [
        ("status", json!(EXPECTED_STATUS)),
        ("ready", json!(true)),
        ("requires_builder_generated_transactions", json!(false)),
        ("requires_public_builder_contracts", json!(true)),
        ("requires_acceptance_harness_transactions", json!(true)),
        ("requires_measured_cycles", json!(true)),
        ("requires_consensus_serialized_tx_size", json!(true)),
        ("requires_exact_occupied_capacity", json!(true)),
        ("requires_stateful_action_coverage", json!(true)),
        ("production_resource_identity_claim", json!(false)),
        ("resource_identity_evidence_scope", json!("always-success-fixture-only")),
        ("requires_build_report_live_artifact_linkage", json!(true)),
    ] {
        require_field(final_gate, key, expected, "final_production_hardening_gate")?;
    }
    require_empty(final_gate, "failures", "final_production_hardening_gate")?;
    validate_stateful_scenarios(onchain)?;
    validate_action_runs(report)?;
    validate_lock_runs(onchain)
}

pub fn run(repo_root: &Path, report: &Path, explicit_repo_root: Option<&Path>, compile_only: bool) -> Result<i32> {
    let report_path = fs::canonicalize(report).with_context(|| format!("missing CKB production evidence: {}", report.display()))?;
    let source_root = match explicit_repo_root {
        Some(path) => fs::canonicalize(path).with_context(|| format!("failed to resolve repository root {}", path.display()))?,
        None => repo_root.to_path_buf(),
    };
    let report_value = load_json(&report_path)?;
    let report_object = object(&report_value, &report_path.display().to_string())?;
    validate_source_provenance(report_object, &source_root)?;
    validate_public_builder_contracts(report_object)?;
    validate_compile_gate(report_object, compile_only)?;
    if !compile_only {
        validate_ckb_runtime_provenance(
            report_object,
            &source_root,
            report_path.parent().context("production evidence report has no parent directory")?,
        )?;
        validate_onchain_gate(report_object)?;
    }
    let mode = if compile_only { "compile-only " } else { "" };
    println!("valid CKB CellScript {mode}production evidence: {}", report_path.display());
    Ok(0)
}
