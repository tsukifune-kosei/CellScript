use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::ckb_devnet::{ckb_hash_hex, sha256_hex};
use crate::evidence_retention::{deduplicate_run, prune_run_directories, write_latest_index};
use crate::production_evidence::{
    self, ACTION_RUNS, BUILD_REPORT_SCHEMA, EXPECTED_CRITICAL_ELF_ABI_EXAMPLES, EXPECTED_EXAMPLES, EXPECTED_LANGUAGE_EXAMPLES,
    EXPECTED_NON_PRODUCTION_EXAMPLES, LOCKS, PUBLIC_TIMELOCK_ACTIONS, SOURCE_PROVENANCE_SCHEMA,
};

const PROFILE_TRAILER: &[u8] = b"SPORABI\0";
const TRAMPOLINE: [u8; 20] = hex_literal::hex!("97000000e7804001b70800009388d80573000000");

#[derive(Clone)]
pub(crate) struct ArtifactRecord {
    pub name: String,
    pub kind: String,
    pub example: Option<String>,
    pub entry: Option<String>,
    pub entry_flag: Option<String>,
    pub source: PathBuf,
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    pub data_hash: String,
    pub sha256: String,
    pub abi: Value,
}

pub(crate) struct CompileEvidence {
    pub report: Value,
    pub artifacts: Vec<ArtifactRecord>,
    pub report_path: PathBuf,
    pub run_dir: PathBuf,
}

fn command_output(command: &mut Command, label: &str) -> Result<Output> {
    let output = command.output().with_context(|| format!("failed to run {label}"))?;
    if !output.status.success() {
        bail!(
            "{label} failed with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(output)
}

fn git_stdout(root: &Path, args: &[&str]) -> Result<String> {
    let output = command_output(Command::new("git").args(args).current_dir(root), "git source query")?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(bytes.get(offset..offset + 2).context("truncated ELF u16")?.try_into()?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(bytes.get(offset..offset + 4).context("truncated ELF u32")?.try_into()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(bytes.get(offset..offset + 8).context("truncated ELF u64")?.try_into()?))
}

fn audit_elf(name: &str, bytes: &[u8]) -> Result<Value> {
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        bail!("{name} is not a little-endian ELF64 artifact");
    }
    if read_u16(bytes, 18)? != 243 {
        bail!("{name} is not an ELF RISC-V artifact");
    }
    if bytes[bytes.len().saturating_sub(64)..].windows(PROFILE_TRAILER.len()).any(|window| window == PROFILE_TRAILER) {
        bail!("{name} contains the forbidden profile trailer");
    }
    let entry = read_u64(bytes, 24)?;
    let program_offset = read_u64(bytes, 32)? as usize;
    let program_size = read_u16(bytes, 54)? as usize;
    let program_count = read_u16(bytes, 56)? as usize;
    let mut executable = None;
    for index in 0..program_count {
        let offset = program_offset + index * program_size;
        if read_u32(bytes, offset)? != 1 {
            continue;
        }
        let flags = read_u32(bytes, offset + 4)?;
        let file_offset = read_u64(bytes, offset + 8)?;
        let virtual_address = read_u64(bytes, offset + 16)?;
        let file_size = read_u64(bytes, offset + 32)?;
        let memory_size = read_u64(bytes, offset + 40)?;
        if flags & 1 != 0 && entry >= virtual_address && entry < virtual_address + memory_size {
            executable = Some((index, flags, file_offset, virtual_address, file_size, memory_size));
            break;
        }
    }
    let (index, flags, file_offset, virtual_address, file_size, memory_size) =
        executable.with_context(|| format!("{name} has no executable load segment containing its entry point"))?;
    if flags != 5 || file_size != memory_size {
        bail!("{name} executable segment must be RX-only with equal file/memory size");
    }
    let entry_offset = (file_offset + entry - virtual_address) as usize;
    let trampoline = bytes.get(entry_offset..entry_offset + TRAMPOLINE.len()).context("truncated ELF entry trampoline")?;
    if trampoline != TRAMPOLINE {
        bail!("{name} has an unexpected CKB entry trampoline: 0x{}", hex::encode(trampoline));
    }
    Ok(json!({
        "schema": "cellscript-ckb-elf-entry-abi-v0.22",
        "status": "passed",
        "entry_point": format!("0x{entry:x}"),
        "executable_load_segment": {
            "index": index, "flags": flags, "flags_symbolic": "R|X", "writable": false,
            "file_offset": file_offset, "virtual_address": format!("0x{virtual_address:x}"),
            "file_size": file_size, "memory_size": memory_size, "file_size_equals_memory_size": true
        },
        "trampoline": {
            "size_bytes": TRAMPOLINE.len(), "entry_file_offset": entry_offset,
            "bytes_hex": hex::encode(trampoline),
            "instructions_le_hex": ["0x00000097", "0x014080e7", "0x000008b7", "0x05d88893", "0x00000073"],
            "first_instruction_le_hex": "0x00000097", "first_instruction_opcode": "auipc", "first_instruction_rd": "ra",
            "call_instruction_opcode": "jalr", "call_target": format!("0x{:x}", entry + 20),
            "expected_call_target": format!("0x{:x}", entry + 20), "exit_syscall_number": 93,
            "exit_sequence_exact": true, "calls_entry_with_ra": true,
            "preserves_ckb_vm_stack_pointer": true, "forbidden_sp_initialisation": false
        }
    }))
}

fn example_build_path(root: &Path, example: &str) -> PathBuf {
    let package = root.join("examples").join(example.trim_end_matches(".cell"));
    if package.join("Cell.toml").is_file() {
        package
    } else {
        root.join("examples").join(example)
    }
}

#[allow(clippy::too_many_arguments)]
fn compile_artifact(
    cellc: &Path,
    source: &Path,
    output: &Path,
    name: &str,
    kind: &str,
    example: Option<&str>,
    entry_flag: Option<&str>,
    entry: Option<&str>,
) -> Result<ArtifactRecord> {
    let mut command = Command::new(cellc);
    command.arg(source).args(["--target-profile", "ckb", "--target", "riscv64-elf", "--primitive-strict", "0.16"]);
    if let (Some(flag), Some(value)) = (entry_flag, entry) {
        command.args([flag, value]);
    }
    command.arg("-o").arg(output);
    for key in ["CELLSCRIPT_RISCV_CC", "CELLSCRIPT_RISCV_AS", "CELLSCRIPT_RISCV_LD"] {
        command.env_remove(key);
    }
    command_output(&mut command, &format!("compile {name}"))?;
    let metadata = PathBuf::from(format!("{}.meta.json", output.display()));
    if !metadata.is_file() {
        bail!("compile {name} did not emit {}", metadata.display());
    }
    let verify = command_output(
        Command::new(cellc).arg("verify-artifact").arg(output).args(["--expect-target-profile", "ckb", "--json"]),
        &format!("verify {name}"),
    )?;
    let verify: Value = serde_json::from_slice(&verify.stdout).with_context(|| format!("invalid verify JSON for {name}"))?;
    if verify["target_profile"] != "ckb" {
        bail!("verify-artifact did not bind {name} to target_profile=ckb");
    }
    let bytes = fs::read(output)?;
    let abi = audit_elf(name, &bytes)?;
    Ok(ArtifactRecord {
        name: name.to_owned(),
        kind: kind.to_owned(),
        example: example.map(str::to_owned),
        entry: entry.map(str::to_owned),
        entry_flag: entry_flag.map(str::to_owned),
        source: source.to_path_buf(),
        path: output.to_path_buf(),
        data_hash: ckb_hash_hex(&bytes),
        sha256: sha256_hex(&bytes),
        bytes,
        abi,
    })
}

fn build_cellc(root: &Path) -> Result<PathBuf> {
    let target = env::var_os("CELLSCRIPT_CELLC_TARGET_DIR").map(PathBuf::from).unwrap_or_else(|| root.join("target/cellscript-cellc"));
    command_output(
        Command::new("cargo")
            .args(["build", "--locked", "--manifest-path"])
            .arg(root.join("Cargo.toml"))
            .args(["--bin", "cellc", "--target-dir"])
            .arg(&target),
        "build cellc",
    )?;
    let binary = target.join("debug/cellc");
    if !binary.is_file() {
        bail!("cellc build succeeded but {} is missing", binary.display());
    }
    Ok(binary)
}

fn recursive_files(root: &Path) -> Result<Vec<PathBuf>> {
    fn visit(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
        let mut entries = fs::read_dir(path)?.collect::<std::result::Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                visit(&path, out)?;
            } else if path.is_file() {
                out.push(path);
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    visit(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn builder_contracts(root: &Path, cellc: &Path, run_dir: &Path) -> Result<Value> {
    let builder_root = run_dir.join("public-builders");
    let mut contracts = Vec::new();
    for example in EXPECTED_EXAMPLES {
        let matrix_actions = ACTION_RUNS
            .iter()
            .find(|(_, candidate, _)| candidate == example)
            .map(|(_, _, actions)| *actions)
            .with_context(|| format!("missing production action matrix for {example}"))?;
        let actions = if *example == "timelock.cell" { PUBLIC_TIMELOCK_ACTIONS } else { matrix_actions };
        let source = root.join("examples").join(example);
        let output = builder_root.join(example.trim_end_matches(".cell"));
        let package_name = format!("@cellscript-acceptance/{}", example.trim_end_matches(".cell"));
        let generated = command_output(
            Command::new(cellc)
                .arg("gen-builder")
                .arg(&source)
                .args(["--target", "typescript", "--target-profile", "ckb", "--output"])
                .arg(&output)
                .args(["--package-name", &package_name, "--json"]),
            &format!("gen-builder {example}"),
        )?;
        let summary: Value = serde_json::from_slice(&generated.stdout)?;
        let manifest_path = output.join("cellscript-builder-manifest.json");
        let manifest: Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        let manifest_actions = manifest["actions"]
            .as_array()
            .context("builder manifest actions missing")?
            .iter()
            .map(|row| row["name"].as_str().unwrap_or_default())
            .collect::<Vec<_>>();
        if manifest_actions != *actions || summary["actions"] != json!(actions) {
            bail!("generated builder actions for {example} do not match the production matrix");
        }
        let plan_dir = output.join("action-plans");
        fs::create_dir_all(&plan_dir)?;
        let mut action_plans = Vec::new();
        for action in actions {
            let plan_path = plan_dir.join(format!("{action}.json"));
            command_output(
                Command::new(cellc)
                    .args(["action", "build"])
                    .arg(&source)
                    .args(["--action", action, "--target-profile", "ckb", "--output"])
                    .arg(&plan_path),
                &format!("action build {example}:{action}"),
            )?;
            let plan: Value = serde_json::from_slice(&fs::read(&plan_path)?)?;
            if plan["status"] != "ok" || plan["policy"] != "cellscript-action-builder-plan-v1" || plan["action"] != *action {
                bail!("invalid action plan for {example}:{action}");
            }
            action_plans.push(json!({
                "action": action, "contract_id": format!("{example}:{action}"),
                "policy": "cellscript-action-builder-plan-v1", "artifact_hash": plan["artifact_hash"],
                "plan_path": plan_path, "plan_sha256": sha256_hex(&fs::read(&plan_path)?), "status": "passed"
            }));
        }
        let files = recursive_files(&output)?;
        let mut digest = Sha256::new();
        for path in &files {
            let relative = path.strip_prefix(&output)?.to_string_lossy().replace('\\', "/");
            digest.update(relative.as_bytes());
            digest.update([0]);
            digest.update(Sha256::digest(fs::read(path)?));
        }
        contracts.push(json!({
            "example": example, "source": source, "status": "passed",
            "generator_schema": summary["schema"], "builder_manifest_schema": manifest["schema"],
            "target": summary["target"], "target_profile": manifest["target_profile"],
            "actions": actions, "action_count": actions.len(), "manifest_path": manifest_path,
            "manifest_sha256": sha256_hex(&fs::read(output.join("cellscript-builder-manifest.json"))?),
            "generated_tree_sha256": format!("0x{}", hex::encode(digest.finalize())),
            "generated_file_count": files.len(), "action_plans": action_plans,
            "runtime_adapter_execution": "not-proven-by-this-contract-gate"
        }));
    }
    Ok(json!({
        "schema": "cellscript-public-builder-contract-gate-v0.22", "status": "passed",
        "example_count": contracts.len(), "action_count": 43,
        "requires_gen_builder": true, "requires_action_build": true,
        "transaction_origin_claim": "acceptance-rust-harness-not-generated-builder", "contracts": contracts
    }))
}

fn source_provenance(root: &Path) -> Result<Value> {
    let mut current = production_evidence::current_source_provenance(root)?;
    current.insert("schema".into(), json!(SOURCE_PROVENANCE_SCHEMA));
    current.insert("generated_at_utc".into(), json!(OffsetDateTime::now_utc().format(&Rfc3339)?));
    Ok(Value::Object(current))
}

fn elf_gate(artifacts: &[ArtifactRecord]) -> Value {
    let rows = artifacts
        .iter()
        .map(|artifact| {
            let trampoline = &artifact.abi["trampoline"];
            json!({
                "name": artifact.name, "kind": artifact.kind, "source": artifact.source,
                "example": artifact.example, "artifact": artifact.path, "status": "passed",
                "preserves_ckb_vm_stack_pointer": true, "entry_trampoline_calls_with_ra": true,
                "executable_segment_rx_only": true, "executable_segment_file_size_equals_memory_size": true,
                "first_instruction_le_hex": trampoline["first_instruction_le_hex"],
                "trampoline_bytes_hex": trampoline["bytes_hex"],
                "trampoline_instructions_le_hex": trampoline["instructions_le_hex"],
                "call_target": trampoline["call_target"], "expected_call_target": trampoline["expected_call_target"],
                "exit_syscall_number": 93, "exit_sequence_exact": true, "entry_point": artifact.abi["entry_point"]
            })
        })
        .collect::<Vec<_>>();
    let mut critical = Map::new();
    for example in EXPECTED_CRITICAL_ELF_ABI_EXAMPLES {
        let names =
            artifacts.iter().filter(|row| row.example.as_deref() == Some(*example)).map(|row| row.name.clone()).collect::<Vec<_>>();
        critical.insert(
            (*example).into(),
            json!({"status":"passed", "artifact_count":names.len(), "audited_artifacts":names, "missing":false, "failures":[]}),
        );
    }
    json!({
        "schema":"cellscript-ckb-elf-entry-abi-gate-v0.22", "status":"passed",
        "requires_ckb_vm_stack_pointer_preserved":true, "requires_entry_trampoline_call_sequence":true,
        "requires_rx_only_executable_segment":true, "requires_no_fake_stack_load_segment":true,
        "critical_examples":EXPECTED_CRITICAL_ELF_ABI_EXAMPLES, "critical_example_gate":critical,
        "audited_artifact_count":rows.len(), "failures":[], "rows":rows
    })
}

fn build_reports(artifacts: &[ArtifactRecord]) -> Value {
    let rows = artifacts
        .iter()
        .map(|artifact| {
            json!({
                "schema": BUILD_REPORT_SCHEMA, "name":artifact.name, "kind":artifact.kind,
                "source":artifact.source, "original_source":artifact.example.as_ref().map(|name| format!("examples/{name}")),
                "example":artifact.example, "entry_flag":artifact.entry_flag, "entry":artifact.entry,
                "target_profile":"ckb", "vm_profile":"ckb-vm", "artifact_format":"riscv64-elf",
                "artifact_path":artifact.path, "metadata_sidecar":format!("{}.meta.json", artifact.path.display()),
                "artifact_packaging":"ckb-elf", "artifact_size_bytes":artifact.bytes.len(),
                "artifact_hash_algorithm":"ckb-blake2b256", "deployable_elf_hash":artifact.data_hash,
                "artifact_sha256":artifact.sha256, "deployment_hash_type_used_by_gate":"data2",
                "verify_artifact_status":"passed", "verify_target_profile":"ckb", "elf_entry_abi_status":"passed",
                "abi_trailer_stripped":true, "onchain_deployments":[]
            })
        })
        .collect::<Vec<_>>();
    json!({
        "schema":"cellscript-ckb-build-report-index-v0.20", "status":"passed", "artifact_count":rows.len(),
        "artifact_hash_algorithm":"ckb-blake2b256", "artifact_format":"riscv64-elf", "target_profile":"ckb",
        "vm_profile":"ckb-vm", "requires_exact_artifact_hash":true, "requires_elf_entry_abi_gate":true,
        "requires_live_code_cell_data_hash_match":true, "reports":rows
    })
}

fn expected_lock_scope() -> Value {
    let mut result = Map::new();
    for (example, locks) in LOCKS {
        result.insert((*example).to_owned(), json!(locks));
    }
    Value::Object(result)
}

pub(crate) fn business_coverage(full: bool) -> Value {
    let rows = ACTION_RUNS
        .iter()
        .map(|(_, example, actions)| {
            let locks = LOCKS.iter().find(|(candidate, _)| candidate == example).map(|(_, locks)| *locks).unwrap_or(&[]);
            json!({
                "example":example, "source_actions":actions, "source_locks":locks,
                "strict_ckb_actions":actions, "strict_ckb_locks":locks,
                "expected_fail_closed_actions":[], "expected_fail_closed_locks":[],
                "ckb_onchain_actions":if full { json!(actions) } else { json!([]) },
                "missing_strict_ckb_actions":[], "missing_strict_ckb_locks":[],
                "missing_ckb_onchain_actions":if full { json!([]) } else { json!(actions) },
                "strict_action_coverage_complete":true, "strict_lock_coverage_complete":true,
                "ckb_onchain_action_coverage_complete":full
            })
        })
        .collect::<Vec<_>>();
    json!({
        "status":if full {"complete"} else {"incomplete"}, "strict_compile_coverage_complete":true,
        "onchain_action_coverage_complete":full, "source_action_count":43, "source_lock_count":17,
        "strict_ckb_action_count":43, "strict_ckb_lock_count":17,
        "expected_fail_closed_action_count":0, "expected_fail_closed_lock_count":0,
        "ckb_onchain_action_count":if full {43} else {0},
        "missing_strict_ckb_actions":{}, "missing_strict_ckb_locks":{},
        "missing_ckb_onchain_actions":if full { json!({}) } else { json!(ACTION_RUNS.iter().map(|(_, example, actions)| ((*example).to_owned(), json!(actions))).collect::<Map<_,_>>()) },
        "rows":rows
    })
}

fn compile_matrix(root: &Path, cellc: &Path, run_dir: &Path) -> Result<Vec<ArtifactRecord>> {
    let artifact_root = run_dir.join("artifacts");
    fs::create_dir_all(&artifact_root)?;
    let mut artifacts = Vec::new();
    for example in EXPECTED_EXAMPLES {
        let source = example_build_path(root, example);
        artifacts.push(compile_artifact(
            cellc,
            &source,
            &artifact_root.join(format!("{}.strict.elf", example)),
            example,
            "bundled-example-strict-original",
            Some(example),
            None,
            None,
        )?);
    }
    for (_, example, actions) in ACTION_RUNS {
        let source = example_build_path(root, example);
        for action in *actions {
            artifacts.push(compile_artifact(
                cellc,
                &source,
                &artifact_root.join(format!("original_{}_{}.elf", example.trim_end_matches(".cell"), action)),
                &format!("{example}:{action}"),
                "original-scoped-action-strict",
                Some(example),
                Some("--entry-action"),
                Some(action),
            )?);
        }
    }
    for (example, locks) in LOCKS {
        let source = example_build_path(root, example);
        for lock in *locks {
            artifacts.push(compile_artifact(
                cellc,
                &source,
                &artifact_root.join(format!("original_{}_{}.elf", example.trim_end_matches(".cell"), lock)),
                &format!("{example}:{lock}"),
                "original-scoped-lock-strict",
                Some(example),
                Some("--entry-lock"),
                Some(lock),
            )?);
        }
    }
    let bounded_group_package = run_dir.join("bounded-group-input-package");
    fs::create_dir_all(bounded_group_package.join("src"))?;
    fs::copy(root.join("tests/fixtures/bounded_group_input.cell"), bounded_group_package.join("src/main.cell"))?;
    fs::write(
        bounded_group_package.join("Cell.toml"),
        "[package]\nedition = \"2026\"\nname = \"bounded_group_input_acceptance\"\nversion = \"0.1.0\"\n",
    )?;
    artifacts.push(compile_artifact(
        cellc,
        &bounded_group_package,
        &artifact_root.join("bounded_group_input_v1_verify.elf"),
        "bounded-group-input-v1:verify",
        "bounded-group-input-stateful-acceptance",
        None,
        Some("--entry-action"),
        Some("verify"),
    )?);
    let bounded_output_package = run_dir.join("bounded-output-plan-package");
    fs::create_dir_all(bounded_output_package.join("src"))?;
    fs::copy(root.join("tests/fixtures/bounded_output_plan.cell"), bounded_output_package.join("src/main.cell"))?;
    fs::write(
        bounded_output_package.join("Cell.toml"),
        "[package]\nedition = \"2026\"\nname = \"bounded_output_plan_acceptance\"\nversion = \"0.1.0\"\n",
    )?;
    artifacts.push(compile_artifact(
        cellc,
        &bounded_output_package,
        &artifact_root.join("bounded_output_plan_v1_verify.elf"),
        "bounded-output-plan-v1:verify",
        "bounded-output-plan-stateful-acceptance",
        None,
        Some("--entry-action"),
        Some("verify"),
    )?);
    Ok(artifacts)
}

fn validate_example_layout(root: &Path) -> Result<()> {
    let examples = root.join("examples");
    let production = fs::read_dir(&examples)?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "cell"))
        .filter_map(|path| path.file_name().and_then(|name| name.to_str()).map(str::to_owned))
        .filter(|name| !EXPECTED_NON_PRODUCTION_EXAMPLES.contains(&name.as_str()))
        .collect::<BTreeSet<_>>();
    if production != EXPECTED_EXAMPLES.iter().map(|value| (*value).to_owned()).collect() {
        bail!("canonical bundled example set changed: {production:?}");
    }
    let language_root = examples.join("language");
    let mut language = BTreeSet::new();
    collect_language_examples(&language_root, &language_root, &mut language)?;
    if language != EXPECTED_LANGUAGE_EXAMPLES.iter().map(|value| (*value).to_owned()).collect() {
        bail!("language example set changed: {language:?}");
    }
    for stale in ["business", "acceptance"] {
        if examples.join(stale).exists() {
            bail!("stale checked-in example mirror exists: examples/{stale}");
        }
    }
    Ok(())
}

fn collect_language_examples(root: &Path, directory: &Path, output: &mut BTreeSet<String>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_symlink() {
            bail!("language example layout must not contain symlinks: {}", path.display());
        }
        if file_type.is_dir() {
            collect_language_examples(root, &path, output)?;
        } else if file_type.is_file() && path.extension().is_some_and(|extension| extension == "cell") {
            let relative = path.strip_prefix(root).context("language example escaped its root")?;
            let relative =
                relative.to_str().context("language example path is not valid UTF-8")?.replace(std::path::MAIN_SEPARATOR, "/");
            output.insert(relative);
        }
    }
    Ok(())
}

pub(crate) fn prepare(root: &Path, run_dir: &Path, mode: &str) -> Result<CompileEvidence> {
    validate_example_layout(root)?;
    fs::create_dir_all(run_dir)?;
    let cellc = build_cellc(root)?;
    let artifacts = compile_matrix(root, &cellc, run_dir)?;
    let builder_contracts = builder_contracts(root, &cellc, run_dir)?;
    let report_path = run_dir.join("ckb-cellscript-acceptance-report.json");
    let report = json!({
        "status":"passed", "acceptance_mode":mode,
        "ckb_acceptance_scope":"Production mode is a hard gate and must not depend on synthetic harnesses, expected fail-closed entries, or non-original artifacts. Bounded mode is a development coverage matrix only.",
        "cellc":cellc, "source_provenance":source_provenance(root)?,
        "bundled_examples_exact_order":EXPECTED_EXAMPLES, "bundled_examples_count":EXPECTED_EXAMPLES.len(),
        "non_production_examples":EXPECTED_NON_PRODUCTION_EXAMPLES,
        "language_examples_exact_order":EXPECTED_LANGUAGE_EXAMPLES, "language_examples_count":EXPECTED_LANGUAGE_EXAMPLES.len(),
        "example_scope":{
            "production_bundled_examples":EXPECTED_EXAMPLES,
            "non_production_top_level_examples":EXPECTED_NON_PRODUCTION_EXAMPLES,
            "non_production_language_examples":EXPECTED_LANGUAGE_EXAMPLES,
            "production_scope_note":"Only production_bundled_examples are deployed and action-exercised by this CKB production acceptance report. non_production_top_level_examples and non_production_language_examples are covered by compiler/tooling tests unless promoted."
        },
        "example_source_layout":{
            "canonical_bundled_examples":root.join("examples"), "language_examples":root.join("examples/language"),
            "canonical_examples_note":"Production acceptance compiles the checked-in top-level examples/*.cell directly. examples/business and examples/acceptance are intentionally absent."
        },
        "lock_acceptance_scope":{
            "strict_compile_only":true, "onchain_lock_spend_matrix":false,
            "pending_onchain_lock_spend_matrix":expected_lock_scope(),
            "required_cases_per_lock_when_promoted":["valid_spend","invalid_spend"],
            "scope_note":"Scoped lock entries are strict-compiled under the CKB profile before live promotion."
        },
        "ckb_elf_entry_abi_gate":elf_gate(&artifacts), "cellscript_build_reports":build_reports(&artifacts),
        "public_builder_contracts":builder_contracts,
        "bundled_examples_strict_admitted":EXPECTED_EXAMPLES,
        "strict_original_ckb_compile_policy_fail_closed":[], "strict_original_ckb_compile_unexpected_failures":[],
        "original_scoped_action_count":43, "original_scoped_lock_count":17,
        "original_scoped_action_fail_closed_count":0, "original_scoped_lock_fail_closed_count":0,
        "original_scoped_action_fail_closed":[], "original_scoped_lock_fail_closed":[],
        "ckb_business_coverage":business_coverage(false), "production_ready":false,
        "production_gate":{
            "status":"passed", "failures":[], "requires_original_scoped_harnesses":true,
            "requires_no_expected_fail_closed_entries":true, "requires_all_bundled_examples_strict_original_ckb":true,
            "requires_ckb_elf_entry_abi_gate":true, "requires_cellscript_build_reports":true,
            "requires_public_builder_contracts":true
        },
        "onchain":{"status":"skipped","reason":"compile-only"}
    });
    write_report(&report_path, &report)?;
    Ok(CompileEvidence { report, artifacts, report_path, run_dir: run_dir.to_path_buf() })
}

pub(crate) fn write_report(path: &Path, report: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(report)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

fn default_ckb_repo(root: &Path) -> PathBuf {
    let parent = root.parent().unwrap_or(root);
    if parent.join("ckb").is_dir() {
        parent.join("ckb")
    } else {
        parent.parent().unwrap_or(parent).join("ckb")
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    root: &Path,
    ckb_repo: Option<&Path>,
    ckb_bin: Option<&Path>,
    compile_only: bool,
    stateful_scenarios: bool,
    mode: &str,
    explicit_run_dir: Option<&Path>,
    keep_node: bool,
) -> Result<i32> {
    if mode == "production" {
        let dirty = git_stdout(root, &["status", "--porcelain", "--untracked-files=all"])?;
        if !dirty.is_empty() {
            bail!("production acceptance requires a clean CellScript source tree\n{dirty}");
        }
    }
    let stamp = OffsetDateTime::now_utc().unix_timestamp();
    let managed_run = explicit_run_dir.is_none();
    let run_dir = explicit_run_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join(format!("target/ckb-cellscript-acceptance/{stamp}-{mode}-{}", std::process::id())));
    if managed_run {
        fs::create_dir_all(&run_dir)?;
        let report_root = run_dir.parent().context("managed acceptance run has no report root")?;
        let marker = format!("-{mode}-");
        let removed = prune_run_directories(root, report_root, &run_dir, &marker)?;
        if !removed.is_empty() {
            println!("CKB acceptance retention: pruned {} old {mode} run(s)", removed.len());
        }
    }
    let mut evidence = prepare(root, &run_dir, mode)?;
    if compile_only {
        if mode == "production" {
            production_evidence::run(root, &evidence.report_path, Some(root), true)?;
            eprintln!("CKB compile-only production evidence is not sufficient for external release; run without --compile-only for final hardening.");
        }
        if managed_run {
            finalize_managed_run(root, &run_dir, &evidence.report_path, mode)?;
        }
        println!("CKB CellScript {mode} compile-only acceptance passed: {}", evidence.report_path.display());
        return Ok(0);
    }
    let repo = fs::canonicalize(ckb_repo.map(Path::to_path_buf).unwrap_or_else(|| default_ckb_repo(root)))?;
    crate::ckb_acceptance_live::run(root, &repo, ckb_bin, stateful_scenarios || mode == "production", mode, keep_node, &mut evidence)?;
    if mode == "production" {
        production_evidence::run(root, &evidence.report_path, Some(root), false)?;
    }
    if managed_run {
        finalize_managed_run(root, &run_dir, &evidence.report_path, mode)?;
    }
    println!("CKB CellScript {mode} acceptance passed: {}", evidence.report_path.display());
    Ok(0)
}

fn finalize_managed_run(root: &Path, run_dir: &Path, report_path: &Path, mode: &str) -> Result<()> {
    let report_root = run_dir.parent().context("managed acceptance run has no report root")?;
    let marker = format!("-{mode}-");
    let stats = deduplicate_run(root, report_root, run_dir, &marker)?;
    if stats.files > 0 {
        println!("CKB acceptance deduplication: hardlinked {} duplicate file(s), {} bytes", stats.files, stats.bytes);
    }
    let status = fs::read(report_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|report| report.get("status").and_then(Value::as_str).map(ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_owned());
    write_latest_index(root, &report_root.join(format!("latest-{mode}.json")), report_path, "ckb-cellscript-acceptance", mode, &status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_matrix_counts_are_stable() {
        assert_eq!(ACTION_RUNS.iter().map(|(_, _, actions)| actions.len()).sum::<usize>(), 43);
        assert_eq!(LOCKS.iter().map(|(_, locks)| locks.len()).sum::<usize>(), 17);
    }

    #[test]
    fn language_example_layout_is_semantically_classified() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        validate_example_layout(&root).expect("language example inventory must match its semantic directories");
    }

    #[test]
    fn transaction_recipe_fixture_is_native_v023() {
        fn assert_generated_scripts_use_data2(value: &Value, generated_hashes: &BTreeSet<String>) -> usize {
            match value {
                Value::Array(values) => values.iter().map(|value| assert_generated_scripts_use_data2(value, generated_hashes)).sum(),
                Value::Object(object) => {
                    let current = usize::from(
                        object.get("code_hash").and_then(Value::as_str).is_some_and(|hash| generated_hashes.contains(hash)),
                    );
                    if current == 1 {
                        assert_eq!(object.get("hash_type").and_then(Value::as_str), Some("data2"));
                    }
                    current + object.values().map(|value| assert_generated_scripts_use_data2(value, generated_hashes)).sum::<usize>()
                }
                _ => 0,
            }
        }

        let fixture: Value = serde_json::from_str(include_str!("../fixtures/ckb_acceptance/transactions-v0.23.json")).unwrap();
        assert_eq!(fixture["schema"], "cellscript-ckb-acceptance-transaction-recipes-v0.23");
        assert_eq!(fixture["action_cases"].as_array().unwrap().len(), 43);
        assert_eq!(fixture["lock_cases"].as_array().unwrap().len(), 17);
        assert_eq!(fixture["stateful_scenarios"].as_array().unwrap().len(), 26);

        let action_cases = fixture["action_cases"].as_array().unwrap();
        let generated_hashes = action_cases
            .iter()
            .chain(fixture["lock_cases"].as_array().unwrap())
            .map(|case| case["artifact_data_hash"].as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(assert_generated_scripts_use_data2(&fixture, &generated_hashes), 253);
        for (name, expected_hash) in [
            ("timelock.cell:create_absolute_lock", "0xb31446eee54243b5c538029b577c2fcfb80c4099f08e602d7d461966306b0cc0"),
            ("timelock.cell:extend_lock", "0xafd8259b7ac6da4aed5c4567cf763c3b4315f53508fc9d464cf785342266ade4"),
            ("timelock.cell:batch_create_locks", "0xfbe48618630b855e8ce67997b87de851e0b01bdee269e9071c9546cb8edf6635"),
        ] {
            let case = action_cases.iter().find(|case| case["name"] == name).unwrap();
            assert_eq!(case["artifact_data_hash"], expected_hash, "stale audited artifact identity for {name}");
        }

        for (transaction, expected_since) in [
            ("0x352b275582f167c4a2332d05c5bab89ffb39f2053dcc899f5d42f57a9f075234", &["0x2000010000000000"][..]),
            ("0xd5fa5dcfd1dc5ac7749aac58e2ccc70953e8e86adcbbd315e7d28eac991c6bbc", &["0x2000010000000000", "0x0", "0x0"][..]),
            ("0x7e40aa9553c4f2c63d5ae3732a4d57a9e697e14b8bf8428dcd99574709a66b9e", &["0x2000010000000000"][..]),
            ("0x402f7e5dd680c1d6dc63abfc07b59a2583aa577503c506bef3d00a3a9318608b", &["0x200001000000000b"][..]),
            ("0xf36de341cb16e3887aa7fca0f4421e35bc3bd224f9e39d215606a49f73dabee4", &["0x200001000000000b", "0x0", "0x0"][..]),
        ] {
            let actual_since = fixture["transactions"][transaction]["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|input| input["since"].as_str().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(actual_since, expected_since, "stale typed temporal input since for {transaction}");
        }

        const EPOCH_11_HEADER: &str = "0x690c44e7f3605a4c984edfe17dc953047114aff5e42ae1b2f108dc042a37a34d";
        for transaction in [
            "0xb74d691e2b3b09ba70b33cae3a78c04ab723fede031598d5ebbb30f3f79c8442",
            "0x5fae038da17633b4994474ccfab8cd4769b9670ca984573a047d8e73fa1321f9",
            "0xc962300d035f0d3e1a401d57d0420ee6e984c4cabc0da7cf8beae28bb3b0c040",
            "0x73908c7815c16a3a45f876d8695355d173f8d1ab68c8b7e74d2bd6d398d440ae",
            "0xc390427394790da202c9564f872551a36bcee7747e19fcc58d0eac765d7bbaae",
            "0xdfb65c7699a692c39bdba73ec0647d99c56398310465d1db372c8a63369c0c93",
            "0xf18073c9dd4436dfca5146f8b7aac0e4bfe4398b8b6f91f1727873aeef202c9d",
            "0x17606461a3d98871a31a1d2dc71e0e81e47c2fb246665a0c19f207255b32f70a",
            "0xc1992e679cdcbc64bb722f94b5d226099b2b9ead0529e4ccf45833055f369b2a",
            "0x3b5f601fb0d58eec101f8758734ca3adaa979411bc16d348e7dad955ae10f23d",
            "0x5e784733c02e52fe1d4c6996255dcfdbf2b792d69c36414970e539e90901d2b2",
            "0x0538556ab99b85f0633cbb009edcc62be34efb26015f555c59d118424785c27b",
            "0x226c0a2e34cedaa363a9d4b223982d2daf4fc419d302115e05e98396b3d68c9b",
            "0xac9d28c6d3ff7bbf0357a655c0aac471c77bb9ad97374dbc2d507eae0541a733",
            "0x8b4922b49150481d756b6c3af4236357618d9dcbff0eee4e164ff3288640e9f5",
            "0x32a7a73a12207334bbb3966a636e22d5ea60ee3dbcf4b8f0d757c90e3cc282b6",
            "0x4d6d94bf0b85a090775f7c8c7127e5b0b4d334547d299080282dac7fc94eafd9",
        ] {
            let recipe = &fixture["transactions"][transaction];
            assert_eq!(recipe["header_deps"], json!([EPOCH_11_HEADER]), "stale multisig HeaderDep for {transaction}");
            let witness = hex::decode(recipe["witnesses"][0].as_str().unwrap().trim_start_matches("0x")).unwrap();
            let reported_time = u64::from_le_bytes(witness[witness.len() - 8..].try_into().unwrap());
            assert_eq!(reported_time, 11, "multisig reported_time must match the rebound HeaderDep for {transaction}");
        }
        for lock_name in ["multisig.cell:can_execute", "multisig.cell:not_expired"] {
            let case = fixture["lock_cases"].as_array().unwrap().iter().find(|case| case["name"] == lock_name).unwrap();
            assert_eq!(case["invalid_tx"]["header_deps"], json!([EPOCH_11_HEADER]));
        }
    }
}
