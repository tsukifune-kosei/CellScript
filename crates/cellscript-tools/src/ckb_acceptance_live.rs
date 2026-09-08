use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use ckb_jsonrpc_types::Transaction as JsonTransaction;
use ckb_types::{
    bytes::Bytes,
    core::ScriptHashType,
    packed,
    prelude::{Builder, Entity, Pack, Unpack},
};
use serde_json::{json, Map, Value};

use crate::ckb_acceptance::{self, ArtifactRecord, CompileEvidence};
use crate::ckb_devnet::{
    always_success_dep, always_success_lock, decode_hex, deploy_code, entry_witness_input_type_hex, funding_cells, hex0x, out_point,
    resolve_ckb_bin, sha256_hex, transaction, CkbDevnet, ALWAYS_SUCCESS_CODE_HASH,
};
use crate::evidence_retention::{keep_gate_workdirs, remove_directory_if_present};
use crate::production_evidence::{ACTION_RUNS, EXPECTED_END_TO_END_STATEFUL_SCENARIOS, EXPECTED_EXAMPLES, LOCKS};

const RECIPES: &str = include_str!("../fixtures/ckb_acceptance/transactions-v0.23.json");
const BOUNDED_GROUP_INPUT_FIXTURE: &str = include_str!("../../../tests/fixtures/bounded_group_input_v1.json");
const BOUNDED_OUTPUT_PLAN_FIXTURE: &str = include_str!("../../../tests/fixtures/bounded_output_plan_v1.json");
const PINNED_CKB_CXXFLAGS: &str = "-include cstdint";
const PINNED_CKB_CXX_COMPATIBILITY: &str = "ckb-librocksdb-sys-8.5.4-explicit-cstdint-v1";

struct TransientBuildDirectory {
    path: PathBuf,
    remove_on_drop: bool,
}

impl Drop for TransientBuildDirectory {
    fn drop(&mut self) {
        if self.remove_on_drop {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn production_ckb_build_command(ckb_repo: &Path, target: &Path) -> Command {
    let mut command = Command::new("cargo");
    command
        .args(["build", "--locked", "--bin", "ckb", "--target-dir"])
        .arg(target)
        .current_dir(ckb_repo)
        // The CKB 0.207.0 pin resolves ckb-librocksdb-sys 8.5.4. Its
        // trace_record.h uses fixed-width integers without including
        // <cstdint>; current C++ toolchains no longer provide that header
        // transitively. Inject the missing standard header without patching
        // the clean, pinned CKB checkout.
        .env("CXXFLAGS", PINNED_CKB_CXXFLAGS);
    command
}

fn command_stdout(root: &Path, program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program).args(args).current_dir(root).output()?;
    if !output.status.success() {
        bail!("{program} {} failed: {}", args.join(" "), String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn parse_hex_u64(value: &Value) -> Result<u64> {
    let text = value.as_str().context("expected hex quantity")?;
    Ok(u64::from_str_radix(text.trim_start_matches("0x"), 16)?)
}

fn file_sha256(path: &Path) -> Result<String> {
    Ok(sha256_hex(&fs::read(path)?))
}

fn build_ckb(root: &Path, ckb_repo: &Path, ckb_bin: Option<&Path>, mode: &str, run_dir: &Path) -> Result<PathBuf> {
    if mode != "production" {
        return resolve_ckb_bin(ckb_repo, ckb_bin);
    }
    if ckb_bin.is_some() {
        bail!("production acceptance does not accept --ckb-bin; the pinned source must be rebuilt");
    }
    let target = run_dir.join(".ckb-build-target");
    let _target_cleanup = TransientBuildDirectory { path: target.clone(), remove_on_drop: !keep_gate_workdirs()? };
    let output = production_ckb_build_command(ckb_repo, &target).output()?;
    if !output.status.success() {
        bail!(
            "fresh pinned CKB build failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let built = target.join("debug/ckb");
    let archived = run_dir.join("ckb-runtime/ckb");
    fs::create_dir_all(archived.parent().unwrap())?;
    fs::copy(&built, &archived).with_context(|| format!("archive {}", built.display()))?;
    let _ = root;
    Ok(fs::canonicalize(archived)?)
}

fn verify_pin(root: &Path, ckb_repo: &Path, mode: &str) -> Result<Value> {
    let pin_path = root.join("scripts/ckb_acceptance_pin.json");
    let pin: Value = serde_json::from_slice(&fs::read(&pin_path)?)?;
    if mode == "production" {
        let head = command_stdout(ckb_repo, "git", &["rev-parse", "HEAD"])?;
        if pin["revision"] != head {
            bail!("CKB revision mismatch: checkout={head}, pin={}", pin["revision"]);
        }
        let dirty = command_stdout(ckb_repo, "git", &["status", "--porcelain", "--untracked-files=all"])?;
        if !dirty.is_empty() {
            bail!("CKB acceptance requires a clean pinned checkout: {}\n{dirty}", ckb_repo.display());
        }
    }
    for template in pin["template_paths"].as_array().context("pin template_paths missing")? {
        let path = ckb_repo.join(template.as_str().context("pin template path must be a string")?);
        if !path.is_file() {
            bail!("pinned CKB template is missing: {}", path.display());
        }
    }
    Ok(pin)
}

fn deployment_evidence(artifact: &ArtifactRecord, deployment: &Value) -> Value {
    json!({
        "run_name":artifact.name, "run_kind":artifact.kind,
        "tx_hash":deployment["commit"]["tx_hash"], "output_index":"0x0",
        "out_point":deployment["cell_dep"]["out_point"], "code_cell_live":true,
        "artifact_ckb_data_hash_blake2b":artifact.data_hash,
        "live_code_cell_data_hash":artifact.data_hash, "live_code_cell_data_hash_matches_artifact":true
    })
}

struct Replayer<'a> {
    devnet: &'a mut CkbDevnet,
    fixture: &'a Value,
    deployments: &'a BTreeMap<String, Value>,
    always_dep: Value,
    old_to_new: BTreeMap<String, String>,
}

impl Replayer<'_> {
    fn transaction(&self, old_hash: &str) -> Result<Value> {
        self.fixture["transactions"][old_hash]
            .as_object()
            .map(|object| Value::Object(object.clone()))
            .with_context(|| format!("transaction recipe missing for {old_hash}"))
    }

    fn replay_recursive(&mut self, old_hash: &str, label: &str) -> Result<Value> {
        if let Some(new_hash) = self.old_to_new.get(old_hash) {
            return Ok(json!({"tx_hash":new_hash,"status":{"status":"committed"},"generated_blocks_after_submit":0}));
        }
        let tx = self.rebind(old_hash)?;
        self.devnet.dry_run(&tx).with_context(|| format!("dry-run replay {label}"))?;
        let commit = self.devnet.submit_and_commit(&tx, label)?;
        self.old_to_new.insert(old_hash.to_owned(), commit["tx_hash"].as_str().unwrap().to_owned());
        Ok(commit)
    }

    fn rebind(&mut self, old_hash: &str) -> Result<Value> {
        let mut tx = self.transaction(old_hash)?;
        tx.as_object_mut().unwrap().remove("hash");
        let inputs = tx["inputs"].as_array_mut().context("recipe inputs missing")?;
        for input in inputs {
            let previous = input["previous_output"]["tx_hash"].as_str().context("recipe input hash missing")?.to_owned();
            let replacement = if let Some(hash) = self.old_to_new.get(&previous) {
                json!({"tx_hash":hash,"index":input["previous_output"]["index"]})
            } else if self.fixture["transactions"].get(&previous).is_some() {
                let commit = self.replay_recursive(&previous, &format!("ancestor {previous}"))?;
                json!({"tx_hash":commit["tx_hash"],"index":input["previous_output"]["index"]})
            } else {
                let funding = self.devnet.find_spendable()?;
                out_point(funding["tx_hash"].as_str().unwrap(), funding["index"].as_u64().unwrap())
            };
            input["previous_output"] = replacement;
        }
        let deps = tx["cell_deps"].as_array_mut().context("recipe cell_deps missing")?;
        for dep in deps {
            let old_tx = dep["out_point"]["tx_hash"].as_str().context("cell dep hash missing")?.to_owned();
            let index = dep["out_point"]["index"].as_str().context("cell dep index missing")?.to_owned();
            if let Some(mapped) = self.old_to_new.get(&old_tx) {
                dep["out_point"]["tx_hash"] = json!(mapped);
                continue;
            }
            if self.fixture["transactions"].get(&old_tx).is_some() {
                let commit = self.replay_recursive(&old_tx, &format!("cell-dep ancestor {old_tx}"))?;
                dep["out_point"]["tx_hash"] = commit["tx_hash"].clone();
                continue;
            }
            let key = format!("{old_tx}:{index}");
            let data_hash = self.fixture["cell_deps"][&key]["data_hash"]
                .as_str()
                .with_context(|| format!("cell-dep identity missing for {key}"))?;
            let replacement = if data_hash == ALWAYS_SUCCESS_CODE_HASH {
                self.always_dep.clone()
            } else {
                self.deployments
                    .get(data_hash)
                    .with_context(|| format!("no current artifact deployment matches recipe dependency {data_hash} ({key})"))?
                    ["cell_dep"]
                    .clone()
            };
            *dep = replacement;
        }
        let old_headers = tx["header_deps"].as_array().context("recipe header_deps missing")?.clone();
        let mut headers = Vec::new();
        for old_header in old_headers {
            let old_header = old_header.as_str().context("header dep must be a string")?;
            let number = parse_hex_u64(&self.fixture["headers"][old_header]["number"])?;
            loop {
                let tip = self.devnet.rpc("get_tip_header", vec![])?;
                if parse_hex_u64(&tip["number"])? >= number {
                    break;
                }
                self.devnet.rpc("generate_block", vec![])?;
            }
            let block = self.devnet.get_block_by_number(number)?;
            headers.push(block["header"]["hash"].clone());
        }
        tx["header_deps"] = Value::Array(headers);
        self.balance_change_capacity(&mut tx).with_context(|| format!("balance rebound transaction {old_hash}"))?;
        Ok(tx)
    }

    fn balance_change_capacity(&mut self, tx: &mut Value) -> Result<()> {
        let mut input_capacity = 0_u64;
        for input in tx["inputs"].as_array().context("transaction inputs missing")? {
            let live = self.devnet.rpc("get_live_cell", vec![input["previous_output"].clone(), json!(false)])?;
            if live["status"] != "live" {
                bail!("rebound input is not live: {}", input["previous_output"]);
            }
            input_capacity =
                input_capacity.checked_add(parse_hex_u64(&live["cell"]["output"]["capacity"])?).context("input capacity overflow")?;
        }
        let outputs = tx["outputs"].as_array().context("transaction outputs missing")?;
        let output_capacity =
            outputs.iter().try_fold(0_u64, |total, output| Ok::<_, anyhow::Error>(total + parse_hex_u64(&output["capacity"])?))?;
        if input_capacity >= output_capacity {
            return Ok(());
        }
        let outputs_data = tx["outputs_data"].as_array().context("transaction outputs_data missing")?;
        let candidate = outputs
            .iter()
            .zip(outputs_data)
            .enumerate()
            .rev()
            .find(|(_, (output, data))| {
                output["lock"]["code_hash"] == ALWAYS_SUCCESS_CODE_HASH
                    && output["type"].is_null()
                    && data.as_str().is_some_and(|value| value == "0x")
            })
            .map(|(index, _)| index);
        const ALWAYS_SUCCESS_EMPTY_OCCUPIED: u64 = 4_100_000_000;
        if let Some(candidate) = candidate {
            let old_change = parse_hex_u64(&outputs[candidate]["capacity"])?;
            let fixed = output_capacity - old_change;
            if let Some(new_change) = input_capacity.checked_sub(fixed)
                && new_change >= ALWAYS_SUCCESS_EMPTY_OCCUPIED
            {
                tx["outputs"][candidate]["capacity"] = json!(format!("0x{new_change:x}"));
                return Ok(());
            }
        }

        // Some recipe transactions intentionally have no disposable change
        // output: every output is a typed scenario cell. A replacement
        // cellbase input can be smaller than the original fixture input, so
        // add fresh always-success funding instead of mutating scenario state.
        let deficit = output_capacity - input_capacity;
        let funding = self.devnet.collect_spendable(deficit)?;
        let inputs = tx["inputs"].as_array_mut().context("transaction inputs missing")?;
        for cell in funding_cells(&funding) {
            inputs.push(json!({
                "previous_output": out_point(
                    cell["tx_hash"].as_str().context("funding transaction hash missing")?,
                    cell["index"].as_u64().context("funding output index missing")?,
                ),
                "since": "0x0",
            }));
        }
        Ok(())
    }
}

fn rejection(devnet: &CkbDevnet, tx: &Value, label: &str, data_hash: &str, error_code: Option<i64>) -> Result<Value> {
    let value = devnet.dry_run_rejects(tx, label, Some("Inputs[0].Lock"), Some(data_hash), error_code)?;
    Ok(json!({
        "status":"rejected", "check":"dry_run_transaction", "reason":value["reason"],
        "expected_reason_matched":value["matched_expected"], "policy_or_capacity_reason":false
    }))
}

fn invalidate_action(tx: &Value, fixture: &Value, old_hash: &str) -> Result<Value> {
    let mut invalid = tx.clone();
    let witnesses = invalid["witnesses"].as_array_mut().context("transaction witnesses missing")?;
    if witnesses.is_empty() {
        witnesses.push(json!("0x00"));
    } else {
        let raw = witnesses[0].as_str().unwrap_or("0x");
        let mut bytes = decode_hex(raw)?;
        if bytes.is_empty() {
            bytes.push(0);
        } else {
            bytes[0] ^= 0xff;
        }
        witnesses[0] = json!(format!("0x{}", hex::encode(bytes)));
    }
    let old_tx = &fixture["transactions"][old_hash];
    let fallback_cell = old_tx["inputs"].as_array().and_then(|inputs| inputs.first()).and_then(|input| {
        let hash = input["previous_output"]["tx_hash"].as_str()?;
        let index = parse_hex_u64(&input["previous_output"]["index"]).ok()? as usize;
        Some((fixture["transactions"][hash]["outputs"][index].clone(), fixture["transactions"][hash]["outputs_data"][index].clone()))
    });
    let fallback_data = fallback_cell.as_ref().and_then(|(_, data)| data.as_str()).unwrap_or("0x00").to_owned();
    let all_output_data_empty = invalid["outputs_data"]
        .as_array()
        .is_some_and(|values| values.iter().all(|value| value.as_str().is_none_or(|value| value == "0x")));
    if all_output_data_empty
        && let Some((cell, _)) = &fallback_cell
        && let Some(output) = invalid["outputs"].as_array_mut().and_then(|values| values.first_mut())
    {
        output["type"] = cell["type"].clone();
    }
    for output_data in invalid["outputs_data"].as_array_mut().context("transaction outputs_data missing")? {
        let mut bytes = decode_hex(output_data.as_str().unwrap_or("0x"))?;
        if bytes.is_empty() {
            *output_data = json!(if fallback_data == "0x" { "0x00" } else { &fallback_data });
        } else {
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            *output_data = json!(format!("0x{}", hex::encode(bytes)));
        }
    }
    Ok(invalid)
}

fn measured_constraints(template: &Value, tx: &Value, dry_run: &Value) -> Result<Value> {
    let mut measured = template.clone();
    let cycles = parse_hex_u64(&dry_run["cycles"])?;
    let json_tx: JsonTransaction =
        serde_json::from_value(tx.clone()).context("transaction recipe is not valid CKB transaction JSON")?;
    let packed_tx: packed::Transaction = json_tx.into();
    let outputs = tx["outputs"].as_array().context("transaction outputs missing")?;
    let outputs_data = tx["outputs_data"].as_array().context("transaction outputs_data missing")?;
    if outputs.len() != outputs_data.len() {
        bail!("transaction output/data length mismatch: {} != {}", outputs.len(), outputs_data.len());
    }
    let output_capacities = outputs.iter().map(|output| parse_hex_u64(&output["capacity"])).collect::<Result<Vec<_>>>()?;
    let occupied_capacities = outputs
        .iter()
        .zip(outputs_data)
        .map(|(output, data)| {
            let script_bytes = |script: &Value| -> Result<u64> {
                if script.is_null() {
                    return Ok(0);
                }
                Ok(33 + u64::try_from(decode_hex(script["args"].as_str().context("script args missing")?)?.len())?)
            };
            let data_bytes = u64::try_from(decode_hex(data.as_str().context("output data must be hex")?)?.len())?;
            Ok((8 + script_bytes(&output["lock"])? + script_bytes(&output["type"])? + data_bytes) * 100_000_000)
        })
        .collect::<Result<Vec<_>>>()?;
    let under_capacity = output_capacities
        .iter()
        .zip(&occupied_capacities)
        .enumerate()
        .filter_map(|(index, (capacity, occupied))| (capacity < occupied).then_some(index))
        .collect::<Vec<_>>();
    let capacity_is_sufficient = under_capacity.is_empty();
    let output_data_bytes = outputs_data
        .iter()
        .map(|data| decode_hex(data.as_str().unwrap_or("0x")).map(|bytes| bytes.len()))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum::<usize>();
    let witness_bytes = tx["witnesses"]
        .as_array()
        .context("transaction witnesses missing")?
        .iter()
        .map(|witness| decode_hex(witness.as_str().unwrap_or("0x")).map(|bytes| bytes.len()))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum::<usize>();
    measured["measured_cycles"] = json!(cycles);
    measured["cycles_status"] = json!("dry-run-measured");
    measured["consensus_serialized_tx_size_bytes"] = json!(packed_tx.as_bytes().len());
    measured["json_envelope_size_bytes"] = json!(serde_json::to_vec(tx)?.len());
    measured["input_count"] = json!(tx["inputs"].as_array().map_or(0, Vec::len));
    measured["output_count"] = json!(outputs.len());
    measured["cell_dep_count"] = json!(tx["cell_deps"].as_array().map_or(0, Vec::len));
    measured["header_dep_count"] = json!(tx["header_deps"].as_array().map_or(0, Vec::len));
    measured["witness_count"] = json!(tx["witnesses"].as_array().map_or(0, Vec::len));
    measured["witness_bytes"] = json!(witness_bytes);
    measured["output_data_bytes"] = json!(output_data_bytes);
    measured["measured_output_capacity_shannons"] = json!(output_capacities);
    measured["output_capacity_shannons"] = json!(output_capacities.iter().sum::<u64>());
    measured["output_occupied_capacity_shannons"] = json!(occupied_capacities);
    measured["occupied_capacity_shannons"] = json!(occupied_capacities.iter().sum::<u64>());
    measured["under_capacity_output_indexes"] = json!(under_capacity);
    measured["capacity_is_sufficient"] = json!(capacity_is_sufficient);
    Ok(measured)
}

fn code_report(artifact: &ArtifactRecord, deployment: &Value) -> Value {
    json!({
        "artifact":artifact.path, "artifact_size_bytes":artifact.bytes.len(),
        "artifact_ckb_data_hash_blake2b":artifact.data_hash,
        "code_cell_dep":deployment["cell_dep"], "code_cell_deploy":deployment["commit"],
        "code_cell_live":true, "live_code_cell_data_hash":artifact.data_hash,
        "live_code_cell_data_hash_matches_artifact":true, "deploy_attempts":1
    })
}

fn action_group_key(example: &str) -> Result<&'static str> {
    ACTION_RUNS
        .iter()
        .find(|(_, candidate, _)| *candidate == example)
        .map(|(key, _, _)| *key)
        .with_context(|| format!("unknown action example {example}"))
}

fn replay_actions(
    replayer: &mut Replayer<'_>,
    fixture: &Value,
    artifacts: &BTreeMap<String, ArtifactRecord>,
) -> Result<BTreeMap<String, Vec<Value>>> {
    let mut groups = BTreeMap::<String, Vec<Value>>::new();
    for case in fixture["action_cases"].as_array().context("action_cases missing")? {
        let name = case["name"].as_str().context("action case name missing")?;
        let (example, _) = name.split_once(':').context("invalid action case name")?;
        let artifact = artifacts.get(name).with_context(|| format!("compiled action artifact missing for {name}"))?;
        let expected_hash = case["artifact_data_hash"].as_str().context("action fixture artifact hash missing")?;
        if artifact.data_hash != expected_hash {
            bail!("{name} artifact changed from audited transaction recipe: {} != {expected_hash}", artifact.data_hash);
        }
        let deployment = replayer.deployments.get(&artifact.data_hash).unwrap();
        let initial_old = case["initial_tx"].as_str().unwrap();
        replayer.replay_recursive(initial_old, &format!("{name} initial cells"))?;
        let valid_old = case["valid_tx"].as_str().unwrap();
        let valid_tx = replayer.rebind(valid_old)?;
        let invalid_tx = invalidate_action(&valid_tx, fixture, valid_old)?;
        let malformed = rejection(replayer.devnet, &invalid_tx, &format!("{name} malformed action"), &artifact.data_hash, None)?;
        let dry_run = replayer.devnet.dry_run(&valid_tx)?;
        let commit = replayer.devnet.submit_and_commit(&valid_tx, &format!("{name} valid action"))?;
        replayer.old_to_new.insert(valid_old.to_owned(), commit["tx_hash"].as_str().unwrap().to_owned());
        let mut output_live = Vec::new();
        for index in 0..valid_tx["outputs"].as_array().unwrap().len() {
            replayer.devnet.wait_live_cell(commit["tx_hash"].as_str().unwrap(), index as u64)?;
            output_live.push(true);
        }
        let row = json!({
            "name":name, "action":case["action"], "status":"passed", "builder_backed":false,
            "transaction_origin":"acceptance-rust-harness", "harness_origin":"rust-transaction-recipe-replay",
            "acceptance_harness_name":case["acceptance_harness_name"],
            "acceptance_harness_implementation":case["acceptance_harness_implementation"],
            "public_builder_contract_id":name, "public_builder_contract_verified":true,
            "artifact":artifact.path, "code":code_report(artifact, deployment),
            "malformed_transaction":malformed, "valid_dry_run":dry_run,
            "valid_commit":commit, "valid_outputs_live":output_live,
            "measured_constraints":measured_constraints(&case["measured_constraints"], &valid_tx, &dry_run)?
        });
        groups.entry(action_group_key(example)?.to_owned()).or_default().push(row);
    }
    Ok(groups)
}

fn replay_locks(replayer: &mut Replayer<'_>, fixture: &Value, artifacts: &BTreeMap<String, ArtifactRecord>) -> Result<Vec<Value>> {
    let mut rows = Vec::new();
    for case in fixture["lock_cases"].as_array().context("lock_cases missing")? {
        let name = case["name"].as_str().context("lock case name missing")?;
        let artifact = artifacts.get(name).with_context(|| format!("compiled lock artifact missing for {name}"))?;
        let expected_hash = case["artifact_data_hash"].as_str().unwrap();
        if artifact.data_hash != expected_hash {
            bail!("{name} artifact changed from audited transaction recipe: {} != {expected_hash}", artifact.data_hash);
        }
        let deployment = replayer.deployments.get(&artifact.data_hash).unwrap();

        let invalid_create = case["invalid_create_tx"].as_str().unwrap();
        replayer.replay_recursive(invalid_create, &format!("{name} invalid input create"))?;
        let mut invalid_tx = case["invalid_tx"].clone();
        invalid_tx.as_object_mut().unwrap().remove("hash");
        // The stored invalid transaction is rebound through a temporary recipe entry.
        let synthetic = format!("invalid:{name}");
        let mut fixture_with_invalid = replayer.fixture.clone();
        fixture_with_invalid["transactions"][&synthetic] = invalid_tx;
        let rebound_invalid = {
            let mut nested = Replayer {
                devnet: replayer.devnet,
                fixture: &fixture_with_invalid,
                deployments: replayer.deployments,
                always_dep: replayer.always_dep.clone(),
                old_to_new: replayer.old_to_new.clone(),
            };
            let tx = nested.rebind(&synthetic)?;
            replayer.old_to_new = nested.old_to_new;
            tx
        };
        let invalid_rejection =
            rejection(replayer.devnet, &rebound_invalid, &format!("{name} invalid lock spend"), &artifact.data_hash, Some(5))?;
        let invalid_input_hash = rebound_invalid["inputs"][0]["previous_output"]["tx_hash"].as_str().unwrap();
        let invalid_input_index = parse_hex_u64(&rebound_invalid["inputs"][0]["previous_output"]["index"])?;
        let live = replayer.devnet.wait_live_cell(invalid_input_hash, invalid_input_index)?;

        let valid_create = case["valid_create_tx"].as_str().unwrap();
        replayer.replay_recursive(valid_create, &format!("{name} valid input create"))?;
        let valid_old = case["valid_tx"].as_str().unwrap();
        let valid_tx = replayer.rebind(valid_old)?;
        let dry_run = replayer.devnet.dry_run(&valid_tx)?;
        let commit = replayer.devnet.submit_and_commit(&valid_tx, &format!("{name} valid lock spend"))?;
        replayer.old_to_new.insert(valid_old.to_owned(), commit["tx_hash"].as_str().unwrap().to_owned());
        replayer.devnet.wait_live_cell(commit["tx_hash"].as_str().unwrap(), 0)?;
        rows.push(json!({
            "name":name, "example":case["example"], "lock":case["lock"], "status":"passed",
            "kind":"original-scoped-lock-strict", "builder_backed":false,
            "transaction_origin":"acceptance-rust-harness", "harness_origin":"rust-transaction-recipe-replay",
            "acceptance_harness_name":case["acceptance_harness_name"],
            "acceptance_harness_implementation":case["acceptance_harness_implementation"],
            "artifact":artifact.path, "code":code_report(artifact, deployment),
            "valid_spend":{"status":"passed","dry_run":dry_run,"commit":commit,"output_live":true},
            "invalid_spend":{"status":"rejected","rejection":invalid_rejection,"input_cells_live_after_rejection":[live["status"] == "live"]},
            "measured_constraints":measured_constraints(&case["measured_constraints"], &valid_tx, &dry_run)?
        }));
    }
    Ok(rows)
}

fn replay_scenarios(replayer: &mut Replayer<'_>, fixture: &Value) -> Result<Value> {
    let mut runs = Vec::new();
    let mut covered = BTreeSet::new();
    let mut step_count = 0_usize;
    for scenario in fixture["stateful_scenarios"].as_array().context("stateful_scenarios missing")? {
        let name = scenario["name"].as_str().unwrap();
        let mut steps = Vec::new();
        for step in scenario["steps"].as_array().unwrap() {
            let old_hash = step["old_tx_hash"].as_str().unwrap();
            let tx = replayer.rebind(old_hash)?;
            let dry_run = replayer.devnet.dry_run(&tx)?;
            let consumed = tx["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|input| json!({"tx_hash":input["previous_output"]["tx_hash"],"index":input["previous_output"]["index"]}))
                .collect::<Vec<_>>();
            let commit = replayer.devnet.submit_and_commit(&tx, &format!("{name}:{}", step["step"].as_str().unwrap()))?;
            replayer.old_to_new.insert(old_hash.to_owned(), commit["tx_hash"].as_str().unwrap().to_owned());
            let mut consumed_status = Vec::new();
            for input in consumed {
                let status = replayer
                    .devnet
                    .rpc("get_live_cell", vec![json!({"tx_hash":input["tx_hash"],"index":input["index"]}), json!(false)])?;
                consumed_status.push(status);
            }
            let mut outputs_live = Map::new();
            for index in 0..tx["outputs"].as_array().unwrap().len() {
                replayer.devnet.wait_live_cell(commit["tx_hash"].as_str().unwrap(), index as u64)?;
                outputs_live.insert(index.to_string(), json!(true));
            }
            steps.push(json!({
                "step":step["step"], "status":"passed", "dry_run":dry_run, "commit":commit,
                "measured_constraints":measured_constraints(&step["measured_constraints"], &tx, &dry_run)?,
                "consumed_inputs":consumed_status, "outputs_live":outputs_live
            }));
            step_count += 1;
        }
        for action in scenario["action_ids"].as_array().unwrap() {
            covered.insert(action.as_str().unwrap().to_owned());
        }
        runs.push(json!({
            "name":name, "kind":scenario["kind"], "status":"passed", "builder_backed":false,
            "transaction_origin":"acceptance-rust-harness", "harness_origin":"rust-transaction-recipe-replay",
            "acceptance_harness_name":"rust-transaction-recipe-replayer-v0.23",
            "action_ids":scenario["action_ids"], "steps":steps
        }));
    }
    let mut required = ACTION_RUNS
        .iter()
        .flat_map(|(_, example, actions)| actions.iter().map(move |action| format!("{example}:{action}")))
        .collect::<Vec<_>>();
    required.sort();
    let covered = covered.into_iter().collect::<Vec<_>>();
    if covered != required {
        bail!("stateful recipe action coverage mismatch");
    }
    let leading =
        runs.iter().take(EXPECTED_END_TO_END_STATEFUL_SCENARIOS.len()).map(|row| row["name"].as_str().unwrap()).collect::<Vec<_>>();
    if leading != EXPECTED_END_TO_END_STATEFUL_SCENARIOS {
        bail!("stateful end-to-end scenario order changed: {leading:?}");
    }
    Ok(json!({
        "status":"passed", "scenario_count":runs.len(),
        "end_to_end_scenario_count":EXPECTED_END_TO_END_STATEFUL_SCENARIOS.len(),
        "action_branch_scenario_count":runs.len()-EXPECTED_END_TO_END_STATEFUL_SCENARIOS.len(),
        "step_count":step_count, "runs":runs,
        "stateful_action_coverage":{
            "status":"passed", "required_action_count":required.len(), "covered_action_count":covered.len(),
            "required_action_ids":required, "covered_action_ids":covered,
            "missing_action_ids":[], "missing_artifact_ids":[], "unexpected_artifact_ids":[]
        }
    }))
}

fn runtime_provenance(
    root: &Path,
    ckb_repo: &Path,
    ckb_bin: &Path,
    devnet: &CkbDevnet,
    pin: &Value,
    genesis_hash: &str,
    mode: &str,
) -> Result<Value> {
    let pin_path = root.join("scripts/ckb_acceptance_pin.json");
    let templates = pin["template_paths"].as_array().unwrap();
    let source_config = ckb_repo.join(templates[0].as_str().unwrap());
    let source_spec = ckb_repo.join(templates[1].as_str().unwrap());
    let effective_config = devnet.ckb_dir.join("ckb.toml");
    let effective_spec = devnet.ckb_dir.join("specs/integration.toml");
    let version = command_stdout(ckb_repo, ckb_bin.to_str().unwrap(), &["--version"])?;
    if mode == "production"
        && (!version.contains(pin["version"].as_str().unwrap()) || !version.contains(&pin["revision"].as_str().unwrap()[..7]))
    {
        bail!("CKB executable provenance mismatch: {version}");
    }
    Ok(json!({
        "schema":"cellscript-ckb-runtime-provenance-v0.22", "pin_schema":pin["schema"],
        "pin_file_sha256":file_sha256(&pin_path)?, "repository":pin["repository"],
        "revision":pin["revision"], "repo_head":command_stdout(ckb_repo,"git",&["rev-parse","HEAD"])? ,
        "repo_dirty":!command_stdout(ckb_repo,"git",&["status","--porcelain","--untracked-files=all"])?.is_empty(),
        "version":pin["version"], "version_output":version,
        "build_mode":if mode=="production" {"fresh-dedicated-cargo-target"} else {"bounded-existing-binary"},
        "cxxflags":if mode=="production" {PINNED_CKB_CXXFLAGS} else {"not-applied-bounded-existing-binary"},
        "cxx_compatibility_contract":if mode=="production" {PINNED_CKB_CXX_COMPATIBILITY} else {"not-applied-bounded-existing-binary"},
        "binary_archived_with_report":mode=="production", "binary_path":ckb_bin,
        "binary_sha256":file_sha256(ckb_bin)?, "source_template_path":source_config,
        "source_template_sha256":file_sha256(&source_config)?, "source_spec_path":source_spec,
        "source_spec_sha256":file_sha256(&source_spec)?, "effective_config_path":effective_config,
        "effective_config_sha256":file_sha256(&effective_config)?, "effective_spec_path":effective_spec,
        "effective_spec_sha256":file_sha256(&effective_spec)?, "genesis_hash":genesis_hash
    }))
}

fn group_actions(groups: &BTreeMap<String, Vec<Value>>, key: &str) -> Vec<Value> {
    groups.get(key).cloned().unwrap_or_default()
}

fn bounded_group_input_script(artifact: &ArtifactRecord) -> Value {
    json!({"code_hash":artifact.data_hash,"hash_type":"data2","args":"0x"})
}

fn seed_bounded_group_input_case(
    devnet: &mut CkbDevnet,
    case: &Value,
    artifact: &ArtifactRecord,
    deployment: &Value,
    always_dep: &Value,
) -> Result<(Value, Vec<Value>)> {
    const CELL_CAPACITY: u64 = 10_000_000_000;
    const CHANGE_FLOOR: u64 = 5_000_000_000;
    let fixture_inputs = case["inputs"].as_array().context("bounded GroupInput case inputs missing")?;
    let synthetic_zero = fixture_inputs.is_empty();
    let output_count = fixture_inputs.len().max(1);
    let needed = u64::try_from(output_count)?
        .checked_mul(CELL_CAPACITY)
        .and_then(|value| value.checked_add(CHANGE_FLOOR))
        .context("bounded GroupInput seed capacity overflow")?;
    let funding = devnet.collect_spendable(needed)?;
    let total = funding["total_capacity"].as_u64().context("bounded GroupInput funding total missing")?;
    let current_type = bounded_group_input_script(artifact);
    let foreign_type = always_success_lock("0x");
    let mut outputs = Vec::new();
    let mut outputs_data = Vec::new();
    let mut seeded = Vec::new();
    if synthetic_zero {
        outputs.push(json!({
            "capacity":format!("0x{CELL_CAPACITY:x}"),
            "lock":always_success_lock("0x"),
            "type":current_type
        }));
        outputs_data.push("0x00000000000000000100000000000000".to_string());
        seeded.push(json!({"index":0,"capacity":CELL_CAPACITY,"scope":"zero-output-only"}));
    } else {
        for (index, input) in fixture_inputs.iter().enumerate() {
            let scope = input["scope"].as_str().context("bounded GroupInput input scope missing")?;
            let type_script = if scope == "group" { current_type.clone() } else { foreign_type.clone() };
            outputs.push(json!({
                "capacity":format!("0x{CELL_CAPACITY:x}"),
                "lock":always_success_lock("0x"),
                "type":type_script
            }));
            outputs_data.push(format!("0x{}", input["data_hex"].as_str().context("bounded GroupInput data missing")?));
            seeded.push(json!({"index":index,"capacity":CELL_CAPACITY,"scope":scope}));
        }
    }
    let allocated = u64::try_from(output_count)?.checked_mul(CELL_CAPACITY).context("seed allocation overflow")?;
    let change = total.checked_sub(allocated).context("bounded GroupInput seed funding is insufficient")?;
    outputs.push(json!({
        "capacity":format!("0x{change:x}"),
        "lock":always_success_lock("0x"),
        "type":Value::Null
    }));
    outputs_data.push("0x".to_string());
    let tx = transaction(
        funding_cells(&funding),
        outputs,
        outputs_data,
        vec![always_dep.clone(), deployment["cell_dep"].clone()],
        vec!["0x".to_string(); funding_cells(&funding).len()],
        vec![],
    );
    let dry_run = devnet.dry_run(&tx)?;
    let name = case["name"].as_str().context("bounded GroupInput case name missing")?;
    let commit = devnet.submit_and_commit(&tx, &format!("bounded GroupInput seed {name}"))?;
    let tx_hash = commit["tx_hash"].as_str().context("bounded GroupInput seed hash missing")?;
    for cell in &mut seeded {
        let index = cell["index"].as_u64().context("bounded GroupInput seed index missing")?;
        devnet.wait_live_cell(tx_hash, index)?;
        cell["tx_hash"] = json!(tx_hash);
    }
    Ok((
        json!({
            "status":"committed",
            "dry_run":dry_run,
            "commit":commit,
            "output_only_zero_group_execution":synthetic_zero
        }),
        seeded,
    ))
}

fn run_bounded_group_input_acceptance(
    devnet: &mut CkbDevnet,
    artifact: &ArtifactRecord,
    deployment: &Value,
    always_dep: &Value,
) -> Result<Value> {
    let fixture: Value = serde_json::from_str(BOUNDED_GROUP_INPUT_FIXTURE)?;
    if fixture["schema"] != "cellscript-bounded-group-input-fixture-v1" {
        bail!("unexpected bounded GroupInput fixture schema");
    }
    let cases = fixture["cases"].as_array().context("bounded GroupInput fixture cases missing")?;
    let mut runs = Vec::new();
    for case in cases {
        let name = case["name"].as_str().context("bounded GroupInput case name missing")?;
        let expected_exit = case["expected_exit"].as_i64().context("bounded GroupInput expected exit missing")?;
        let (seed, seeded) = seed_bounded_group_input_case(devnet, case, artifact, deployment, always_dep)?;
        if case["inputs"].as_array().is_some_and(Vec::is_empty) {
            runs.push(json!({
                "name":name,
                "status":"passed",
                "expected_exit":expected_exit,
                "observed_exit":0,
                "execution":"committed-output-only-type-group",
                "seed":seed,
                "selected_group_input_count":0
            }));
            continue;
        }

        let total = seeded.iter().try_fold(0_u64, |sum, cell| {
            sum.checked_add(cell["capacity"].as_u64().context("bounded GroupInput seed capacity missing")?)
                .context("bounded GroupInput spend capacity overflow")
        })?;
        let tx = transaction(
            &seeded,
            vec![json!({
                "capacity":format!("0x{total:x}"),
                "lock":always_success_lock("0x"),
                "type":Value::Null
            })],
            vec!["0x".to_string()],
            vec![always_dep.clone(), deployment["cell_dep"].clone()],
            vec!["0x".to_string(); seeded.len()],
            vec![],
        );
        let selected_count = seeded.iter().filter(|cell| cell["scope"] == "group").count();
        if expected_exit == 0 {
            let dry_run = devnet.dry_run(&tx)?;
            let measurements = measured_constraints(&json!({}), &tx, &dry_run)?;
            let commit = devnet.submit_and_commit(&tx, &format!("bounded GroupInput consume {name}"))?;
            for cell in &seeded {
                devnet.wait_dead_cell(
                    cell["tx_hash"].as_str().context("bounded GroupInput seed hash missing")?,
                    cell["index"].as_u64().context("bounded GroupInput seed index missing")?,
                )?;
            }
            devnet.wait_live_cell(commit["tx_hash"].as_str().context("bounded GroupInput spend hash missing")?, 0)?;
            runs.push(json!({
                "name":name,
                "status":"passed",
                "expected_exit":0,
                "observed_exit":0,
                "execution":"committed-input-type-group",
                "selected_group_input_count":selected_count,
                "seed":seed,
                "dry_run":dry_run,
                "measurements":measurements,
                "commit":commit,
                "all_seeded_inputs_dead":true
            }));
        } else {
            let rejection = devnet.dry_run_rejects(
                &tx,
                &format!("bounded GroupInput reject {name}"),
                Some("Inputs[0].Type"),
                Some(&artifact.data_hash),
                Some(expected_exit),
            )?;
            for cell in &seeded {
                devnet.wait_live_cell(
                    cell["tx_hash"].as_str().context("bounded GroupInput seed hash missing")?,
                    cell["index"].as_u64().context("bounded GroupInput seed index missing")?,
                )?;
            }
            runs.push(json!({
                "name":name,
                "status":"passed",
                "expected_exit":expected_exit,
                "observed_exit":expected_exit,
                "execution":"rejected-input-type-group",
                "selected_group_input_count":selected_count,
                "seed":seed,
                "rejection":rejection,
                "all_seeded_inputs_remain_live":true
            }));
        }
    }
    Ok(json!({
        "schema":"cellscript-bounded-group-input-stateful-acceptance-v1",
        "status":"passed",
        "fixture_schema":fixture["schema"],
        "fixture_sha256":sha256_hex(BOUNDED_GROUP_INPUT_FIXTURE.as_bytes()),
        "artifact":artifact.path,
        "artifact_ckb_data_hash_blake2b":artifact.data_hash,
        "selection":fixture["selection"],
        "order":fixture["order"],
        "logical_identity_policy":fixture["logical_identity_policy"],
        "case_count":runs.len(),
        "runs":runs
    }))
}

fn packed_script_hash(script: &Value) -> Result<[u8; 32]> {
    let code_hash: [u8; 32] = decode_hex(script["code_hash"].as_str().context("Script code_hash missing")?)?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("Script code_hash must be 32 bytes, got {}", bytes.len()))?;
    let hash_type = match script["hash_type"].as_str().context("Script hash_type missing")? {
        "data" => ScriptHashType::Data,
        "type" => ScriptHashType::Type,
        "data1" => ScriptHashType::Data1,
        "data2" => ScriptHashType::Data2,
        value => bail!("unsupported Script hash_type '{value}' in bounded output fixture"),
    };
    let args = decode_hex(script["args"].as_str().context("Script args missing")?)?;
    let packed = packed::Script::new_builder().code_hash(code_hash.pack()).hash_type(hash_type).args(Bytes::from(args).pack()).build();
    Ok(packed.calc_script_hash().unpack())
}

fn bounded_output_plan_payload(case: &Value, output_lock_hash: [u8; 32]) -> Result<Vec<u8>> {
    let plans = case["plans"].as_array().context("bounded output case plans missing")?;
    let mut inner = b"CSBPLv1\0".to_vec();
    inner.extend_from_slice(&u32::try_from(plans.len())?.to_le_bytes());
    for plan in plans {
        match plan["owner"].as_str().context("bounded output Plan owner missing")? {
            "output_lock" => inner.extend_from_slice(&output_lock_hash),
            "zero" => inner.extend_from_slice(&[0_u8; 32]),
            owner => bail!("unsupported bounded output Plan owner '{owner}'"),
        }
        inner.extend_from_slice(&plan["amount"].as_u64().context("bounded output Plan amount missing")?.to_le_bytes());
    }
    match case["codec"].as_str().context("bounded output case codec missing")? {
        "canonical" | "canonical_unchecked_count" => {}
        "wrong_magic" => inner[0] ^= 0xff,
        "trailing_byte" => inner.push(0),
        codec => bail!("unsupported bounded output fixture codec '{codec}'"),
    }
    let mut outer = b"CSARGv1\0".to_vec();
    outer.extend_from_slice(&u32::try_from(inner.len())?.to_le_bytes());
    outer.extend_from_slice(&inner);
    Ok(outer)
}

fn seed_bounded_output_plan_case(
    devnet: &mut CkbDevnet,
    case: &Value,
    artifact: &ArtifactRecord,
    deployment: &Value,
    always_dep: &Value,
) -> Result<(Value, Value)> {
    const CHANGE_FLOOR: u64 = 5_000_000_000;
    let output_capacity =
        case["outputs"].as_array().context("bounded output case outputs missing")?.iter().try_fold(0_u64, |sum, output| {
            sum.checked_add(output["capacity_shannons"].as_u64().context("bounded output capacity missing")?)
                .context("bounded output capacity sum overflow")
        })?;
    let needed = output_capacity.checked_add(CHANGE_FLOOR).context("bounded output seed capacity overflow")?;
    let funding = devnet.collect_spendable(needed)?;
    let total = funding["total_capacity"].as_u64().context("bounded output funding total missing")?;
    let trigger_lock = always_success_lock("0x");
    let trigger_lock_hash = packed_script_hash(&trigger_lock)?;
    let seed_plan = json!({
        "plans":[{"owner":"output_lock","amount":1}],
        "codec":"canonical"
    });
    let seed_payload = bounded_output_plan_payload(&seed_plan, trigger_lock_hash)?;
    let mut witnesses = vec!["0x".to_string(); funding_cells(&funding).len()];
    witnesses[0] = entry_witness_input_type_hex(&seed_payload);
    let tx = transaction(
        funding_cells(&funding),
        vec![json!({
            "capacity":format!("0x{total:x}"),
            "lock":trigger_lock,
            "type":bounded_group_input_script(artifact)
        })],
        vec![hex0x(&1_u64.to_le_bytes())],
        vec![always_dep.clone(), deployment["cell_dep"].clone()],
        witnesses,
        vec![],
    );
    let dry_run = devnet.dry_run(&tx)?;
    let name = case["name"].as_str().context("bounded output case name missing")?;
    let commit = devnet.submit_and_commit(&tx, &format!("bounded output trigger seed {name}"))?;
    let tx_hash = commit["tx_hash"].as_str().context("bounded output seed hash missing")?;
    devnet.wait_live_cell(tx_hash, 0)?;
    Ok((json!({"status":"committed","dry_run":dry_run,"commit":commit}), json!({"tx_hash":tx_hash,"index":0,"capacity":total})))
}

fn run_bounded_output_plan_acceptance(
    devnet: &mut CkbDevnet,
    artifact: &ArtifactRecord,
    deployment: &Value,
    always_dep: &Value,
) -> Result<Value> {
    let fixture: Value = serde_json::from_str(BOUNDED_OUTPUT_PLAN_FIXTURE)?;
    if fixture["schema"] != "cellscript-bounded-output-plan-fixture-v1" {
        bail!("unexpected bounded output plan fixture schema");
    }
    let cases = fixture["cases"].as_array().context("bounded output plan fixture cases missing")?;
    let output_lock = always_success_lock("0x");
    let output_lock_hash = packed_script_hash(&output_lock)?;
    let current_type = bounded_group_input_script(artifact);
    let foreign_type = always_success_lock("0x666f726569676e");
    let mut runs = Vec::new();
    for case in cases {
        let name = case["name"].as_str().context("bounded output case name missing")?;
        let expected_exit = case["expected_exit"].as_i64().context("bounded output expected exit missing")?;
        let (seed, trigger) = seed_bounded_output_plan_case(devnet, case, artifact, deployment, always_dep)?;
        let outputs_spec = case["outputs"].as_array().context("bounded output case outputs missing")?;
        let mut outputs = Vec::new();
        let mut outputs_data = Vec::new();
        let mut allocated = 0_u64;
        let mut group_output_indexes = Vec::new();
        for (index, output) in outputs_spec.iter().enumerate() {
            let capacity = output["capacity_shannons"].as_u64().context("bounded output capacity missing")?;
            allocated = allocated.checked_add(capacity).context("bounded output allocation overflow")?;
            let scope = output["scope"].as_str().context("bounded output scope missing")?;
            let type_script = if scope == "group" {
                group_output_indexes.push(index);
                current_type.clone()
            } else if scope == "outside_group" {
                foreign_type.clone()
            } else {
                bail!("unsupported bounded output scope '{scope}'");
            };
            if output["lock"] != "output_lock" {
                bail!("unsupported bounded output fixture Lock selector");
            }
            outputs.push(json!({
                "capacity":format!("0x{capacity:x}"),
                "lock":output_lock,
                "type":type_script
            }));
            outputs_data.push(hex0x(&output["amount"].as_u64().context("bounded output amount missing")?.to_le_bytes()));
        }
        let total = trigger["capacity"].as_u64().context("bounded output trigger capacity missing")?;
        let change = total.checked_sub(allocated).context("bounded output trigger cannot fund outputs")?;
        outputs.push(json!({
            "capacity":format!("0x{change:x}"),
            "lock":always_success_lock("0x"),
            "type":Value::Null
        }));
        outputs_data.push("0x".to_string());
        let payload = bounded_output_plan_payload(case, output_lock_hash)?;
        let tx = transaction(
            std::slice::from_ref(&trigger),
            outputs,
            outputs_data,
            vec![always_dep.clone(), deployment["cell_dep"].clone()],
            vec![entry_witness_input_type_hex(&payload)],
            vec![],
        );
        if expected_exit == 0 {
            let dry_run = devnet.dry_run(&tx)?;
            let measurements = measured_constraints(&json!({}), &tx, &dry_run)?;
            let commit = devnet.submit_and_commit(&tx, &format!("bounded output plan commit {name}"))?;
            devnet.wait_dead_cell(
                trigger["tx_hash"].as_str().context("bounded output trigger hash missing")?,
                trigger["index"].as_u64().context("bounded output trigger index missing")?,
            )?;
            let tx_hash = commit["tx_hash"].as_str().context("bounded output commit hash missing")?;
            for index in &group_output_indexes {
                devnet.wait_live_cell(tx_hash, u64::try_from(*index)?)?;
            }
            runs.push(json!({
                "name":name,
                "status":"passed",
                "expected_exit":0,
                "observed_exit":0,
                "execution":"committed-ordered-group-outputs",
                "plan_count":case["plans"].as_array().map(Vec::len).unwrap_or(0),
                "group_output_indexes":group_output_indexes,
                "seed":seed,
                "dry_run":dry_run,
                "measurements":measurements,
                "commit":commit,
                "trigger_input_dead":true,
                "group_outputs_live":true
            }));
        } else {
            let rejection = devnet.dry_run_rejects(
                &tx,
                &format!("bounded output plan reject {name}"),
                Some("Inputs[0].Type"),
                Some(&artifact.data_hash),
                Some(expected_exit),
            )?;
            devnet.wait_live_cell(
                trigger["tx_hash"].as_str().context("bounded output trigger hash missing")?,
                trigger["index"].as_u64().context("bounded output trigger index missing")?,
            )?;
            runs.push(json!({
                "name":name,
                "status":"passed",
                "expected_exit":expected_exit,
                "observed_exit":expected_exit,
                "execution":"rejected-ordered-group-outputs",
                "plan_count":case["plans"].as_array().map(Vec::len).unwrap_or(0),
                "group_output_indexes":group_output_indexes,
                "seed":seed,
                "rejection":rejection,
                "trigger_input_remains_live":true
            }));
        }
    }
    Ok(json!({
        "schema":"cellscript-bounded-output-plan-stateful-acceptance-v1",
        "status":"passed",
        "fixture_schema":fixture["schema"],
        "fixture_sha256":sha256_hex(BOUNDED_OUTPUT_PLAN_FIXTURE.as_bytes()),
        "artifact":artifact.path,
        "artifact_ckb_data_hash_blake2b":artifact.data_hash,
        "selection":fixture["selection"],
        "order":fixture["order"],
        "correspondence":fixture["correspondence"],
        "identity_policy":fixture["identity_policy"],
        "equal_plan_bytes_allowed":fixture["equal_plan_bytes_allowed"],
        "case_count":runs.len(),
        "runs":runs
    }))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run(
    root: &Path,
    ckb_repo: &Path,
    configured_ckb_bin: Option<&Path>,
    stateful: bool,
    mode: &str,
    keep_node: bool,
    evidence: &mut CompileEvidence,
) -> Result<()> {
    let fixture: Value = serde_json::from_str(RECIPES)?;
    if fixture["schema"] != "cellscript-ckb-acceptance-transaction-recipes-v0.23" {
        bail!("unexpected CKB acceptance transaction recipe schema");
    }
    let pin = verify_pin(root, ckb_repo, mode)?;
    let ckb_bin = build_ckb(root, ckb_repo, configured_ckb_bin, mode, &evidence.run_dir)?;
    let mut devnet = CkbDevnet::new(ckb_repo.to_path_buf(), ckb_bin.clone(), evidence.run_dir.clone())?;
    devnet.start()?;
    let genesis = devnet.get_block_by_number(0)?;
    let genesis_hash = genesis["header"]["hash"].as_str().context("genesis hash missing")?.to_owned();
    let genesis_cellbase = genesis["transactions"][0]["hash"].as_str().context("genesis cellbase missing")?.to_owned();
    let always_dep = always_success_dep(&genesis_cellbase);

    let mut deployments = BTreeMap::<String, Value>::new();
    let mut artifact_deployments = BTreeMap::<String, Value>::new();
    for artifact in &evidence.artifacts {
        let deployment = if let Some(existing) = deployments.get(&artifact.data_hash) {
            existing.clone()
        } else {
            let created = deploy_code(&mut devnet, &artifact.name, &artifact.bytes, &always_dep)?;
            deployments.insert(artifact.data_hash.clone(), created.clone());
            created
        };
        artifact_deployments.insert(artifact.path.to_string_lossy().into_owned(), deployment);
    }
    let artifact_by_name = evidence
        .artifacts
        .iter()
        .filter(|artifact| artifact.entry.is_some())
        .map(|artifact| (artifact.name.clone(), artifact.clone()))
        .collect::<BTreeMap<_, _>>();
    let bounded_group_input_report = if stateful {
        let artifact =
            artifact_by_name.get("bounded-group-input-v1:verify").context("bounded GroupInput acceptance artifact missing")?;
        let deployment = artifact_deployments
            .get(&artifact.path.to_string_lossy().into_owned())
            .context("bounded GroupInput acceptance deployment missing")?;
        run_bounded_group_input_acceptance(&mut devnet, artifact, deployment, &always_dep)?
    } else {
        json!({"status":"skipped","reason":"stateful scenarios not requested","runs":[]})
    };
    let bounded_output_plan_report = if stateful {
        let artifact =
            artifact_by_name.get("bounded-output-plan-v1:verify").context("bounded output plan acceptance artifact missing")?;
        let deployment = artifact_deployments
            .get(&artifact.path.to_string_lossy().into_owned())
            .context("bounded output plan acceptance deployment missing")?;
        run_bounded_output_plan_acceptance(&mut devnet, artifact, deployment, &always_dep)?
    } else {
        json!({"status":"skipped","reason":"stateful scenarios not requested","runs":[]})
    };
    let mut replayer = Replayer {
        devnet: &mut devnet,
        fixture: &fixture,
        deployments: &deployments,
        always_dep: always_dep.clone(),
        old_to_new: BTreeMap::new(),
    };
    let action_groups = replay_actions(&mut replayer, &fixture, &artifact_by_name)?;
    let lock_runs = replay_locks(&mut replayer, &fixture, &artifact_by_name)?;
    let stateful_report = if stateful {
        replay_scenarios(&mut replayer, &fixture)?
    } else {
        json!({"status":"skipped","reason":"stateful scenarios not requested","runs":[]})
    };

    let mut deployment_runs = Vec::new();
    for example in EXPECTED_EXAMPLES {
        let artifact = evidence
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == "bundled-example-strict-original" && artifact.example.as_deref() == Some(*example))
            .unwrap();
        let deployment = artifact_deployments.get(&artifact.path.to_string_lossy().into_owned()).unwrap();
        deployment_runs.push(json!({
            "name":example, "kind":"bundled-example-strict-original", "status":"passed",
            "artifact":artifact.path, "artifact_size_bytes":artifact.bytes.len(), "code_cell_live":true,
            "artifact_ckb_data_hash_blake2b":artifact.data_hash, "live_code_cell_data_hash":artifact.data_hash,
            "live_code_cell_data_hash_matches_artifact":true,
            "valid_deploy_dry_run":deployment["valid_deploy_dry_run"], "code_cell_dep":deployment["cell_dep"]
        }));
    }

    let build_index = evidence.report["cellscript_build_reports"].as_object_mut().unwrap();
    for row in build_index["reports"].as_array_mut().unwrap() {
        let path = row["artifact_path"].as_str().unwrap();
        let artifact = evidence.artifacts.iter().find(|artifact| artifact.path == Path::new(path)).unwrap();
        let deployment = artifact_deployments.get(path).unwrap();
        row["onchain_deployments"] = json!([deployment_evidence(artifact, deployment)]);
    }
    let report_count = build_index["reports"].as_array().unwrap().len();
    build_index.insert("onchain_deployed_artifact_count".into(), json!(report_count));
    build_index.insert("live_code_cell_data_hash_match_count".into(), json!(report_count));
    build_index.insert("missing_onchain_deployments".into(), json!([]));
    build_index.insert("live_code_cell_data_hash_mismatches".into(), json!([]));
    build_index.insert("unexpected_onchain_artifacts".into(), json!([]));

    let action_count = action_groups.values().map(Vec::len).sum::<usize>();
    let lock_count = lock_runs.len();
    let mut onchain = json!({
        "status":"passed", "tip_before":genesis["header"], "tip_after":replayer.devnet.rpc("get_tip_header",vec![])?,
        "genesis_hash":genesis_hash, "genesis_cellbase_hash":genesis_cellbase,
        "chain_template":replayer.devnet.ckb_dir, "always_success_system_cell_index":"0x5",
        "bundled_example_deployment_runs":deployment_runs, "bundled_examples_deployed":EXPECTED_EXAMPLES,
        "all_bundled_examples_deployed":true, "all_artifacts_deployed_and_spent":true,
        "resource_identity_evidence_scope":{
            "status":"fixture-only", "always_success_resource_types":true, "production_resource_identity_proven":false,
            "scope_note":"Acceptance resource Type Scripts are always-success fixtures; action and lock verifier behavior remains real CKB-VM evidence."
        },
        "token_action_runs":group_actions(&action_groups,"token_action_runs"),
        "nft_action_runs":group_actions(&action_groups,"nft_action_runs"),
        "timelock_action_runs":group_actions(&action_groups,"timelock_action_runs"),
        "multisig_action_runs":group_actions(&action_groups,"multisig_action_runs"),
        "vesting_action_runs":group_actions(&action_groups,"vesting_action_runs"),
        "amm_action_runs":group_actions(&action_groups,"amm_action_runs"),
        "launch_action_runs":group_actions(&action_groups,"launch_action_runs"),
        "lock_spend_matrix_runs":lock_runs, "stateful_scenarios":stateful_report,
        "bounded_group_input_acceptance":bounded_group_input_report,
        "bounded_output_plan_acceptance":bounded_output_plan_report,
        "all_token_actions_exercised":true, "all_nft_actions_exercised":true,
        "all_timelock_actions_exercised":true, "all_multisig_actions_exercised":true,
        "all_vesting_actions_exercised":true, "all_amm_actions_exercised":true,
        "all_launch_actions_exercised":true, "builder_backed_action_count":0,
        "acceptance_harness_action_count":action_count, "public_builder_contract_action_count":action_count,
        "measured_cycles_action_count":action_count, "tx_size_measured_action_count":action_count,
        "occupied_capacity_measured_action_count":action_count, "lock_spend_matrix_count":lock_count,
        "builder_backed_lock_spend_matrix_count":0, "acceptance_harness_lock_spend_matrix_count":lock_count,
        "lock_valid_spend_count":lock_count, "lock_invalid_spend_count":lock_count,
        "measured_cycles_lock_count":lock_count, "tx_size_measured_lock_count":lock_count,
        "occupied_capacity_measured_lock_count":lock_count, "all_locks_behavior_exercised":true
    });
    for (key, _, actions) in ACTION_RUNS {
        let prefix = key.trim_end_matches("_action_runs");
        onchain[format!("{prefix}_actions_exercised")] = json!(actions);
    }
    evidence.report["onchain"] = onchain;
    evidence.report["ckb_repo"] = json!(ckb_repo);
    evidence.report["ckb_bin"] = json!(ckb_bin);
    evidence.report["rpc_url"] = json!(replayer.devnet.rpc_url);
    evidence.report["ckb_log"] = json!(replayer.devnet.log_path);
    evidence.report["ckb_runtime_provenance"] =
        runtime_provenance(root, ckb_repo, &ckb_bin, replayer.devnet, &pin, &genesis_hash, mode)?;
    evidence.report["lock_acceptance_scope"] = json!({
        "strict_compile_only":false, "onchain_lock_spend_matrix":true,
        "onchain_lock_spend_matrix_scope":LOCKS.iter().map(|(example,locks)|((*example).to_owned(),json!(locks))).collect::<Map<_,_>>(),
        "required_cases_per_lock":["valid_spend","invalid_spend"],
        "scope_note":"Scoped lock entries are strict-compiled under the CKB profile and each lock is exercised through Rust transaction-recipe valid-spend and invalid-spend transactions."
    });
    evidence.report["ckb_business_coverage"] = ckb_acceptance::business_coverage(true);
    let production_ready = mode == "production";
    evidence.report["production_ready"] = json!(production_ready);
    evidence.report["status"] = json!("passed");
    evidence.report["final_production_hardening_gate"] = json!({
        "status":if production_ready { "passed" } else { "not-evaluated-in-bounded-mode" },
        "ready":production_ready, "requires_builder_generated_transactions":false,
        "requires_public_builder_contracts":true, "requires_acceptance_harness_transactions":true,
        "requires_measured_cycles":true, "requires_consensus_serialized_tx_size":true,
        "requires_exact_occupied_capacity":true, "requires_stateful_action_coverage":true,
        "production_resource_identity_claim":false, "resource_identity_evidence_scope":"always-success-fixture-only",
        "requires_build_report_live_artifact_linkage":true, "failures":[]
    });
    ckb_acceptance::write_report(&evidence.report_path, &evidence.report)?;
    if !keep_node {
        replayer.devnet.stop();
        if !keep_gate_workdirs()? {
            remove_directory_if_present(&evidence.run_dir, &replayer.devnet.ckb_dir.join("data"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use ckb_types::{packed::WitnessArgs, prelude::*};

    use super::*;

    #[test]
    fn transient_ckb_build_directory_is_removed_on_scope_exit() {
        let path = std::env::temp_dir().join(format!("cellscript-ckb-build-cleanup-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        fs::write(path.join("build-output"), b"transient").unwrap();
        {
            let _cleanup = TransientBuildDirectory { path: path.clone(), remove_on_drop: true };
        }
        assert!(!path.exists());
    }

    #[test]
    fn production_ckb_build_injects_the_pinned_cstdint_compatibility_flag() {
        let command = production_ckb_build_command(Path::new("/tmp/pinned-ckb"), Path::new("/tmp/pinned-ckb-target"));
        let cxxflags = command.get_envs().find_map(|(key, value)| (key == OsStr::new("CXXFLAGS")).then_some(value)).flatten();

        assert_eq!(cxxflags, Some(OsStr::new(PINNED_CKB_CXXFLAGS)));
        assert_eq!(PINNED_CKB_CXX_COMPATIBILITY, "ckb-librocksdb-sys-8.5.4-explicit-cstdint-v1");
    }

    fn assert_entry_witnesses(transaction: &Value, label: &str, count: &mut usize) {
        for witness in transaction["witnesses"].as_array().expect("transaction witnesses") {
            let encoded = decode_hex(witness.as_str().expect("hex witness")).expect("valid witness hex");
            if encoded.is_empty() {
                continue;
            }
            let args = WitnessArgs::from_slice(&encoded)
                .unwrap_or_else(|error| panic!("{label} witness must be Molecule WitnessArgs: {error}"));
            assert!(args.lock().to_opt().is_none(), "{label} entry witness must not occupy lock");
            assert!(args.output_type().to_opt().is_none(), "{label} entry witness must not occupy output_type");
            let payload =
                args.input_type().to_opt().unwrap_or_else(|| panic!("{label} entry witness must occupy input_type")).raw_data();
            assert!(payload.starts_with(b"CSARGv1\0"), "{label} input_type must contain a CSARG payload");
            *count += 1;
        }
    }

    #[test]
    fn acceptance_recipes_use_canonical_witness_args_input_type() {
        let fixture: Value = serde_json::from_str(RECIPES).expect("valid acceptance fixture");
        let mut count = 0;
        for (hash, transaction) in fixture["transactions"].as_object().expect("transactions") {
            assert_entry_witnesses(transaction, hash, &mut count);
        }
        for case in fixture["lock_cases"].as_array().expect("lock cases") {
            assert_entry_witnesses(&case["invalid_tx"], case["name"].as_str().expect("lock case name"), &mut count);
        }
        assert_eq!(count, 123, "the complete Edition 2026 acceptance witness matrix must be covered");
    }
}
