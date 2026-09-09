//! Canonical same-transaction CKB-VM composition anchor for the 0.30 corpus.

use camino::Utf8Path;
use cellscript::{
    artifact::{
        compile_artifact, encode_policy_action_record, ArtifactAction, ArtifactContext, ArtifactDeclaration, ArtifactDispatch,
    },
    strip_vm_abi_trailer, CompileOptions, EntryWitnessArg, ExecutableSurfacePolicy,
};
use cellscript_ckb_adapter::policy_witness::{encode_policy_witness_bundle, PolicyScriptRole, PolicyWitnessRecord};
use ckb_testtool::{
    builtin::ALWAYS_SUCCESS,
    ckb_hash::blake2b_256,
    ckb_types::{
        bytes::Bytes,
        core::{Capacity, DepType, ScriptHashType, TransactionBuilder, TransactionView},
        packed,
        prelude::*,
    },
    context::Context,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{path::Path, process::Command};

const ORDER_SOURCE: &str = include_str!("fixtures/capability_anchor_order.cell");
const POLICY_SOURCE: &str = include_str!("fixtures/capability_anchor_policy.cell");
const TOKEN_SOURCE: &str = include_str!("fixtures/capability_anchor_token.cell");
const AUTHORIZATION_SOURCE: &str = include_str!("fixtures/capability_anchor_authorization.cell");
const POLICY_DATA: &[u8] = b"cellscript-0.30-anchor-policy";
const MAX_CYCLES: u64 = 10_000_000;

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mutation {
    None,
    AuthorizationCredential,
    TokenAmount,
    OrderAmount,
    PolicyState,
    Dependency,
}

#[derive(Debug, Deserialize)]
struct AnchorFixture {
    schema: String,
    source_files: Vec<String>,
    policy_data_hex: String,
    artifacts: usize,
    script_groups: usize,
    positive_case: String,
    adversarial_cases: Vec<AdversarialCase>,
    measured: AnchorMeasurements,
    budgets: AnchorBudgets,
}

#[derive(Debug, Deserialize)]
struct AdversarialCase {
    name: String,
    mutation: Mutation,
}

#[derive(Debug, Deserialize)]
struct AnchorMeasurements {
    cycles: u64,
    combined_elf_bytes: usize,
    max_stack_frame_bytes: u32,
    witness_bytes: usize,
    transaction_bytes: usize,
    occupied_capacity_shannons: u64,
    raw_transaction_hash: String,
    serialized_transaction_hash: String,
    protocol_bundle_hash: String,
}

#[derive(Debug, Deserialize)]
struct AnchorBudgets {
    max_cycles: u64,
    max_combined_elf_bytes: usize,
    max_stack_frame_bytes: u32,
    max_witness_bytes: usize,
    max_transaction_bytes: usize,
    max_occupied_capacity_shannons: u64,
}

struct AnchorResult {
    verification: Result<u64, String>,
    transaction: TransactionView,
    elf_bytes: usize,
    max_stack_frame_bytes: u32,
    witness_bytes: usize,
    occupied_capacity_shannons: u64,
    protocol_bundle: Option<AnchorProtocolBundleEvidence>,
}

struct AnchorProtocolBundleEvidence {
    raw_transaction_hash: String,
    serialized_transaction_hash: String,
    protocol_bundle_hash: String,
}

struct AnchorArtifactSpec<'a> {
    id: &'static str,
    result: &'a cellscript::CompileResult,
    code_out_point: &'a packed::OutPoint,
    script: &'a packed::Script,
    entry_kind: &'static str,
    entry_name: &'static str,
    script_role: &'static str,
}

fn fixture() -> AnchorFixture {
    serde_json::from_str(include_str!("fixtures/capability_anchor_cases.json")).expect("canonical anchor fixture JSON")
}

fn options() -> CompileOptions {
    CompileOptions { target: Some("riscv64-elf".to_string()), target_profile: Some("ckb".to_string()), ..CompileOptions::default() }
}

fn compile(source: &str) -> cellscript::CompileResult {
    cellscript::compile(source, options()).unwrap_or_else(|error| panic!("anchor source must compile: {error}\n{source}"))
}

fn compile_order_policy() -> cellscript::CompileResult {
    compile_artifact(
        POLICY_SOURCE,
        CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() },
        ArtifactDeclaration {
            name: "PersistentOrder".to_string(),
            context: ArtifactContext::TypeGroup { resource: "OrderState".to_string() },
            dispatch: ArtifactDispatch::PolicyWitnessV1,
            actions: [(10, "partial_fill"), (20, "settle"), (30, "cancel")]
                .into_iter()
                .map(|(tag, action)| ArtifactAction { tag, action: action.to_string() })
                .collect(),
            common_checks: Vec::new(),
        },
        ExecutableSurfacePolicy::DenyFailClosed,
    )
    .unwrap_or_else(|error| panic!("anchor order policy must compile: {error}"))
}

fn input(context: &mut Context, tag: u8, lock: packed::Script, type_script: packed::Script, amount: u64) -> packed::CellInput {
    let output = packed::CellOutput::new_builder()
        .capacity::<packed::Uint64>(100_000_000_000u64.pack())
        .lock(lock)
        .type_(Some(type_script).pack())
        .build();
    let out_point = packed::OutPoint::new_builder().tx_hash([tag; 32].pack()).build();
    context.create_cell_with_out_point(out_point.clone(), output, Bytes::copy_from_slice(&amount.to_le_bytes()));
    packed::CellInput::new_builder().previous_output(out_point).build()
}

fn output(lock: packed::Script, type_script: packed::Script) -> packed::CellOutput {
    packed::CellOutput::new_builder()
        .capacity::<packed::Uint64>(100_000_000_000u64.pack())
        .lock(lock)
        .type_(Some(type_script).pack())
        .build()
}

fn entry_witness(payload: Vec<u8>) -> Bytes {
    packed::WitnessArgs::new_builder().input_type(Some(Bytes::from(payload)).pack()).build().as_bytes()
}

fn empty_witness() -> Bytes {
    packed::WitnessArgs::new_builder().build().as_bytes()
}

fn policy_witness(
    compiled: &cellscript::CompileResult,
    type_script: &packed::Script,
    action: &str,
    args: &[EntryWitnessArg],
) -> Bytes {
    let selected = encode_policy_action_record(&compiled.metadata, &type_script.calc_script_hash().unpack(), action, args)
        .expect("selected persistent order policy action");
    entry_witness(
        encode_policy_witness_bundle(&[PolicyWitnessRecord {
            role: PolicyScriptRole::Type,
            script_hash: selected.script_hash,
            tag: selected.tag,
            args: selected.args,
        }])
        .expect("canonical persistent order policy witness bundle"),
    )
}

fn plan(owner: [u8; 32], amounts: [u64; 2]) -> Vec<u8> {
    let elements = amounts
        .into_iter()
        .map(|amount| {
            let mut element = owner.to_vec();
            element.extend_from_slice(&amount.to_le_bytes());
            element
        })
        .collect::<Vec<_>>();
    cellscript::encode_bounded_output_plan_v1(&elements, 40, 2).expect("canonical anchor output plan")
}

fn hash_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(blake2b_256(bytes)))
}

fn bytes_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn out_point_json(out_point: &packed::OutPoint) -> Value {
    let index: u32 = out_point.index().unpack();
    json!({
        "tx_hash": bytes_hex(out_point.tx_hash().as_slice()),
        "index": index,
    })
}

fn script_json(script: &packed::Script) -> Value {
    let hash_type = match u8::from(script.hash_type()) {
        0 => "data",
        1 => "type",
        2 => "data1",
        4 => "data2",
        other => panic!("anchor uses unsupported Script hash type {other}"),
    };
    json!({
        "code_hash": bytes_hex(script.code_hash().as_slice()),
        "hash_type": hash_type,
        "args": bytes_hex(&script.args().raw_data()),
    })
}

fn cell_commitment(output: &packed::CellOutput, data: &[u8]) -> String {
    let mut preimage = output.as_slice().to_vec();
    preimage.extend_from_slice(data);
    hash_hex(&preimage)
}

fn cell_json(output: &packed::CellOutput, data: &[u8]) -> Value {
    let capacity: u64 = output.capacity().unpack();
    json!({
        "cell_commitment": cell_commitment(output, data),
        "capacity": capacity,
        "lock": script_json(&output.lock()),
        "type": output.type_().to_opt().map(|script| script_json(&script)),
        "data": bytes_hex(data),
    })
}

fn witness_json(witness: &packed::Bytes) -> Value {
    let raw = witness.raw_data();
    let args = packed::WitnessArgs::from_slice(&raw).expect("anchor witnesses use canonical WitnessArgs");
    let mut object = serde_json::Map::new();
    for (field, bytes) in
        [("lock", args.lock().to_opt()), ("input_type", args.input_type().to_opt()), ("output_type", args.output_type().to_opt())]
    {
        if let Some(bytes) = bytes {
            let raw = bytes.raw_data();
            object.insert(field.to_string(), Value::String(hash_hex(&raw)));
            object.insert(format!("{field}_bytes"), Value::String(bytes_hex(&raw)));
        }
    }
    Value::Object(object)
}

fn write_anchor_artifact(root: &Path, spec: &AnchorArtifactSpec<'_>) -> Value {
    let artifact_name = format!("{}.elf", spec.id);
    let artifact_path = root.join(&artifact_name);
    let artifact_path = Utf8Path::from_path(&artifact_path).expect("UTF-8 anchor artifact path");
    spec.result.write_to_path(artifact_path).expect("write anchor artifact");
    let metadata_name = format!("{artifact_name}.meta.json");
    spec.result
        .write_metadata_to_path(Utf8Path::from_path(&root.join(&metadata_name)).expect("UTF-8 anchor metadata path"))
        .expect("write anchor metadata");
    spec.result.write_verified_artifact_sidecars(artifact_path).expect("write anchor sidecars");

    let builder_manifest = if spec.entry_kind == "action" {
        let output = Command::new(env!("CARGO_BIN_EXE_cellc"))
            .current_dir(root)
            .args(["gen-builder", "--metadata", &metadata_name, "--target", "typescript", "--action", spec.entry_name, "--output"])
            .arg(format!("{}-builder", spec.id))
            .arg("--json")
            .output()
            .expect("run generated anchor builder");
        assert!(
            output.status.success(),
            "anchor builder generation for {} failed: stdout={} stderr={}",
            spec.id,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Some(format!("{}-builder/cellscript-builder-manifest.json", spec.id))
    } else {
        None
    };
    let artifact_hash = spec.result.metadata.artifact_hash.as_deref().expect("anchor artifact hash");
    let mut files = json!({
        "artifact": artifact_name,
        "metadata": metadata_name,
        "lowering_record": format!("{}.elf.lowering.json", spec.id),
        "source_map": format!("{}.elf.sourcemap.json", spec.id),
    });
    if let Some(builder_manifest) = builder_manifest {
        files["builder_manifest"] = Value::String(builder_manifest);
    }
    json!({
        "id": spec.id,
        "package_coordinate": format!("acceptance/{}@0.30.0", spec.id),
        "lock_node_id": format!("{}@0.30.0|path:tests/fixtures|env=anchor|features=default", spec.id),
        "entry": { "kind": spec.entry_kind, "name": spec.entry_name },
        "script_role": spec.script_role,
        "files": files,
        "deployment": {
            "network": {
                "chain_id": "ckb-dev-anchor",
                "genesis_hash": format!("0x{}", "0".repeat(64)),
            },
            "artifact_hash": artifact_hash,
            "script": script_json(spec.script),
            "code_cell_dep": {
                "out_point": out_point_json(spec.code_out_point),
                "dep_type": "code",
            },
        },
    })
}

fn builder_assumption_evidence(
    specs: &[AnchorArtifactSpec<'_>],
    transaction: &TransactionView,
    outputs: &[Value],
    occupied_capacity_shannons: u64,
) -> Value {
    let output_capacities = outputs
        .iter()
        .enumerate()
        .map(|(index, output)| json!({ "index": index, "capacity": output["capacity"] }))
        .collect::<Vec<_>>();
    let mut evidence = serde_json::Map::new();
    for spec in specs {
        let metadata = serde_json::to_value(&spec.result.metadata).expect("serialize anchor metadata");
        let Some(assumptions) = metadata["runtime"]["builder_assumptions"].as_array() else {
            continue;
        };
        for assumption in assumptions {
            if assumption["kind"] != "capacity_policy" {
                continue;
            }
            let assumption_id = assumption["assumption_id"].as_str().expect("capacity assumption id");
            evidence.insert(
                assumption_id.to_string(),
                json!({
                    "assumption_id": assumption_id,
                    "kind": assumption["kind"],
                    "origin": assumption["origin"],
                    "feature": assumption["feature"],
                    "proof_plan_status": assumption["proof_plan_status"],
                    "evidence": {
                        "outputs": output_capacities,
                        "occupied_capacity_shannons": occupied_capacity_shannons,
                        "tx_size_bytes": transaction.data().serialized_size_in_block(),
                        "under_capacity_output_indexes": [],
                    },
                }),
            );
        }
    }
    Value::Object(evidence)
}

fn check_anchor_protocol_bundle(
    context: &Context,
    transaction: &TransactionView,
    cycles: u64,
    specs: &[AnchorArtifactSpec<'_>],
    order_plan: &[u8],
    occupied_capacity_shannons: u64,
) -> AnchorProtocolBundleEvidence {
    let directory = tempfile::tempdir().expect("anchor ProtocolBundle directory");
    let root = directory.path();
    let artifacts = specs.iter().map(|spec| write_anchor_artifact(root, spec)).collect::<Vec<_>>();

    let inputs = transaction
        .inputs()
        .into_iter()
        .map(|input| {
            let out_point = input.previous_output();
            let (output, data) = context.get_cell(&out_point).expect("anchor live input");
            let mut cell = cell_json(&output, &data);
            cell["out_point"] = out_point_json(&out_point);
            let since: u64 = input.since().unpack();
            cell["since"] = json!(since);
            cell
        })
        .collect::<Vec<_>>();
    let outputs = transaction
        .outputs()
        .into_iter()
        .enumerate()
        .map(|(index, output)| cell_json(&output, &transaction.outputs_data().get(index).expect("anchor output data").raw_data()))
        .collect::<Vec<_>>();
    let witnesses = transaction.witnesses().into_iter().map(|witness| witness_json(&witness)).collect::<Vec<_>>();
    let cell_deps = transaction
        .cell_deps()
        .into_iter()
        .map(|dep| {
            json!({
                "out_point": out_point_json(&dep.out_point()),
                "dep_type": match u8::from(dep.dep_type()) { 0 => "code", 1 => "dep_group", other => panic!("unsupported dep type {other}") },
            })
        })
        .collect::<Vec<_>>();
    let dep_index = |out_point: &packed::OutPoint| {
        transaction
            .cell_deps()
            .into_iter()
            .position(|dep| dep.out_point() == *out_point)
            .expect("artifact code CellDep in anchor transaction")
    };
    let input_commitment = |index: usize| inputs[index]["cell_commitment"].clone();
    let witness_commitment = |index: usize| witnesses[index]["input_type"].clone();
    let roles = vec![
        json!({
            "artifact": "token", "name": "asset-input", "location": "input", "index": 0,
            "ownership": "exclusive", "expected_type": script_json(specs[2].script), "cell_commitment": input_commitment(0),
        }),
        json!({
            "artifact": "authorization", "name": "authorized-input", "location": "input", "index": 0,
            "ownership": "shared-read", "expected_lock": script_json(specs[3].script), "cell_commitment": input_commitment(0),
        }),
        json!({
            "artifact": "order", "name": "order-input-zero", "location": "input", "index": 1,
            "ownership": "exclusive", "expected_type": script_json(specs[0].script), "cell_commitment": input_commitment(1),
        }),
        json!({
            "artifact": "order", "name": "order-input-one", "location": "input", "index": 2,
            "ownership": "exclusive", "expected_type": script_json(specs[0].script), "cell_commitment": input_commitment(2),
        }),
        json!({
            "artifact": "policy", "name": "policy-input", "location": "input", "index": 3,
            "ownership": "exclusive", "expected_type": script_json(specs[1].script), "cell_commitment": input_commitment(3),
        }),
    ];
    let witness_claims = vec![
        json!({
            "artifact": "authorization", "name": "authorization-args", "index": 0, "field": "input_type",
            "ownership": "exclusive-write", "abi": specs[3].result.metadata.compatibility_profile.entry_witness_payload_abi,
            "value_commitment": witness_commitment(0),
        }),
        json!({
            "artifact": "order", "name": "settlement-plan", "index": 1, "field": "input_type",
            "ownership": "exclusive-write", "abi": specs[0].result.metadata.compatibility_profile.entry_witness_payload_abi,
            "value_commitment": witness_commitment(1),
        }),
        json!({
            "artifact": "policy", "name": "policy-dispatch", "index": 3, "field": "input_type",
            "ownership": "exclusive-write", "abi": specs[1].result.metadata.compatibility_profile.entry_witness_payload_abi,
            "value_commitment": witness_commitment(3),
        }),
    ];
    let dep_claims = specs
        .iter()
        .map(|spec| {
            let index = dep_index(spec.code_out_point);
            json!({
                "artifact": spec.id,
                "name": format!("{}-code", spec.id),
                "index": index,
                "cell_dep": cell_deps[index],
            })
        })
        .collect::<Vec<_>>();
    let input = json!({
        "schema": "cellscript-protocol-bundle-input-v1",
        "network": {
            "chain_id": "ckb-dev-anchor",
            "genesis_hash": format!("0x{}", "0".repeat(64)),
        },
        "artifacts": artifacts,
        "transaction": {
            "version": 0,
            "inputs": inputs,
            "outputs": outputs,
            "witnesses": witnesses,
            "cell_deps": cell_deps,
            "header_deps": [],
            "fee_policy_hash": format!("0x{}", "f5".repeat(32)),
            "change_policy_hash": format!("0x{}", "c6".repeat(32)),
            "bounded_output_plan_evidence": [{
                "schema": "cellscript-bounded-output-plan-evidence-v1",
                "version": 1,
                "action": "settle",
                "binding": "plans",
                "witness_index": 1,
                "witness_field": "input_type",
                "plan_payload": bytes_hex(order_plan),
                "current_script_hash": bytes_hex(specs[0].script.calc_script_hash().as_slice()),
                "group_output_indexes": [1, 3],
            }],
            "builder_assumption_evidence": builder_assumption_evidence(specs, transaction, &outputs, occupied_capacity_shannons),
        },
        "roles": roles,
        "witnesses": witness_claims,
        "cell_deps": dep_claims,
    });
    let input: cellscript::protocol_bundle::ProtocolBundleInput =
        serde_json::from_value(input).expect("canonical anchor ProtocolBundle input");
    let report = cellscript::protocol_bundle::check_protocol_bundle(&input, root).expect("check canonical anchor ProtocolBundle");
    assert_eq!(
        report.status, "ok",
        "anchor ProtocolBundle conflicts: {:#?}; metadata validation: {:#?}",
        report.conflicts, report.evidence.metadata_transaction_validation
    );
    assert!(report.conflicts.is_empty());
    let report_bytes = serde_json::to_vec(&report).expect("serialize anchor ProtocolBundle report");
    let (materialized, materialization) = cellscript_ckb_adapter::materialize_protocol_bundle_report(&report_bytes)
        .expect("materialize canonical anchor ProtocolBundle");
    assert_eq!(materialized.data().as_slice(), transaction.data().as_slice(), "ProtocolBundle must materialize the executed bytes");
    assert_eq!(materialization.script_groups.len(), specs.len());
    assert!(materialization.script_groups.iter().all(|group| group.direct_script_group));
    assert!(materialization
        .script_groups
        .iter()
        .all(|group| group.transaction_bytes_hash == materialization.serialized_transaction_hash));
    let dry_run = cellscript_ckb_adapter::protocol_bundle_dry_run_evidence(
        &materialized,
        &materialization,
        &ckb_testtool::ckb_jsonrpc_types::EstimateCycles { cycles: cycles.into() },
    )
    .expect("bind anchor CKB-VM result to ProtocolBundle transaction");
    assert_eq!(dry_run.aggregate_cycles, cycles);
    assert_eq!(dry_run.direct_script_group_count, specs.len());
    assert!(dry_run.groups.iter().all(|group| group.acceptance == "accepted-by-aggregate-estimate-cycles"));

    AnchorProtocolBundleEvidence {
        raw_transaction_hash: materialization.raw_transaction_hash,
        serialized_transaction_hash: materialization.serialized_transaction_hash,
        protocol_bundle_hash: materialization.bundle_hash,
    }
}

fn run_anchor(mutation: Mutation) -> AnchorResult {
    assert_eq!(
        blake2b_256(POLICY_DATA),
        [
            0xe4, 0xce, 0xeb, 0x43, 0x42, 0x0a, 0x26, 0xba, 0x80, 0x79, 0x48, 0xa9, 0x36, 0x22, 0x17, 0xd0, 0xb2, 0x5b, 0x61, 0x4f,
            0xbe, 0x2c, 0x23, 0xc5, 0x3d, 0x4b, 0xdf, 0xf8, 0xb8, 0xef, 0x96, 0x60,
        ]
    );

    let order = compile(ORDER_SOURCE);
    let policy = compile_order_policy();
    let token = compile(TOKEN_SOURCE);
    let authorization = compile(AUTHORIZATION_SOURCE);
    assert_eq!(order.metadata.typed_semantics.foundation.entry_contract.exact_entry, "action:settle");
    assert_eq!(policy.metadata.typed_semantics.foundation.entry_contract.exact_entry, "wrapper:_cellscript_entry");
    assert_eq!(token.metadata.typed_semantics.foundation.entry_contract.exact_entry, "action:preserve");
    assert_eq!(authorization.metadata.typed_semantics.foundation.entry_contract.exact_entry, "lock:authorize");
    for artifact in [&order, &policy, &token, &authorization] {
        artifact.validate().expect("each anchor artifact must pass independent validation");
    }

    let order_elf = &order.artifact_bytes;
    let policy_elf = &policy.artifact_bytes;
    let token_elf = &token.artifact_bytes;
    let authorization_elf = &authorization.artifact_bytes;
    let elf_bytes = order_elf.len() + policy_elf.len() + token_elf.len() + authorization_elf.len();
    let max_stack_frame_bytes = [&order, &policy, &token, &authorization]
        .into_iter()
        .flat_map(|artifact| artifact.verified_lowering_record.iter().flat_map(|record| &record.entries))
        .map(|entry| entry.frame_size_bytes)
        .max()
        .expect("anchor lowering records contain entry stack frames");

    let mut context = Context::new_with_deterministic_rng();
    context.set_capture_debug(true);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let order_out_point = context.deploy_cell(Bytes::copy_from_slice(order_elf));
    let policy_out_point = context.deploy_cell(Bytes::copy_from_slice(policy_elf));
    let token_out_point = context.deploy_cell(Bytes::copy_from_slice(token_elf));
    let authorization_out_point = context.deploy_cell(Bytes::copy_from_slice(authorization_elf));
    let dependency_data = if matches!(mutation, Mutation::Dependency) {
        Bytes::from_static(b"substituted-anchor-policy")
    } else {
        Bytes::from_static(POLICY_DATA)
    };
    let dependency_out_point = context.deploy_cell(dependency_data);

    let always_success_lock = context.build_script(&always_success_out_point, Bytes::new()).unwrap();
    let order_type = context.build_script_with_hash_type(&order_out_point, ScriptHashType::Data2, Bytes::new()).unwrap();
    let policy_type = context.build_script_with_hash_type(&policy_out_point, ScriptHashType::Data2, Bytes::new()).unwrap();
    let token_type = context.build_script_with_hash_type(&token_out_point, ScriptHashType::Data2, Bytes::new()).unwrap();
    let authorization_lock =
        context.build_script_with_hash_type(&authorization_out_point, ScriptHashType::Data2, Bytes::new()).unwrap();

    let inputs = vec![
        input(&mut context, 0x41, authorization_lock.clone(), token_type.clone(), 50),
        input(&mut context, 0x42, always_success_lock.clone(), order_type.clone(), 10),
        input(&mut context, 0x43, always_success_lock.clone(), order_type.clone(), 20),
        input(&mut context, 0x44, always_success_lock.clone(), policy_type.clone(), 30),
    ];
    let outputs = vec![
        output(authorization_lock.clone(), token_type.clone()),
        output(always_success_lock.clone(), order_type.clone()),
        output(always_success_lock.clone(), policy_type.clone()),
        output(always_success_lock.clone(), order_type.clone()),
    ];
    let output_amounts: [u64; 4] = [
        if matches!(mutation, Mutation::TokenAmount) { 51 } else { 50 },
        if matches!(mutation, Mutation::OrderAmount) { 13 } else { 12 },
        if matches!(mutation, Mutation::PolicyState) { 19 } else { 18 },
        18,
    ];
    let outputs_data = output_amounts.into_iter().map(|amount| Bytes::copy_from_slice(&amount.to_le_bytes())).collect::<Vec<_>>();

    let authorization_payload = authorization.metadata.locks[0]
        .entry_witness_args(&[EntryWitnessArg::U64(if matches!(mutation, Mutation::AuthorizationCredential) { 41 } else { 42 })])
        .expect("authorization entry payload");
    let order_plan = plan(always_success_lock.calc_script_hash().unpack(), [12, 18]);
    let order_payload = order.metadata.actions[0]
        .entry_witness_args(&[EntryWitnessArg::Bytes(order_plan.clone())])
        .expect("bounded settlement output plan entry payload");
    let policy_payload = policy_witness(
        &policy,
        &policy_type,
        "partial_fill",
        &[EntryWitnessArg::U64(12), EntryWitnessArg::Address(always_success_lock.calc_script_hash().unpack())],
    );
    let witnesses = [entry_witness(authorization_payload), entry_witness(order_payload), empty_witness(), policy_payload];
    let witness_bytes = witnesses.iter().map(Bytes::len).sum();
    let occupied_capacity_shannons = outputs
        .iter()
        .zip(&outputs_data)
        .map(|(cell, data)| {
            cell.occupied_capacity(Capacity::bytes(data.len()).expect("output data capacity"))
                .expect("occupied output capacity")
                .as_u64()
        })
        .sum();

    let transaction = context.complete_tx(
        TransactionBuilder::default()
            .inputs(inputs)
            .outputs(outputs)
            .outputs_data(outputs_data.pack())
            .witnesses(witnesses.pack())
            .cell_dep(packed::CellDep::new_builder().out_point(dependency_out_point.clone()).dep_type(DepType::Code).build())
            .build(),
    );
    let verification = context.verify_tx(&transaction, MAX_CYCLES).map_err(|error| format!("{error:#?}"));
    let protocol_bundle = verification.as_ref().ok().copied().filter(|_| matches!(mutation, Mutation::None)).map(|cycles| {
        let specs = [
            AnchorArtifactSpec {
                id: "order",
                result: &order,
                code_out_point: &order_out_point,
                script: &order_type,
                entry_kind: "action",
                entry_name: "settle",
                script_role: "type",
            },
            AnchorArtifactSpec {
                id: "policy",
                result: &policy,
                code_out_point: &policy_out_point,
                script: &policy_type,
                entry_kind: "action",
                entry_name: "partial_fill",
                script_role: "type",
            },
            AnchorArtifactSpec {
                id: "token",
                result: &token,
                code_out_point: &token_out_point,
                script: &token_type,
                entry_kind: "action",
                entry_name: "preserve",
                script_role: "type",
            },
            AnchorArtifactSpec {
                id: "authorization",
                result: &authorization,
                code_out_point: &authorization_out_point,
                script: &authorization_lock,
                entry_kind: "lock",
                entry_name: "authorize",
                script_role: "lock",
            },
        ];
        check_anchor_protocol_bundle(&context, &transaction, cycles, &specs, &order_plan, occupied_capacity_shannons)
    });
    AnchorResult {
        verification,
        transaction,
        elf_bytes,
        max_stack_frame_bytes,
        witness_bytes,
        occupied_capacity_shannons,
        protocol_bundle,
    }
}

#[test]
fn canonical_anchor_executes_four_cellscript_artifacts_in_one_transaction() {
    let fixture = fixture();
    assert_eq!(fixture.schema, "cellscript-capability-anchor-fixture-v1");
    assert_eq!(
        fixture.source_files,
        [
            "tests/fixtures/capability_anchor_order.cell",
            "tests/fixtures/capability_anchor_policy.cell",
            "tests/fixtures/capability_anchor_token.cell",
            "tests/fixtures/capability_anchor_authorization.cell",
        ]
    );
    assert_eq!(fixture.policy_data_hex, format!("0x{}", hex::encode(POLICY_DATA)));
    assert_eq!(fixture.artifacts, 4);
    assert_eq!(fixture.script_groups, 5);
    assert_eq!(fixture.positive_case, "settle_two_orders");
    let result = run_anchor(Mutation::None);
    let cycles = result.verification.expect("the canonical same-transaction anchor must pass");
    let transaction_bytes = result.transaction.data().serialized_size_in_block();
    assert_eq!(cycles, fixture.measured.cycles, "recorded anchor cycle measurement is stale");
    assert_eq!(result.elf_bytes, fixture.measured.combined_elf_bytes, "recorded anchor ELF measurement is stale");
    assert_eq!(
        result.max_stack_frame_bytes, fixture.measured.max_stack_frame_bytes,
        "recorded anchor stack-frame measurement is stale"
    );
    assert_eq!(result.witness_bytes, fixture.measured.witness_bytes, "recorded anchor witness measurement is stale");
    assert_eq!(transaction_bytes, fixture.measured.transaction_bytes, "recorded anchor transaction measurement is stale");
    assert_eq!(
        result.occupied_capacity_shannons, fixture.measured.occupied_capacity_shannons,
        "recorded anchor occupied-capacity measurement is stale"
    );
    let protocol_bundle = result.protocol_bundle.expect("canonical anchor ProtocolBundle evidence");
    assert_eq!(
        protocol_bundle.raw_transaction_hash, fixture.measured.raw_transaction_hash,
        "recorded anchor raw transaction hash is stale"
    );
    assert_eq!(
        protocol_bundle.serialized_transaction_hash, fixture.measured.serialized_transaction_hash,
        "recorded anchor serialized transaction hash is stale"
    );
    assert_eq!(
        protocol_bundle.protocol_bundle_hash, fixture.measured.protocol_bundle_hash,
        "recorded anchor ProtocolBundle hash is stale"
    );
    assert!(cycles > 0 && cycles <= fixture.budgets.max_cycles, "anchor cycles outside the recorded budget: {cycles}");
    assert!(result.elf_bytes <= fixture.budgets.max_combined_elf_bytes, "combined anchor ELF bytes regressed: {}", result.elf_bytes);
    assert!(
        result.max_stack_frame_bytes <= fixture.budgets.max_stack_frame_bytes,
        "anchor stack frame regressed: {}",
        result.max_stack_frame_bytes
    );
    assert!(result.witness_bytes <= fixture.budgets.max_witness_bytes, "anchor witness bytes regressed: {}", result.witness_bytes);
    assert!(transaction_bytes <= fixture.budgets.max_transaction_bytes, "anchor transaction bytes regressed: {transaction_bytes}");
    assert!(
        result.occupied_capacity_shannons <= fixture.budgets.max_occupied_capacity_shannons,
        "anchor occupied capacity regressed: {}",
        result.occupied_capacity_shannons
    );
}

#[test]
fn persistent_order_policy_uses_prior_outputs_for_partial_fill_settle_and_cancel() {
    let policy = compile_order_policy();
    let policy_elf = strip_vm_abi_trailer(&policy.artifact_bytes);
    let mut context = Context::new_with_deterministic_rng();
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let policy_out_point = context.deploy_cell(Bytes::copy_from_slice(policy_elf));
    let lock = context.build_script(&always_success_out_point, Bytes::new()).unwrap();
    let type_script = context.build_script(&policy_out_point, Bytes::new()).unwrap();
    let state_cell = output(lock.clone(), type_script.clone());
    let initial_data = Bytes::copy_from_slice(&30u64.to_le_bytes());
    let successor_data = Bytes::copy_from_slice(&18u64.to_le_bytes());

    let initial = context.create_cell(state_cell.clone(), initial_data.clone());
    let partial_fill = context.complete_tx(
        TransactionBuilder::default()
            .input(packed::CellInput::new_builder().previous_output(initial).build())
            .output(state_cell.clone())
            .output_data(successor_data.clone().pack())
            .witness(
                policy_witness(
                    &policy,
                    &type_script,
                    "partial_fill",
                    &[EntryWitnessArg::U64(12), EntryWitnessArg::Address(lock.calc_script_hash().unpack())],
                )
                .pack(),
            )
            .build(),
    );
    context.verify_tx(&partial_fill, MAX_CYCLES).expect("partial fill policy step must pass");
    let successor = packed::OutPoint::new(partial_fill.hash(), 0);
    context.create_cell_with_out_point(successor.clone(), state_cell.clone(), successor_data.clone());
    assert_eq!(context.get_cell(&successor), Some((state_cell.clone(), successor_data)));

    let terminal_output =
        packed::CellOutput::new_builder().capacity::<packed::Uint64>(100_000_000_000u64.pack()).lock(lock.clone()).build();
    let settle = context.complete_tx(
        TransactionBuilder::default()
            .input(packed::CellInput::new_builder().previous_output(successor.clone()).build())
            .output(terminal_output.clone())
            .output_data(Bytes::new().pack())
            .witness(policy_witness(&policy, &type_script, "settle", &[]).pack())
            .build(),
    );
    assert_eq!(settle.inputs().get(0).unwrap().previous_output(), successor);
    context.verify_tx(&settle, MAX_CYCLES).expect("settle must consume the verified partial-fill output");

    let cancel_input = context.create_cell(state_cell.clone(), initial_data.clone());
    let cancel = context.complete_tx(
        TransactionBuilder::default()
            .input(packed::CellInput::new_builder().previous_output(cancel_input).build())
            .output(terminal_output)
            .output_data(Bytes::new().pack())
            .witness(policy_witness(&policy, &type_script, "cancel", &[]).pack())
            .build(),
    );
    context.verify_tx(&cancel, MAX_CYCLES).expect("cancel terminal action must pass");

    let invalid_input = context.create_cell(state_cell.clone(), initial_data);
    let invalid_fill = context.complete_tx(
        TransactionBuilder::default()
            .input(packed::CellInput::new_builder().previous_output(invalid_input).build())
            .output(state_cell)
            .output_data(Bytes::copy_from_slice(&0u64.to_le_bytes()).pack())
            .witness(
                policy_witness(
                    &policy,
                    &type_script,
                    "partial_fill",
                    &[EntryWitnessArg::U64(30), EntryWitnessArg::Address(lock.calc_script_hash().unpack())],
                )
                .pack(),
            )
            .build(),
    );
    context.verify_tx(&invalid_fill, MAX_CYCLES).expect_err("a non-partial fill must reject");
}

#[test]
fn canonical_anchor_rejects_each_role_and_dependency_substitution() {
    let fixture = fixture();
    assert_eq!(fixture.adversarial_cases.len(), 5);
    for case in fixture.adversarial_cases {
        assert!(run_anchor(case.mutation).verification.is_err(), "{} ({:?}) must fail the full transaction", case.name, case.mutation);
    }
}
