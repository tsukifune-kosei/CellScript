use cellscript::{compile, CompileOptions};

#[test]
fn v0_14_exposes_spawn_ipc_source_witness_time_capacity_metadata() {
    let source = r#"
module cellscript::v0_14_surface

resource Token has store {
    amount: u64,
}

resource Wallet has store {
    owner: Address,
}

struct Proof {
    pubkey: Hash,
    signature: Hash,
}

action delegate_verify(proof: Proof) -> u64 {
    let pid = spawn("secp256k1_verifier")
    let status = wait()
    assert_invariant(status == 0, "delegate failed")
    return pid
}

action pipe_pipeline(value: u64) -> u64 {
    let fds = pipe()
    let read_fd = fds.0
    let write_fd = fds.1
    pipe_write(write_fd, value)
    let echoed = pipe_read(read_fd)
    close(read_fd)
    close(write_fd)
    return echoed
}

action capacity_and_time(amount: u64) -> Token {
    require_maturity(100)
    require_time(1714000000)
    require_epoch_relative(10, 0, 1)
    let floor = occupied_capacity("Token")
    assert_invariant(floor >= 0, "capacity floor visible")
    create Token { amount }
}

lock owner_lock(wallet: protected Wallet, owner: lock_args Address, claimed_owner: witness Address) -> bool {
    let view = source::group_input(0)
    let sig = witness::lock(view)
    let digest = env::sighash_all(view)
    require owner == wallet.owner
    require sig == digest
}

lock output_witness_lock(wallet: protected Wallet, claimed_owner: witness Address) -> bool {
    let input = source::input(0)
    let output = source::group_output(0)
    let input_type = witness::input_type(input)
    let output_type = witness::output_type(output)
    require input_type == output_type
}
"#;

    let result = compile(source, CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() }).unwrap();
    let features = &result.metadata.runtime.ckb_runtime_features;
    for expected in [
        "ckb-spawn-ipc",
        "ckb-lock-args",
        "ckb-source-view",
        "ckb-witness-args",
        "ckb-sighash-all",
        "ckb-declarative-since",
        "ckb-declarative-capacity",
    ] {
        assert!(features.iter().any(|feature| feature == expected), "missing {expected}: {features:?}");
    }

    assert!(result.metadata.runtime.ckb_runtime_accesses.iter().any(|access| {
        access.operation == "witness-lock" && access.syscall == "LOAD_WITNESS_ARGS_LOCK" && access.source == "GroupInput"
    }));
    assert!(result.metadata.runtime.ckb_runtime_accesses.iter().any(|access| {
        access.operation == "lock-args"
            && access.syscall == "LOAD_SCRIPT_ARGS"
            && access.source == "ScriptArgs"
            && access.binding == "owner"
    }));
    assert!(result
        .metadata
        .runtime
        .ckb_runtime_accesses
        .iter()
        .any(|access| { access.operation == "source-input" && access.syscall == "SOURCE_VIEW" && access.source == "Input" }));
    assert!(result.metadata.runtime.ckb_runtime_accesses.iter().any(|access| {
        access.operation == "source-group-output" && access.syscall == "SOURCE_VIEW" && access.source == "GroupOutput"
    }));
    assert!(result.metadata.runtime.ckb_runtime_accesses.iter().any(|access| {
        access.operation == "witness-input-type" && access.syscall == "LOAD_WITNESS_ARGS_INPUT_TYPE" && access.source == "GroupInput"
    }));
    assert!(result.metadata.runtime.ckb_runtime_accesses.iter().any(|access| {
        access.operation == "witness-output-type"
            && access.syscall == "LOAD_WITNESS_ARGS_OUTPUT_TYPE"
            && access.source == "GroupOutput"
    }));
    assert!(result.metadata.runtime.ckb_runtime_accesses.iter().any(|access| access.operation == "spawn"));
    let delegate_verify =
        result.metadata.actions.iter().find(|action| action.name == "delegate_verify").expect("delegate_verify metadata");
    let delegate_group = delegate_verify.ckb_script_group.as_ref().expect("delegate_verify CKB script group metadata");
    assert_eq!(delegate_group.entry_kind, "action");
    assert_eq!(delegate_group.group_kind, "type");
    assert!(delegate_group.cell_dep_sources.contains(&"CellDep".to_string()));
    assert!(delegate_verify.verifier_obligations.iter().any(|obligation| {
        obligation.category == "spawn-target"
            && obligation.feature == "spawn-target:CellDep#0"
            && obligation.status == "runtime-required"
            && obligation.detail.contains("CellDep or DepGroup")
    }));
    assert!(delegate_verify.transaction_runtime_input_requirements.iter().any(|requirement| {
        requirement.feature == "spawn-target:CellDep#0"
            && requirement.component == "spawn-target-cell-dep"
            && requirement.status == "runtime-required"
            && requirement.source == "CellDep"
            && requirement.binding == "spawn-target"
            && requirement.field.as_deref() == Some("script")
            && requirement.abi == "ckb-spawn-cell-dep-script-reference"
            && requirement.blocker_class.as_deref() == Some("spawn-target-cell-dep-gap")
    }));
    let ckb_constraints = result.metadata.constraints.ckb.as_ref().expect("CKB constraints");
    assert!(ckb_constraints.script_references.iter().any(|reference| {
        reference.scope == "action:delegate_verify"
            && reference.purpose == "spawn-target"
            && reference.dep_source == "CellDep-or-DepGroup"
            && reference.status == "runtime-required-builder-resolved"
    }));
    let owner_lock = result.metadata.locks.iter().find(|lock| lock.name == "owner_lock").expect("owner_lock metadata");
    let owner_group = owner_lock.ckb_script_group.as_ref().expect("owner_lock CKB script group metadata");
    assert_eq!(owner_group.entry_kind, "lock");
    assert_eq!(owner_group.group_kind, "lock");
    assert_eq!(owner_group.active_script_group, "lock-group");
    assert!(owner_group.input_sources.contains(&"GroupInput".to_string()));
    assert!(owner_group.group_scoped_sources.contains(&"GroupInput".to_string()));
    let output_lock =
        result.metadata.locks.iter().find(|lock| lock.name == "output_witness_lock").expect("output_witness_lock metadata");
    let output_group = output_lock.ckb_script_group.as_ref().expect("output_witness_lock CKB script group metadata");
    assert!(output_group.output_sources.contains(&"GroupOutput".to_string()));
    assert!(output_group.group_scoped_sources.contains(&"GroupOutput".to_string()));
    assert_eq!(result.metadata.target_profile.spawn_ipc_abi, "ckb-vm-v2-spawn-ipc-syscalls-2601-2608");
    assert_eq!(result.metadata.target_profile.lock_args_abi, "ckb-script-args-typed-fixed-bytes");
    assert_eq!(result.metadata.target_profile.source_encoding, "ckb-source-group-high-bit");
    assert_eq!(result.metadata.target_profile.cell_dep_abi, "ckb-cell-dep-outpoint-and-dep-group");
    assert_eq!(result.metadata.target_profile.script_ref_abi, "ckb-script-code-hash-hash-type-args");
    assert_eq!(result.metadata.target_profile.output_data_abi, "ckb-outputs-and-outputs-data-index-aligned");
    assert_eq!(result.metadata.target_profile.capacity_floor_abi, "ckb-output-capacity-floor-shannons");
    assert_eq!(result.metadata.target_profile.type_id_abi, "ckb-type-id-v1");

    let profile_abi = &result.metadata.constraints.ckb.as_ref().expect("CKB constraints").profile_abi_contract;
    assert_eq!(profile_abi.witness_abi, result.metadata.target_profile.witness_abi);
    assert_eq!(profile_abi.lock_args_abi, result.metadata.target_profile.lock_args_abi);
    assert_eq!(profile_abi.source_encoding, result.metadata.target_profile.source_encoding);
    assert_eq!(profile_abi.spawn_ipc_abi, result.metadata.target_profile.spawn_ipc_abi);
    assert_eq!(profile_abi.since_abi, result.metadata.target_profile.since_abi);
    assert_eq!(profile_abi.cell_dep_abi, result.metadata.target_profile.cell_dep_abi);
    assert_eq!(profile_abi.script_ref_abi, result.metadata.target_profile.script_ref_abi);
    assert_eq!(profile_abi.output_data_abi, result.metadata.target_profile.output_data_abi);
    assert_eq!(profile_abi.capacity_floor_abi, result.metadata.target_profile.capacity_floor_abi);
    assert_eq!(profile_abi.type_id_abi, result.metadata.target_profile.type_id_abi);
    assert_eq!(profile_abi.tx_version, result.metadata.target_profile.tx_version);
}

#[test]
fn v0_14_exposes_declarative_capacity_floor_metadata() {
    let source = r#"
module cellscript::v0_14_capacity_floor

resource Token has store
with_capacity_floor(6100000000)
{
    amount: u64,
}

action mint(amount: u64) -> Token {
    create Token { amount }
}
"#;

    let result = compile(source, CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() }).unwrap();
    let token = result.metadata.types.iter().find(|ty| ty.name == "Token").expect("Token metadata");
    assert_eq!(token.capacity_floor_shannons, Some(6_100_000_000));
    assert_eq!(token.capacity_floor_source.as_deref(), Some("dsl-with_capacity_floor"));
    let ckb_constraints = result.metadata.constraints.ckb.as_ref().expect("CKB constraints");
    assert_eq!(
        ckb_constraints.capacity_policy_surface,
        "dsl-declared-capacity-floor; builder/runtime-required-for-change-and-measurement"
    );
    assert_eq!(ckb_constraints.declared_capacity_floors.len(), 1);
    let floor = &ckb_constraints.declared_capacity_floors[0];
    assert_eq!(floor.type_name, "Token");
    assert_eq!(floor.shannons, 6_100_000_000);
    assert_eq!(floor.source, "dsl-with_capacity_floor");
    assert_eq!(floor.status, "builder-must-preserve-output-capacity-at-or-above-floor");
    result.validate().unwrap();

    let err = compile(
        r#"
module cellscript::bad_capacity_floor

resource Token has store
with_capacity_floor(0)
{
    amount: u64,
}
"#,
        CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() },
    )
    .unwrap_err();
    assert!(err.message.contains("capacity floor must be greater than zero"), "unexpected error: {}", err.message);
}

#[test]
fn v0_14_exposes_type_id_create_output_plan_and_output_data_boundary() {
    let source = r#"
module cellscript::v0_14_type_id

#[type_id("cellscript::v0_14_type_id::Token:v1")]
resource Token has store
with_default_hash_type(Type)
{
    amount: u64,
}

action mint(amount: u64) -> Token {
    create Token { amount }
}
"#;

    let result = compile(source, CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() }).unwrap();
    let token = result.metadata.types.iter().find(|ty| ty.name == "Token").expect("Token metadata");
    assert_eq!(token.type_id.as_deref(), Some("cellscript::v0_14_type_id::Token:v1"));
    assert_eq!(token.default_hash_type.as_deref(), Some("type"));
    assert_eq!(token.hash_type_source, "dsl-with_default_hash_type");
    let ckb_type_id = token.ckb_type_id.as_ref().expect("CKB TYPE_ID contract metadata");
    assert_eq!(ckb_type_id.abi, "ckb-type-id-v1");
    assert_eq!(ckb_type_id.hash_type, "type");
    assert_eq!(ckb_type_id.args_source, "first-input-output-index");
    assert_eq!(ckb_type_id.group_rule, "at-most-one-input-and-one-output");

    let mint = result.metadata.actions.iter().find(|action| action.name == "mint").expect("mint metadata");
    let mint_group = mint.ckb_script_group.as_ref().expect("mint CKB script group metadata");
    assert_eq!(mint_group.group_kind, "type");
    assert!(mint_group.output_sources.contains(&"Output".to_string()));
    let output_data = mint.create_set[0].ckb_output_data.as_ref().expect("CKB output data binding");
    assert_eq!(output_data.output_source, "Output");
    assert_eq!(output_data.output_index, 0);
    assert_eq!(output_data.output_data_source, "outputs_data");
    assert_eq!(output_data.output_data_index, 0);
    assert_eq!(output_data.relation, "same-index");
    assert_eq!(mint.ckb_type_id_output_indexes(), vec![0]);
    let plan = mint.create_set[0].ckb_type_id.as_ref().expect("TYPE_ID create output plan");
    assert_eq!(plan.abi, "ckb-type-id-v1");
    assert_eq!(plan.output_source, "Output");
    assert_eq!(plan.output_index, 0);
    assert_eq!(plan.generator_setting, "ckb_type_id_output_indexes");
    assert_eq!(plan.wasm_setting, "ckbTypeIdOutputs");
    let ckb_constraints = result.metadata.constraints.ckb.as_ref().expect("CKB constraints");
    assert!(ckb_constraints.script_references.iter().any(|reference| {
        reference.scope == "action:mint"
            && reference.purpose == "type-id-create-output"
            && reference.name == "Token"
            && reference.code_hash.as_deref() == Some(plan.script_code_hash.as_str())
            && reference.hash_type.as_deref() == Some("type")
            && reference.args.as_deref() == Some("first-input-output-index")
    }));

    let create_access = result
        .metadata
        .runtime
        .ckb_runtime_accesses
        .iter()
        .find(|access| access.operation == "create" && access.source == "Output" && access.index == 0)
        .expect("create output runtime access");
    assert_eq!(create_access.syscall, "LOAD_CELL");
    assert_eq!(result.metadata.target_profile.output_data_abi, "ckb-outputs-and-outputs-data-index-aligned");
}

#[test]
fn v0_14_rejects_unavailable_dynamic_blake2b() {
    let err = compile(
        r#"
module cellscript::bad_blake2b

action bad(input: Hash) -> Hash {
    return hash_blake2b(input)
}
"#,
        CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() },
    )
    .unwrap_err();

    assert!(err.message.contains("hash_blake2b is not available"), "unexpected error: {}", err.message);
}

#[test]
fn v0_14_rejects_spawn_ipc_fd_use_after_close() {
    let err = compile(
        r#"
module cellscript::bad_fd

action bad(value: u64) -> u64 {
    let (read_fd, write_fd) = pipe()
    close(read_fd)
    pipe_read(read_fd)
}
"#,
        CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() },
    )
    .unwrap_err();

    assert!(err.message.contains("pipe_read uses a Spawn/IPC file descriptor after close"), "unexpected error: {}", err.message);
}

#[test]
fn v0_14_rejects_spawn_ipc_fd_double_close() {
    let err = compile(
        r#"
module cellscript::bad_fd

action bad() -> u64 {
    let fds = pipe()
    let read_fd = fds.0
    close(read_fd)
    close(read_fd)
}
"#,
        CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() },
    )
    .unwrap_err();

    assert!(err.message.contains("already closed"), "unexpected error: {}", err.message);
}

#[test]
fn v0_14_rejects_spawn_ipc_fd_leak() {
    let err = compile(
        r#"
module cellscript::bad_fd

action bad(value: u64) -> u64 {
    let fds = pipe()
    let read_fd = fds.0
    let write_fd = fds.1
    pipe_write(write_fd, value)
    return pipe_read(read_fd)
}
"#,
        CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() },
    )
    .unwrap_err();

    assert!(err.message.contains("is not closed before callable exit"), "unexpected error: {}", err.message);
}

#[test]
fn v0_14_spawn_target_must_be_static() {
    let ok = compile(
        r#"
module cellscript::static_spawn

const VERIFY_TARGET: String = "secp256k1_verifier";

action delegate() -> u64 {
    return spawn(VERIFY_TARGET)
}
"#,
        CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() },
    )
    .unwrap();
    assert!(ok.metadata.runtime.ckb_runtime_accesses.iter().any(|access| access.operation == "spawn"));

    let err = compile(
        r#"
module cellscript::dynamic_spawn

action delegate(target: String) -> u64 {
    return spawn(target)
}
"#,
        CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() },
    )
    .unwrap_err();

    assert!(err.message.contains("spawn target must be a static script reference"), "unexpected error: {}", err.message);
}

#[test]
fn v0_14_language_examples_cover_spawn_pipeline_and_type_id_create() {
    let pipeline = compile(
        include_str!("../examples/language/v0_14_multi_step_pipeline.cell"),
        CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() },
    )
    .unwrap();
    let pipeline_action =
        pipeline.metadata.actions.iter().find(|action| action.name == "pipe_to_delegate").expect("pipe_to_delegate metadata");
    for operation in ["pipe", "pipe-write", "spawn", "wait", "pipe-read", "close-fd"] {
        assert!(
            pipeline_action.ckb_runtime_accesses.iter().any(|access| access.operation == operation),
            "missing {operation}: {:?}",
            pipeline_action.ckb_runtime_accesses
        );
    }
    assert!(pipeline_action
        .transaction_runtime_input_requirements
        .iter()
        .any(|requirement| { requirement.component == "spawn-target-cell-dep" && requirement.status == "runtime-required" }));

    let type_id = compile(
        include_str!("../examples/language/v0_14_ckb_type_id_create.cell"),
        CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() },
    )
    .unwrap();
    let mint =
        type_id.metadata.actions.iter().find(|action| action.name == "mint_identity_token").expect("mint_identity_token metadata");
    assert_eq!(mint.ckb_type_id_output_indexes(), vec![0]);
    assert!(mint.create_set[0].ckb_type_id.is_some());
}
