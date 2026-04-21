use camino::Utf8PathBuf;
use cellscript::{compile_file, ArtifactFormat, CompileOptions, PoolPrimitiveMetadata};

const BUNDLED_EXAMPLES: [&str; 7] =
    ["amm_pool.cell", "launch.cell", "multisig.cell", "nft.cell", "timelock.cell", "token.cell", "vesting.cell"];

const BUNDLED_EXAMPLE_ELF_SIZE_BUDGETS: [(&str, usize); 7] = [
    ("amm_pool.cell", 56 * 1024),
    ("launch.cell", 48 * 1024),
    ("multisig.cell", 40 * 1024),
    ("nft.cell", 64 * 1024),
    ("timelock.cell", 40 * 1024),
    ("token.cell", 24 * 1024),
    ("vesting.cell", 36 * 1024),
];

const BUNDLED_EXAMPLE_ASM_SHAPE_BUDGETS: [(&str, AssemblyShapeBudget); 7] = [
    ("amm_pool.cell", AssemblyShapeBudget { max_lines: 9_000, max_fail_handlers: 32, max_shared_epilogues: 8 }),
    ("launch.cell", AssemblyShapeBudget { max_lines: 5_000, max_fail_handlers: 16, max_shared_epilogues: 4 }),
    ("multisig.cell", AssemblyShapeBudget { max_lines: 7_800, max_fail_handlers: 64, max_shared_epilogues: 20 }),
    ("nft.cell", AssemblyShapeBudget { max_lines: 10_000, max_fail_handlers: 64, max_shared_epilogues: 18 }),
    ("timelock.cell", AssemblyShapeBudget { max_lines: 7_000, max_fail_handlers: 52, max_shared_epilogues: 22 }),
    ("token.cell", AssemblyShapeBudget { max_lines: 2_800, max_fail_handlers: 24, max_shared_epilogues: 6 }),
    ("vesting.cell", AssemblyShapeBudget { max_lines: 4_400, max_fail_handlers: 28, max_shared_epilogues: 6 }),
];

#[derive(Debug, Clone, Copy)]
struct AssemblyShapeBudget {
    max_lines: usize,
    max_fail_handlers: usize,
    max_shared_epilogues: usize,
}

fn example_path(name: &str) -> Utf8PathBuf {
    Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples").join(name)
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

fn count_lines_containing(assembly: &str, needle: &str) -> usize {
    assembly.lines().filter(|line| line.contains(needle)).count()
}

fn count_lines_with_prefix_and_contains(assembly: &str, prefix: &str, needle: &str) -> usize {
    assembly.lines().filter(|line| line.starts_with(prefix) && line.contains(needle)).count()
}

#[allow(dead_code)]
struct SchedulerAccessWitness {
    operation: u8,
    source: u8,
    index: u32,
    binding_hash: [u8; 32],
}

#[allow(dead_code)]
struct SchedulerWitness {
    magic: u16,
    version: u8,
    effect_class: u8,
    parallelizable: bool,
    touches_shared_count: u32,
    touches_shared: Vec<[u8; 32]>,
    estimated_cycles: u64,
    access_count: u32,
    accesses: Vec<SchedulerAccessWitness>,
}

fn decode_hex_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex string must contain full bytes");
    (0..hex.len()).step_by(2).map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("valid hex byte")).collect()
}

fn scheduler_witness_operation_ids(hex: &str) -> Vec<u8> {
    let bytes = decode_hex_bytes(hex);
    let witness = decode_molecule_scheduler_witness(&bytes);
    assert_eq!(witness.magic, 0xCE11);
    assert_eq!(witness.access_count as usize, witness.accesses.len());
    witness.accesses.into_iter().map(|access| access.operation).collect()
}

fn decode_molecule_scheduler_witness(bytes: &[u8]) -> SchedulerWitness {
    let fields = decode_molecule_table(bytes, 9);
    SchedulerWitness {
        magic: read_u16(fields[0], "magic"),
        version: read_u8(fields[1], "version"),
        effect_class: read_u8(fields[2], "effect_class"),
        parallelizable: read_bool(fields[3], "parallelizable"),
        touches_shared_count: read_u32(fields[4], "touches_shared_count"),
        touches_shared: read_fixvec_byte32(fields[5]),
        estimated_cycles: read_u64(fields[6], "estimated_cycles"),
        access_count: read_u32(fields[7], "access_count"),
        accesses: read_scheduler_accesses(fields[8]),
    }
}

fn decode_molecule_table(bytes: &[u8], expected_fields: usize) -> Vec<&[u8]> {
    assert!(bytes.len() >= 8, "molecule table header is too short: {}", bytes.len());
    let total_size = read_u32(&bytes[..4], "total_size") as usize;
    assert_eq!(total_size, bytes.len(), "molecule table total size mismatch");
    let first_offset = read_u32(&bytes[4..8], "first_offset") as usize;
    assert!(first_offset >= 8 && first_offset <= bytes.len() && first_offset % 4 == 0, "invalid first offset {first_offset}");
    let field_count = first_offset / 4 - 1;
    assert_eq!(field_count, expected_fields, "unexpected molecule table field count");
    let mut offsets = bytes[4..first_offset].chunks_exact(4).map(|chunk| read_u32(chunk, "offset") as usize).collect::<Vec<_>>();
    offsets.push(total_size);
    for pair in offsets.windows(2) {
        assert!(pair[0] <= pair[1], "molecule offsets must be monotonic: {:?}", offsets);
        assert!(pair[0] >= first_offset && pair[1] <= total_size, "molecule offsets must stay in payload: {:?}", offsets);
    }
    offsets.windows(2).map(|pair| &bytes[pair[0]..pair[1]]).collect()
}

fn read_scheduler_accesses(bytes: &[u8]) -> Vec<SchedulerAccessWitness> {
    let count = read_u32(&bytes[..4], "access_count") as usize;
    assert_eq!(bytes.len(), 4 + count * 38, "access fixvec byte length mismatch");
    bytes[4..]
        .chunks_exact(38)
        .map(|chunk| SchedulerAccessWitness {
            operation: chunk[0],
            source: chunk[1],
            index: read_u32(&chunk[2..6], "access.index"),
            binding_hash: chunk[6..38].try_into().expect("binding hash width"),
        })
        .collect()
}

fn read_fixvec_byte32(bytes: &[u8]) -> Vec<[u8; 32]> {
    let count = read_u32(&bytes[..4], "byte32_count") as usize;
    assert_eq!(bytes.len(), 4 + count * 32, "byte32 fixvec byte length mismatch");
    bytes[4..].chunks_exact(32).map(|chunk| chunk.try_into().expect("byte32 width")).collect()
}

fn read_u8(bytes: &[u8], field: &str) -> u8 {
    assert_eq!(bytes.len(), 1, "{field} should be a molecule byte");
    bytes[0]
}

fn read_bool(bytes: &[u8], field: &str) -> bool {
    match read_u8(bytes, field) {
        0 => false,
        1 => true,
        value => panic!("{field} should be a molecule bool, got {value}"),
    }
}

fn read_u16(bytes: &[u8], field: &str) -> u16 {
    assert_eq!(bytes.len(), 2, "{field} should be a molecule u16");
    u16::from_le_bytes(bytes.try_into().expect("u16 width"))
}

fn read_u32(bytes: &[u8], field: &str) -> u32 {
    assert_eq!(bytes.len(), 4, "{field} should be a molecule u32");
    u32::from_le_bytes(bytes.try_into().expect("u32 width"))
}

fn read_u64(bytes: &[u8], field: &str) -> u64 {
    assert_eq!(bytes.len(), 8, "{field} should be a molecule u64");
    u64::from_le_bytes(bytes.try_into().expect("u64 width"))
}

fn assert_pool_component(primitive: &PoolPrimitiveMetadata, component: &str, context: &str) {
    assert!(
        primitive.checked_components.iter().any(|candidate| candidate == component),
        "{} should expose checked Pool component '{}': {:?}",
        context,
        component,
        primitive.checked_components
    );
}

fn assert_pool_invariant_family(primitive: &PoolPrimitiveMetadata, name: &str, status: &str, source: &str, context: &str) {
    assert!(
        primitive.invariant_families.iter().any(|family| family.name == name && family.status == status && family.source == source),
        "{} should classify Pool invariant '{}' as {} from {}: {:?}",
        context,
        name,
        status,
        source,
        primitive.invariant_families
    );
}

fn assert_pool_invariant_blocker_class(primitive: &PoolPrimitiveMetadata, name: &str, blocker_class: &str, context: &str) {
    assert!(
        primitive
            .invariant_families
            .iter()
            .any(|family| family.name == name && family.blocker_class.as_deref() == Some(blocker_class)),
        "{} should classify Pool invariant '{}' with blocker class '{}': {:?}",
        context,
        name,
        blocker_class,
        primitive.invariant_families
    );
}

fn assert_pool_runtime_input_blocker_class(primitive: &PoolPrimitiveMetadata, component: &str, blocker_class: &str, context: &str) {
    assert!(
        primitive
            .runtime_input_requirements
            .iter()
            .any(|requirement| requirement.component == component && requirement.blocker_class.as_deref() == Some(blocker_class)),
        "{} should classify Pool runtime inputs for '{}' with blocker class '{}': {:?}",
        context,
        component,
        blocker_class,
        primitive.runtime_input_requirements
    );
}

fn assert_pool_runtime_input_requirement(
    primitive: &PoolPrimitiveMetadata,
    component: &str,
    source: &str,
    index: usize,
    binding: &str,
    field: Option<&str>,
    abi: &str,
    byte_len: usize,
    context: &str,
) {
    assert!(
        primitive.runtime_input_requirements.iter().any(|requirement| {
            requirement.component == component
                && requirement.source == source
                && requirement.index == index
                && requirement.binding == binding
                && requirement.field.as_deref() == field
                && requirement.abi == abi
                && requirement.byte_len == byte_len
        }),
        "{} should expose runtime input requirement {} {}#{}:{}{:?} {}[{}]: {:?}",
        context,
        component,
        source,
        index,
        binding,
        field,
        abi,
        byte_len,
        primitive.runtime_input_requirements
    );
}

fn action<'a>(metadata: &'a cellscript::CompileMetadata, name: &str) -> &'a cellscript::ActionMetadata {
    metadata.actions.iter().find(|action| action.name == name).unwrap_or_else(|| panic!("missing {name} action metadata"))
}

fn assert_create(action: &cellscript::ActionMetadata, ty: &str, context: &str) {
    assert!(
        action.create_set.iter().any(|pattern| pattern.ty == ty && pattern.operation == "create"),
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

fn assert_mutate_field(action: &cellscript::ActionMetadata, ty: &str, binding: &str, field: &str, context: &str) {
    assert!(
        action.mutate_set.iter().any(|mutation| mutation.ty == ty
            && mutation.binding == binding
            && mutation.fields.iter().any(|candidate| candidate == field)),
        "{} should expose {}.{} mutation for '{}': {:?}",
        context,
        ty,
        field,
        binding,
        action.mutate_set
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

#[test]
fn bundled_examples_compile_to_non_empty_assembly() {
    for example in BUNDLED_EXAMPLES {
        let result = compile_file(example_path(example), CompileOptions::default()).unwrap_or_else(|err| {
            panic!("failed to compile {}: {}", example, err);
        });

        assert_eq!(result.artifact_format, ArtifactFormat::RiscvAssembly, "unexpected artifact format for {}", example);
        assert!(!result.artifact_bytes.is_empty(), "empty artifact for {}", example);
        assert!(result.metadata.artifact_hash_blake3.is_some(), "missing artifact hash metadata for {}", example);
        assert!(result.metadata.artifact_size_bytes.is_some(), "missing artifact size metadata for {}", example);
        assert!(!result.metadata.actions.is_empty(), "missing action metadata for {}", example);
        assert!(
            result.metadata.actions.iter().all(|action| {
                action.scheduler_witness_abi == "molecule"
                    && !action.scheduler_witness_hex.is_empty()
                    && !action.scheduler_witness_hex.starts_with("11ce")
                    && action.scheduler_witness_bytes().is_ok()
            }),
            "missing launch Molecule scheduler witness for {}",
            example
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
fn bundled_examples_stay_within_backend_shape_budgets() {
    for example in BUNDLED_EXAMPLES {
        let result = compile_file(
            example_path(example),
            CompileOptions { target: Some("riscv64-asm".to_string()), ..CompileOptions::default() },
        )
        .unwrap_or_else(|e| panic!("{} should compile to assembly: {}", example, e.message));
        let assembly = std::str::from_utf8(&result.artifact_bytes)
            .unwrap_or_else(|e| panic!("{} emitted invalid utf-8 assembly: {}", example, e));
        let budget = bundled_example_asm_shape_budget(example);
        let line_count = assembly.lines().count();
        let fail_handlers = count_lines_with_prefix_and_contains(assembly, ".L", "_fail_");
        let shared_epilogues = count_lines_with_prefix_and_contains(assembly, ".L", "_epilogue:");

        assert!(
            line_count <= budget.max_lines,
            "{} assembly grew past its backend shape budget: {} > {} lines",
            example,
            line_count,
            budget.max_lines
        );
        assert!(
            fail_handlers <= budget.max_fail_handlers,
            "{} emitted too many shared fail handlers: {} > {}",
            example,
            fail_handlers,
            budget.max_fail_handlers
        );
        assert!(
            shared_epilogues <= budget.max_shared_epilogues,
            "{} emitted too many shared epilogues: {} > {}",
            example,
            shared_epilogues,
            budget.max_shared_epilogues
        );
        assert_eq!(
            count_lines_containing(assembly, "__cellscript_memcmp_fixed:"),
            1,
            "{} should emit one fixed-byte comparison helper",
            example
        );
        assert_eq!(
            count_lines_containing(assembly, "__cellscript_require_min_size:"),
            1,
            "{} should emit one minimum-size guard helper",
            example
        );
        assert_eq!(
            count_lines_containing(assembly, "__cellscript_require_exact_size:"),
            1,
            "{} should emit one exact-size guard helper",
            example
        );
        assert!(!assembly.contains("immediate '"), "{} assembly should not contain a leaked assembler overflow diagnostic", example);
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
        "grant_vesting create output should now be covered by imported Token layout, DAA prelude, and fixed-byte parameters"
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
    assert!(
        claim_vested.verifier_obligations.iter().any(|obligation| {
            obligation.category == "lifecycle-transition"
                && obligation.feature == "VestingGrant.state"
                && obligation.status == "checked-runtime"
        }),
        "claim_vested should expose the runtime-checked lifecycle transition obligation"
    );
    let claim_conditions = claim_vested
        .verifier_obligations
        .iter()
        .find(|obligation| {
            obligation.category == "transaction-invariant"
                && obligation.feature == "claim-conditions:VestingGrant"
                && obligation.status == "runtime-required"
        })
        .expect("claim_vested should expose receipt claim condition obligation");
    assert!(
        claim_conditions.detail.contains("daa-cliff-reached=checked-runtime")
            && claim_conditions.detail.contains("state-not-fully-claimed=checked-runtime")
            && claim_conditions.detail.contains("positive-claimable=checked-runtime")
            && claim_conditions.detail.contains("claim-witness-format=checked-runtime")
            && claim_conditions.detail.contains("claim-authorization-domain=checked-runtime"),
        "claim_vested should surface checked source predicates without closing authorization: {}",
        claim_conditions.detail
    );
    assert!(
        claim_conditions.detail.contains("Input#0:grant.cliff_daa_score=input-cell-field-u64[8]")
            && claim_conditions.detail.contains("Input#0:grant.state=input-cell-field-u8[1]")
            && claim_conditions.detail.contains("Input#0:grant.beneficiary=input-cell-field-bytes-32[32]"),
        "claim_vested should expose field-aware receipt inputs for remaining runtime authorization: {}",
        claim_conditions.detail
    );
    assert!(
        claim_vested.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "claim-conditions:VestingGrant"
                && requirement.status == "runtime-required"
                && requirement.component == "claim-witness-signature"
                && requirement.source == "Witness"
                && requirement.field.as_deref() == Some("signature")
                && requirement.abi == "claim-witness-signature-65"
                && requirement.byte_len == Some(65)
                && requirement.blocker.as_deref()
                    == Some(
                        "claim lowering checks witness shape but has no verifier-coverable signer key binding or secp256k1 verification call"
                    )
                && requirement.blocker_class.as_deref() == Some("witness-verification-gap")
        }),
        "claim_vested should expose structured witness/signature runtime input requirements: {:?}",
        claim_vested.transaction_runtime_input_requirements
    );
    assert!(
        claim_vested.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "claim-conditions:VestingGrant"
                && requirement.status == "checked-runtime"
                && requirement.component == "claim-time-context"
                && requirement.source == "Header"
                && requirement.field.as_deref() == Some("daa_score")
                && requirement.abi == "claim-time-daa-score-u64"
                && requirement.byte_len == Some(8)
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }),
        "claim_vested should expose structured time context runtime input requirements: {:?}",
        claim_vested.transaction_runtime_input_requirements
    );
    assert!(
        result.metadata.runtime.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.scope == "action:claim_vested"
                && requirement.feature == "claim-conditions:VestingGrant"
                && requirement.status == "checked-runtime"
                && requirement.component == "claim-authorization-domain"
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }),
        "module runtime metadata should aggregate checked claim authorization runtime input requirements: {:?}",
        result.metadata.runtime.transaction_runtime_input_requirements
    );

    let revoke_grant = result.metadata.actions.iter().find(|action| action.name == "revoke_grant").expect("revoke_grant metadata");
    assert!(
        revoke_grant.fail_closed_runtime_features.is_empty(),
        "revoke_grant output fields and locks should now be verifier-coverable: {:?}",
        revoke_grant.fail_closed_runtime_features
    );
}

#[test]
fn token_mint_authority_mutation_is_explicit() {
    let result = compile_file(example_path("token.cell"), CompileOptions::default()).expect("token example should compile");
    let asm = String::from_utf8(result.artifact_bytes.clone()).expect("token asm should be utf8");
    let mint = result.metadata.actions.iter().find(|action| action.name == "mint").expect("mint metadata");
    let mutation = mint
        .mutate_set
        .iter()
        .find(|mutation| mutation.operation == "mutate" && mutation.ty == "MintAuthority" && mutation.binding == "auth")
        .expect("mint should expose MintAuthority mutate_set metadata");

    assert_eq!(mutation.fields, vec!["minted".to_string()]);
    assert_eq!(mutation.preserved_fields, vec!["max_supply".to_string(), "token_symbol".to_string()]);
    assert_eq!(mutation.input_source, "Input");
    assert_eq!(mutation.input_index, 0);
    assert_eq!(mutation.output_source, "Output");
    assert_eq!(mutation.output_index, 1);
    assert!(mutation.preserve_type_hash);
    assert!(mutation.preserve_lock_hash);
    assert_eq!(mutation.type_hash_preservation_status, "checked-runtime");
    assert_eq!(mutation.lock_hash_preservation_status, "checked-runtime");
    assert_eq!(mutation.field_equality_status, "checked-runtime");
    assert_eq!(mutation.field_transition_status, "checked-runtime");

    assert!(
        mint.verifier_obligations.iter().any(|obligation| {
            obligation.category == "cell-state"
                && obligation.feature == "mutable-cell:MintAuthority"
                && obligation.status == "checked-runtime"
                && obligation.detail.contains("Input#0 -> Output#1")
                && obligation.detail.contains("type_hash preservation=checked-runtime")
                && obligation.detail.contains("lock_hash preservation=checked-runtime")
                && obligation.detail.contains("field equality=checked-runtime")
                && obligation.detail.contains("field transition=checked-runtime")
                && obligation.detail.contains("transition fields: minted")
                && obligation.detail.contains("preserved fields: max_supply, token_symbol")
        }),
        "mint authority updates should remain explicit until the replacement authority cell is proved: {:?}",
        mint.verifier_obligations
    );
    assert!(mint.ckb_runtime_accesses.iter().any(|access| {
        access.operation == "mutate-input" && access.source == "Input" && access.index == 0 && access.binding == "auth"
    }));
    assert!(mint.ckb_runtime_accesses.iter().any(|access| {
        access.operation == "mutate-output" && access.source == "Output" && access.index == 1 && access.binding == "auth"
    }));
    let scheduler_ops = scheduler_witness_operation_ids(&mint.scheduler_witness_hex);
    assert!(scheduler_ops.contains(&8), "mint scheduler witness should encode mutate-input access");
    assert!(scheduler_ops.contains(&9), "mint scheduler witness should encode mutate-output access");
    assert!(
        asm.contains("# cellscript abi: LOAD_CELL_BY_FIELD reason=mutate_input_type_hash source=Input index=0 field=5")
            && asm.contains("# cellscript abi: LOAD_CELL_BY_FIELD reason=mutate_output_type_hash source=Output index=1 field=5")
            && asm.contains("# cellscript abi: verify mutate replacement MintAuthority type_hash Input#0 == Output#1 size=32"),
        "mint should emit executable TypeHash preservation checks for the replacement MintAuthority cell:\n{}",
        asm
    );
    assert!(
        asm.contains("# cellscript abi: LOAD_CELL_BY_FIELD reason=mutate_input_lock_hash source=Input index=0 field=3")
            && asm.contains("# cellscript abi: LOAD_CELL_BY_FIELD reason=mutate_output_lock_hash source=Output index=1 field=3")
            && asm.contains("# cellscript abi: verify mutate replacement MintAuthority lock_hash Input#0 == Output#1 size=32"),
        "mint should emit executable LockHash preservation checks for the replacement MintAuthority cell:\n{}",
        asm
    );
    assert!(
        asm.contains("# cellscript abi: LOAD_CELL_DATA reason=mutate_input_data source=Input index=0")
            && asm.contains("# cellscript abi: LOAD_CELL_DATA reason=mutate_output_data source=Output index=1")
            && asm.contains(
                "# cellscript abi: verify mutate preserved field MintAuthority.max_supply Input#0 == Output#1 offset=8 size=8"
            )
            && asm.contains(
                "# cellscript abi: verify mutate preserved field MintAuthority.token_symbol Input#0 == Output#1 offset=0 size=8"
            ),
        "mint should emit executable preserved-field equality checks for the replacement MintAuthority cell:\n{}",
        asm
    );
    assert!(
        asm.contains("# cellscript abi: LOAD_CELL_DATA reason=mutate_input_transition source=Input index=0")
            && asm.contains("# cellscript abi: LOAD_CELL_DATA reason=mutate_output_transition source=Output index=1")
            && asm.contains(
                "# cellscript abi: verify mutate transition field MintAuthority.minted Add Input#0 -> Output#1 offset=16 size=8"
            ),
        "mint should emit executable transition checks for the replacement MintAuthority cell:\n{}",
        asm
    );
    assert!(
        mint.fail_closed_runtime_features.is_empty(),
        "mint authority mutation should be a verifier obligation, not a fail-closed lowering path: {:?}",
        mint.fail_closed_runtime_features
    );
}

#[test]
fn nft_core_actions_expose_action_specific_builder_metadata() {
    let result = compile_file(example_path("nft.cell"), CompileOptions::default()).expect("nft example should compile");

    let mint = action(&result.metadata, "mint");
    assert_eq!(mint.effect_class, "Creating");
    assert!(mint.parallelizable);
    assert!(mint.fail_closed_runtime_features.is_empty(), "nft mint should not carry fail-closed debt");
    assert_create(mint, "NFT", "nft mint");
    assert_mutate_field(mint, "Collection", "collection", "total_supply", "nft mint");
    assert_runtime_requirement(mint, "create-output:NFT:create_NFT", "checked-runtime", "create-output-fields", "nft mint");
    assert_runtime_requirement(mint, "mutable-cell:Collection", "runtime-required", "mutate-field-equality", "nft mint");

    let transfer = action(&result.metadata, "transfer");
    assert_eq!(transfer.effect_class, "Mutating");
    assert!(transfer.fail_closed_runtime_features.is_empty(), "nft transfer should not carry fail-closed debt");
    assert_mutate_field(transfer, "NFT", "nft", "owner", "nft transfer");
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
}

#[test]
fn timelock_core_actions_expose_time_and_release_metadata() {
    let result = compile_file(example_path("timelock.cell"), CompileOptions::default()).expect("timelock example should compile");

    let create_absolute_lock = action(&result.metadata, "create_absolute_lock");
    assert_eq!(create_absolute_lock.effect_class, "Creating");
    assert_create(create_absolute_lock, "TimeLock", "timelock create_absolute_lock");
    assert_runtime_requirement(
        create_absolute_lock,
        "create-output:TimeLock:create_TimeLock",
        "runtime-required",
        "create-output-fields",
        "timelock create_absolute_lock",
    );

    let execute_release = action(&result.metadata, "execute_release");
    assert_eq!(execute_release.effect_class, "Mutating");
    assert_destroy(execute_release, "time_lock", "timelock execute_release");
    assert_destroy(execute_release, "locked_asset", "timelock execute_release");
    assert_destroy(execute_release, "request", "timelock execute_release");
    assert_create(execute_release, "ReleaseRecord", "timelock execute_release");
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
        "create-output:ReleaseRecord:create_ReleaseRecord",
        "checked-runtime",
        "create-output-fields",
        "timelock execute_release",
    );

    let extend_lock = action(&result.metadata, "extend_lock");
    assert!(extend_lock.fail_closed_runtime_features.is_empty(), "extend_lock should not carry fail-closed debt");
    assert_mutate_field(extend_lock, "TimeLock", "time_lock", "unlock_height", "timelock extend_lock");
    assert_runtime_requirement(
        extend_lock,
        "mutable-cell:TimeLock",
        "runtime-required",
        "mutate-field-equality",
        "timelock extend_lock",
    );
}

#[test]
fn multisig_core_actions_expose_threshold_lifecycle_metadata() {
    let result = compile_file(example_path("multisig.cell"), CompileOptions::default()).expect("multisig example should compile");

    let create_wallet = action(&result.metadata, "create_wallet");
    assert_eq!(create_wallet.effect_class, "Creating");
    assert_create(create_wallet, "MultisigWallet", "multisig create_wallet");
    assert_runtime_requirement(
        create_wallet,
        "create-output:MultisigWallet:create_MultisigWallet",
        "runtime-required",
        "create-output-fields",
        "multisig create_wallet",
    );

    let propose_transfer = action(&result.metadata, "propose_transfer");
    assert_eq!(propose_transfer.effect_class, "Creating");
    assert_create(propose_transfer, "Proposal", "multisig propose_transfer");
    assert_mutate_field(propose_transfer, "MultisigWallet", "wallet", "nonce", "multisig propose_transfer");
    assert_runtime_requirement(
        propose_transfer,
        "create-output:Proposal:create_Proposal",
        "runtime-required",
        "create-output-fields",
        "multisig propose_transfer",
    );
    assert_runtime_requirement(
        propose_transfer,
        "mutable-cell:MultisigWallet",
        "runtime-required",
        "mutate-field-equality",
        "multisig propose_transfer",
    );

    let add_signature = action(&result.metadata, "add_signature");
    assert_eq!(add_signature.effect_class, "Mutating");
    assert_create(add_signature, "SignatureConfirmation", "multisig add_signature");
    assert_runtime_requirement(
        add_signature,
        "create-output:SignatureConfirmation:create_SignatureConfirmation",
        "checked-runtime",
        "create-output-fields",
        "multisig add_signature",
    );
    assert_runtime_requirement(
        add_signature,
        "mutable-cell:Proposal",
        "runtime-required",
        "mutate-field-equality",
        "multisig add_signature",
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
        "create-output:ExecutionRecord:create_ExecutionRecord",
        "checked-runtime",
        "create-output-fields",
        "multisig execute_proposal",
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
fn amm_pool_mutable_shared_params_are_scheduler_visible() {
    let result = compile_file(example_path("amm_pool.cell"), CompileOptions::default()).expect("amm pool example should compile");
    let asm = String::from_utf8(result.artifact_bytes.clone()).expect("amm pool asm should be utf8");

    let seed_pool = result.metadata.actions.iter().find(|action| action.name == "seed_pool").expect("seed_pool metadata");
    assert!(!seed_pool.touches_shared.is_empty(), "created Pool should be scheduler-visible");
    assert!(!seed_pool.parallelizable, "new shared Pool creation should not be marked parallelizable");
    assert!(
        seed_pool.fail_closed_runtime_features.is_empty(),
        "seed_pool should verify the created Pool output type hash and LPReceipt fields without fail-closed debt: {:?}",
        seed_pool.fail_closed_runtime_features
    );
    assert!(
        seed_pool.verifier_obligations.iter().any(|obligation| {
            obligation.category == "pool-pattern"
                && obligation.feature == "pool-create:Pool"
                && obligation.status == "runtime-required"
                && obligation.detail.contains("ordinary shared Cell creation")
                && obligation.detail.contains("pool_primitives[].invariant_families")
        }),
        "seed_pool should keep pool-pattern creation/admission semantics explicit: {:?}",
        seed_pool.verifier_obligations
    );
    let seed_pool_primitive = seed_pool
        .pool_primitives
        .iter()
        .find(|primitive| primitive.feature == "pool-create:Pool")
        .expect("seed_pool should expose structured Pool creation metadata");
    assert_eq!(seed_pool_primitive.operation, "create");
    assert_eq!(seed_pool_primitive.status, "runtime-required");
    assert_eq!(seed_pool_primitive.binding.as_deref(), Some("create_Pool"));
    assert_eq!(seed_pool_primitive.output_source.as_deref(), Some("Output"));
    assert_eq!(seed_pool_primitive.output_index, Some(0));
    assert_eq!(seed_pool_primitive.source_invariant_count, 3);
    assert_pool_component(seed_pool_primitive, "ordinary-shared-create-summary", "seed_pool");
    assert_pool_component(seed_pool_primitive, "assert-invariant-cfg=3", "seed_pool");
    assert_pool_component(seed_pool_primitive, "source-invariant:token-pair-distinct=checked-runtime", "seed_pool");
    assert_pool_component(seed_pool_primitive, "source-invariant:positive-reserves=checked-runtime", "seed_pool");
    assert_pool_component(seed_pool_primitive, "source-invariant:fee-bps-bound=checked-runtime", "seed_pool");
    assert_pool_invariant_family(seed_pool_primitive, "token-pair-distinct", "checked-runtime", "assert-invariant-cfg", "seed_pool");
    assert_pool_invariant_family(seed_pool_primitive, "positive-reserves", "checked-runtime", "assert-invariant-cfg", "seed_pool");
    assert_pool_invariant_family(seed_pool_primitive, "fee-bps-bound", "checked-runtime", "assert-invariant-cfg", "seed_pool");
    assert_pool_component(seed_pool_primitive, "pool-protocol:token-pair-symbol-admission=checked-runtime", "seed_pool");
    assert!(
        asm.contains(
            "# cellscript abi: pool token-pair identity admission source=Input left=token_a#0 right=token_b#1 field=type_hash size=32"
        ),
        "seed_pool should emit executable token-pair TypeHash identity admission:\n{}",
        asm
    );
    assert!(
        asm.contains("# cellscript abi: LOAD_CELL_BY_FIELD reason=pool_token_pair_left_type_hash source=Input index=0 field=5")
            && asm
                .contains("# cellscript abi: LOAD_CELL_BY_FIELD reason=pool_token_pair_right_type_hash source=Input index=1 field=5"),
        "seed_pool should load both consumed token TypeHash fields:\n{}",
        asm
    );
    assert_pool_component(seed_pool_primitive, "pool-protocol:token-pair-identity-admission=checked-runtime", "seed_pool");
    assert_pool_invariant_family(
        seed_pool_primitive,
        "token-pair-identity-admission",
        "checked-runtime",
        "input-type-id-abi+load-cell-by-field",
        "seed_pool",
    );
    assert!(
        !seed_pool_primitive.runtime_required_components.iter().any(|component| component == "token-pair-identity-admission"),
        "seed_pool token-pair identity admission should be closed by executable Input TypeHash inequality checks: {:?}",
        seed_pool_primitive.runtime_required_components
    );
    assert_pool_invariant_family(
        seed_pool_primitive,
        "token-pair-symbol-admission",
        "checked-runtime",
        "assert-invariant-cfg+create-output-symbol-fields",
        "seed_pool",
    );
    assert!(
        !seed_pool_primitive.runtime_required_components.iter().any(|component| component == "token-pair-symbol-admission"),
        "seed_pool token-pair symbol admission should be closed by source guard plus Pool symbol field checks: {:?}",
        seed_pool_primitive.runtime_required_components
    );
    assert_pool_component(seed_pool_primitive, "pool-protocol:positive-reserve-admission=checked-runtime", "seed_pool");
    assert_pool_invariant_family(
        seed_pool_primitive,
        "positive-reserve-admission",
        "checked-runtime",
        "assert-invariant-cfg+create-output-fields",
        "seed_pool",
    );
    assert!(
        !seed_pool_primitive.runtime_required_components.iter().any(|component| component == "positive-reserve-admission"),
        "seed_pool positive reserve admission should be closed by executable source guard plus create-field checks: {:?}",
        seed_pool_primitive.runtime_required_components
    );
    assert_pool_component(seed_pool_primitive, "pool-protocol:fee-policy=checked-runtime", "seed_pool");
    assert_pool_invariant_family(
        seed_pool_primitive,
        "fee-policy",
        "checked-runtime",
        "assert-invariant-cfg+create-output-fields",
        "seed_pool",
    );
    assert!(
        !seed_pool_primitive.runtime_required_components.iter().any(|component| component == "fee-policy"),
        "seed_pool fee policy should be closed by executable fee bound plus create-field checks: {:?}",
        seed_pool_primitive.runtime_required_components
    );
    assert_pool_component(seed_pool_primitive, "pool-protocol:lp-supply-invariant=checked-runtime", "seed_pool");
    assert_pool_invariant_family(
        seed_pool_primitive,
        "lp-supply-invariant",
        "checked-runtime",
        "create-output-field-coupling",
        "seed_pool",
    );
    assert!(
        !seed_pool_primitive.runtime_required_components.iter().any(|component| component == "lp-supply-invariant"),
        "seed_pool LP supply should be closed when Pool.total_lp and LPReceipt.lp_amount share a verifier-covered source: {:?}",
        seed_pool_primitive.runtime_required_components
    );
    assert!(
        !seed_pool_primitive
            .runtime_input_requirements
            .iter()
            .any(|requirement| requirement.component == "token-pair-identity-admission"),
        "checked token-pair identity admission should not remain in Pool runtime input requirements: {:?}",
        seed_pool_primitive.runtime_input_requirements
    );
    assert!(!seed_pool_primitive.runtime_required_components.iter().any(|component| component == "token-pair-admission"));
    assert!(
        result
            .metadata
            .runtime
            .pool_primitives
            .iter()
            .any(|primitive| primitive.scope == "action:seed_pool" && primitive.feature == "pool-create:Pool"),
        "runtime metadata should aggregate structured Pool primitive obligations"
    );
    assert!(
        asm.contains("# cellscript abi: LOAD_CELL_BY_FIELD reason=output_type_hash source=Output index=0 field=5"),
        "created Pool type_hash should be loaded from the Output TypeHash field:\n{}",
        asm
    );
    assert!(
        asm.contains("# cellscript abi: verify output bytes field LPReceipt.pool_id offset=0 size=32 against loaded bytes"),
        "LPReceipt.pool_id should be checked against the created Pool output type hash:\n{}",
        asm
    );

    for (
        action_name,
        expected_fields,
        expected_preserved,
        expected_checked_transitions,
        expected_input_index,
        expected_output_index,
        expected_invariant_count,
        expected_source_invariants,
        expected_runtime_family,
        expected_runtime_source,
    ) in [
        (
            "swap_a_for_b",
            &["reserve_a", "reserve_b"][..],
            &["fee_rate_bps", "token_a_symbol", "token_b_symbol", "total_lp"][..],
            &["reserve_a", "reserve_b"][..],
            1,
            1,
            3,
            &["input-token-a-match", "minimum-output-bound", "reserve-output-bound"][..],
            "constant-product-pricing",
            "swap-constant-product-abi",
        ),
        (
            "add_liquidity",
            &["reserve_a", "reserve_b", "total_lp"][..],
            &["fee_rate_bps", "token_a_symbol", "token_b_symbol"][..],
            &["reserve_a", "reserve_b", "total_lp"][..],
            2,
            1,
            2,
            &["deposit-token-a-match", "deposit-token-b-match"][..],
            "proportional-liquidity-accounting",
            "add-liquidity-proportional-abi",
        ),
        (
            "remove_liquidity",
            &["reserve_a", "reserve_b", "total_lp"][..],
            &["fee_rate_bps", "token_a_symbol", "token_b_symbol"][..],
            &["reserve_a", "reserve_b", "total_lp"][..],
            1,
            2,
            1,
            &["lp-receipt-pool-id-match"][..],
            "proportional-withdrawal-accounting",
            "remove-liquidity-proportional-withdrawal-abi",
        ),
    ] {
        let action = result.metadata.actions.iter().find(|action| action.name == action_name).expect("amm action metadata");
        let mutation = action
            .mutate_set
            .iter()
            .find(|mutation| mutation.operation == "mutate" && mutation.ty == "Pool" && mutation.binding == "pool")
            .expect("amm action should expose Pool mutate_set metadata");
        let mutation_fields = mutation.fields.iter().map(String::as_str).collect::<Vec<_>>();
        assert_eq!(
            mutation_fields.as_slice(),
            expected_fields,
            "{} should expose the mutated Pool fields in mutate_set metadata",
            action_name
        );
        assert_eq!(
            mutation.preserved_fields.iter().map(String::as_str).collect::<Vec<_>>().as_slice(),
            expected_preserved,
            "{} should expose Pool fields that must be preserved by the replacement output",
            action_name
        );
        assert_eq!(mutation.input_source, "Input");
        assert_eq!(mutation.input_index, expected_input_index, "{} should pin the mutable Pool input ABI index", action_name);
        assert_eq!(mutation.output_source, "Output");
        assert_eq!(
            mutation.output_index, expected_output_index,
            "{} should pin the mutable Pool replacement output ABI index",
            action_name
        );
        assert!(mutation.preserve_type_hash, "{} should require Pool TypeHash preservation", action_name);
        assert!(mutation.preserve_lock_hash, "{} should require Pool LockHash preservation", action_name);
        assert_eq!(mutation.type_hash_preservation_status, "checked-runtime");
        assert_eq!(mutation.lock_hash_preservation_status, "checked-runtime");
        assert_eq!(mutation.field_equality_status, "checked-runtime");
        assert_eq!(mutation.field_transition_status, "checked-runtime");
        assert!(action.ckb_runtime_accesses.iter().any(|access| {
            access.operation == "mutate-input"
                && access.source == "Input"
                && access.index == expected_input_index
                && access.binding == "pool"
        }));
        assert!(action.ckb_runtime_accesses.iter().any(|access| {
            access.operation == "mutate-output"
                && access.source == "Output"
                && access.index == expected_output_index
                && access.binding == "pool"
        }));
        let scheduler_ops = scheduler_witness_operation_ids(&action.scheduler_witness_hex);
        assert!(scheduler_ops.contains(&8), "{} scheduler witness should encode mutate-input access", action_name);
        assert!(scheduler_ops.contains(&9), "{} scheduler witness should encode mutate-output access", action_name);
        assert!(
            asm.contains(&format!(
                "# cellscript abi: LOAD_CELL_BY_FIELD reason=mutate_input_type_hash source=Input index={} field=5",
                expected_input_index
            )) && asm.contains(&format!(
                "# cellscript abi: LOAD_CELL_BY_FIELD reason=mutate_output_type_hash source=Output index={} field=5",
                expected_output_index
            )) && asm.contains(&format!(
                "# cellscript abi: verify mutate replacement Pool type_hash Input#{} == Output#{} size=32",
                expected_input_index, expected_output_index
            )),
            "{} should emit executable TypeHash preservation checks for the replacement Pool cell:\n{}",
            action_name,
            asm
        );
        assert!(
            asm.contains(&format!(
                "# cellscript abi: LOAD_CELL_BY_FIELD reason=mutate_input_lock_hash source=Input index={} field=3",
                expected_input_index
            )) && asm.contains(&format!(
                "# cellscript abi: LOAD_CELL_BY_FIELD reason=mutate_output_lock_hash source=Output index={} field=3",
                expected_output_index
            )) && asm.contains(&format!(
                "# cellscript abi: verify mutate replacement Pool lock_hash Input#{} == Output#{} size=32",
                expected_input_index, expected_output_index
            )),
            "{} should emit executable LockHash preservation checks for the replacement Pool cell:\n{}",
            action_name,
            asm
        );
        assert!(
            asm.contains(&format!(
                "# cellscript abi: LOAD_CELL_DATA reason=mutate_input_data source=Input index={}",
                expected_input_index
            )) && asm.contains(&format!(
                "# cellscript abi: LOAD_CELL_DATA reason=mutate_output_data source=Output index={}",
                expected_output_index
            )) && expected_preserved.iter().all(|field| {
                asm.contains(&format!(
                    "# cellscript abi: verify mutate preserved field Pool.{} Input#{} == Output#{}",
                    field, expected_input_index, expected_output_index
                ))
            }),
            "{} should emit executable preserved-field equality checks for the replacement Pool cell:\n{}",
            action_name,
            asm
        );
        assert!(
            asm.contains(&format!(
                "# cellscript abi: LOAD_CELL_DATA reason=mutate_input_transition source=Input index={}",
                expected_input_index
            )) && asm.contains(&format!(
                "# cellscript abi: LOAD_CELL_DATA reason=mutate_output_transition source=Output index={}",
                expected_output_index
            )) && expected_checked_transitions
                .iter()
                .all(|field| { asm.contains(&format!("# cellscript abi: verify mutate transition field Pool.{}", field)) }),
            "{} should emit executable transition checks for verifier-coverable Pool delta fields {:?}:\n{}",
            action_name,
            expected_checked_transitions,
            asm
        );
        assert!(
            !action.touches_shared.is_empty(),
            "{} mutates &mut Pool and must expose the shared Pool type hash to the scheduler",
            action_name
        );
        assert!(!action.parallelizable, "{} mutates shared Pool state and should not default to parallel execution", action_name);
        assert_eq!(action.effect_class, "Mutating", "{} should be classified as mutating shared state", action_name);
        assert!(
            action.verifier_obligations.iter().any(|obligation| {
                obligation.category == "shared-state"
                    && obligation.feature == "shared-mutation:Pool"
                    && obligation.status == "checked-runtime"
                    && obligation.detail.contains("type_hash preservation=checked-runtime")
                    && obligation.detail.contains("lock_hash preservation=checked-runtime")
                    && obligation.detail.contains("field equality=checked-runtime")
                    && obligation.detail.contains("field transition=checked-runtime")
                    && obligation.detail.contains("transition fields:")
                    && obligation.detail.contains("preserved fields:")
            }),
            "{} should report fully verifier-covered &mut Pool state transitions for the source-level formulas: {:?}",
            action_name,
            action.verifier_obligations
        );
        assert!(
            action.verifier_obligations.iter().any(|obligation| {
                obligation.category == "pool-pattern"
                    && obligation.feature == "pool-mutation-invariants:Pool"
                    && obligation.status == "runtime-required"
                    && obligation.detail.contains("Generic shared mutation checks")
                    && obligation.detail.contains("pool_primitives[].invariant_families")
            }),
            "{} should keep pool-pattern invariant/admission semantics separate from checked shared mutation: {:?}",
            action_name,
            action.verifier_obligations
        );
        let pool_primitive = action
            .pool_primitives
            .iter()
            .find(|primitive| primitive.feature == "pool-mutation-invariants:Pool")
            .expect("AMM action should expose structured Pool mutation primitive metadata");
        assert_eq!(pool_primitive.operation, "mutation-invariants");
        assert_eq!(pool_primitive.status, "runtime-required");
        assert_eq!(pool_primitive.binding.as_deref(), Some("pool"));
        assert_eq!(pool_primitive.input_source.as_deref(), Some("Input"));
        assert_eq!(pool_primitive.input_index, Some(expected_input_index));
        assert_eq!(pool_primitive.output_source.as_deref(), Some("Output"));
        assert_eq!(pool_primitive.output_index, Some(expected_output_index));
        assert_eq!(pool_primitive.transition_fields.iter().map(String::as_str).collect::<Vec<_>>().as_slice(), expected_fields);
        assert_eq!(pool_primitive.preserved_fields.iter().map(String::as_str).collect::<Vec<_>>().as_slice(), expected_preserved);
        assert_eq!(pool_primitive.source_invariant_count, expected_invariant_count);
        assert_pool_component(pool_primitive, "field-transition=checked-runtime", action_name);
        for source_invariant in expected_source_invariants {
            assert_pool_component(pool_primitive, &format!("source-invariant:{}=checked-runtime", source_invariant), action_name);
            assert_pool_invariant_family(pool_primitive, source_invariant, "checked-runtime", "assert-invariant-cfg", action_name);
        }
        assert_pool_invariant_family(
            pool_primitive,
            expected_runtime_family,
            "runtime-required",
            expected_runtime_source,
            action_name,
        );
        let expected_runtime_blocker_class = match expected_runtime_family {
            "constant-product-pricing" => "phase2-deferred-amm-pricing",
            "proportional-liquidity-accounting" => "phase2-deferred-amm-liquidity-accounting",
            "proportional-withdrawal-accounting" => "phase2-deferred-amm-withdrawal-accounting",
            other => panic!("unexpected AMM runtime family: {}", other),
        };
        assert_pool_invariant_blocker_class(pool_primitive, expected_runtime_family, expected_runtime_blocker_class, action_name);
        assert_pool_runtime_input_blocker_class(pool_primitive, expected_runtime_family, expected_runtime_blocker_class, action_name);
        assert_pool_invariant_family(pool_primitive, "reserve-conservation", "checked-runtime", "transition-formula", action_name);
        assert!(
            !pool_primitive.runtime_required_components.iter().any(|component| component == "reserve-conservation"),
            "{} should discharge reserve conservation through checked field transition formula: {:?}",
            action_name,
            pool_primitive.runtime_required_components
        );
        assert_pool_invariant_family(
            pool_primitive,
            "pool-specific-admission",
            "runtime-required",
            "pool-specific-admission-abi",
            action_name,
        );
        assert_pool_invariant_blocker_class(pool_primitive, "pool-specific-admission", "phase2-deferred-pool-admission", action_name);
        assert_pool_runtime_input_blocker_class(
            pool_primitive,
            "pool-specific-admission",
            "phase2-deferred-pool-admission",
            action_name,
        );
        for field in ["token_a_symbol", "token_b_symbol"] {
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "pool-specific-admission",
                "Input",
                expected_input_index,
                "pool",
                Some(field),
                "mutate-input-field-bytes-8",
                8,
                action_name,
            );
        }
        if action_name == "swap_a_for_b" {
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "pool-specific-admission",
                "Input",
                0,
                "input",
                Some("symbol"),
                "input-cell-field-bytes-8",
                8,
                action_name,
            );
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "pool-specific-admission",
                "Output",
                0,
                "create_Token",
                Some("symbol"),
                "create-output-field-bytes-8",
                8,
                action_name,
            );
            assert_pool_component(pool_primitive, "pool-protocol:lp-supply-consistency=checked-runtime", action_name);
            assert_pool_invariant_family(
                pool_primitive,
                "lp-supply-consistency",
                "checked-runtime",
                "mutate-preserved-field-equality",
                action_name,
            );
            assert!(
                pool_primitive.runtime_required_components.iter().all(|component| component != "lp-supply-consistency"),
                "{} should discharge LP supply consistency through preserved Pool.total_lp equality: {:?}",
                action_name,
                pool_primitive.runtime_required_components
            );
            assert!(
                pool_primitive.runtime_input_requirements.iter().all(|requirement| requirement.component != "lp-supply-consistency"),
                "{} checked LP supply consistency should not retain total_lp runtime inputs: {:?}",
                action_name,
                pool_primitive.runtime_input_requirements
            );
            assert_pool_component(pool_primitive, "pool-protocol:reserve-conservation=checked-runtime", action_name);
            assert!(
                pool_primitive.runtime_input_requirements.iter().all(|requirement| requirement.component != "reserve-conservation"),
                "{} checked reserve conservation should not retain runtime inputs: {:?}",
                action_name,
                pool_primitive.runtime_input_requirements
            );
            assert_pool_invariant_family(pool_primitive, "fee-accounting", "runtime-required", "swap-fee-accounting-abi", action_name);
            assert_pool_invariant_blocker_class(pool_primitive, "fee-accounting", "phase2-deferred-pool-fee-policy", action_name);
            assert_pool_runtime_input_blocker_class(pool_primitive, "fee-accounting", "phase2-deferred-pool-fee-policy", action_name);
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "fee-accounting",
                "Input",
                0,
                "input",
                Some("amount"),
                "input-cell-field-u64",
                8,
                action_name,
            );
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "fee-accounting",
                "Input",
                expected_input_index,
                "pool",
                Some("fee_rate_bps"),
                "mutate-input-field-u16",
                2,
                action_name,
            );
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "constant-product-pricing",
                "Input",
                0,
                "input",
                Some("amount"),
                "input-cell-field-u64",
                8,
                action_name,
            );
            for field in ["reserve_a", "reserve_b"] {
                assert_pool_runtime_input_requirement(
                    pool_primitive,
                    "constant-product-pricing",
                    "Input",
                    expected_input_index,
                    "pool",
                    Some(field),
                    "mutate-input-field-u64",
                    8,
                    action_name,
                );
                assert_pool_runtime_input_requirement(
                    pool_primitive,
                    "constant-product-pricing",
                    "Output",
                    expected_output_index,
                    "pool",
                    Some(field),
                    "mutate-output-field-u64",
                    8,
                    action_name,
                );
            }
        }
        if action_name == "add_liquidity" {
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "pool-specific-admission",
                "Input",
                0,
                "token_a",
                Some("symbol"),
                "input-cell-field-bytes-8",
                8,
                action_name,
            );
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "pool-specific-admission",
                "Input",
                1,
                "token_b",
                Some("symbol"),
                "input-cell-field-bytes-8",
                8,
                action_name,
            );
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "pool-specific-admission",
                "Input",
                expected_input_index,
                "pool",
                Some("type_hash"),
                "mutate-input-type-id-32",
                32,
                action_name,
            );
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "pool-specific-admission",
                "Output",
                0,
                "create_LPReceipt",
                Some("pool_id"),
                "create-output-field-hash-32",
                32,
                action_name,
            );
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "proportional-liquidity-accounting",
                "Input",
                0,
                "token_a",
                Some("amount"),
                "input-cell-field-u64",
                8,
                action_name,
            );
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "proportional-liquidity-accounting",
                "Input",
                1,
                "token_b",
                Some("amount"),
                "input-cell-field-u64",
                8,
                action_name,
            );
            for field in ["reserve_a", "reserve_b", "total_lp"] {
                assert_pool_runtime_input_requirement(
                    pool_primitive,
                    "proportional-liquidity-accounting",
                    "Input",
                    expected_input_index,
                    "pool",
                    Some(field),
                    "mutate-input-field-u64",
                    8,
                    action_name,
                );
                assert_pool_runtime_input_requirement(
                    pool_primitive,
                    "proportional-liquidity-accounting",
                    "Output",
                    expected_output_index,
                    "pool",
                    Some(field),
                    "mutate-output-field-u64",
                    8,
                    action_name,
                );
            }
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "proportional-liquidity-accounting",
                "Output",
                0,
                "create_LPReceipt",
                Some("lp_amount"),
                "create-output-field-u64",
                8,
                action_name,
            );
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "lp-supply-consistency",
                "Output",
                0,
                "create_LPReceipt",
                Some("lp_amount"),
                "create-output-field-u64",
                8,
                action_name,
            );
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "lp-supply-consistency",
                "Input",
                expected_input_index,
                "pool",
                Some("total_lp"),
                "mutate-input-field-u64",
                8,
                action_name,
            );
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "lp-supply-consistency",
                "Output",
                expected_output_index,
                "pool",
                Some("total_lp"),
                "mutate-output-field-u64",
                8,
                action_name,
            );
        }
        if action_name == "remove_liquidity" {
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "pool-specific-admission",
                "Input",
                0,
                "receipt",
                Some("pool_id"),
                "input-cell-field-hash-32",
                32,
                action_name,
            );
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "pool-specific-admission",
                "Input",
                expected_input_index,
                "pool",
                Some("type_hash"),
                "mutate-input-type-id-32",
                32,
                action_name,
            );
            for index in [0, 1] {
                assert_pool_runtime_input_requirement(
                    pool_primitive,
                    "pool-specific-admission",
                    "Output",
                    index,
                    "create_Token",
                    Some("symbol"),
                    "create-output-field-bytes-8",
                    8,
                    action_name,
                );
            }
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "proportional-withdrawal-accounting",
                "Input",
                0,
                "receipt",
                Some("lp_amount"),
                "input-cell-field-u64",
                8,
                action_name,
            );
            for field in ["reserve_a", "reserve_b", "total_lp"] {
                assert_pool_runtime_input_requirement(
                    pool_primitive,
                    "proportional-withdrawal-accounting",
                    "Input",
                    expected_input_index,
                    "pool",
                    Some(field),
                    "mutate-input-field-u64",
                    8,
                    action_name,
                );
            }
            for field in ["reserve_a", "reserve_b"] {
                assert_pool_runtime_input_requirement(
                    pool_primitive,
                    "proportional-withdrawal-accounting",
                    "Output",
                    expected_output_index,
                    "pool",
                    Some(field),
                    "mutate-output-field-u64",
                    8,
                    action_name,
                );
            }
            for index in [0, 1] {
                assert_pool_runtime_input_requirement(
                    pool_primitive,
                    "proportional-withdrawal-accounting",
                    "Output",
                    index,
                    "create_Token",
                    Some("amount"),
                    "create-output-field-u64",
                    8,
                    action_name,
                );
            }
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "lp-supply-consistency",
                "Input",
                0,
                "receipt",
                Some("lp_amount"),
                "input-cell-field-u64",
                8,
                action_name,
            );
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "lp-supply-consistency",
                "Input",
                expected_input_index,
                "pool",
                Some("total_lp"),
                "mutate-input-field-u64",
                8,
                action_name,
            );
            assert_pool_runtime_input_requirement(
                pool_primitive,
                "lp-supply-consistency",
                "Output",
                expected_output_index,
                "pool",
                Some("total_lp"),
                "mutate-output-field-u64",
                8,
                action_name,
            );
        }
        if action_name != "swap_a_for_b" {
            assert_pool_invariant_family(
                pool_primitive,
                "lp-supply-consistency",
                "runtime-required",
                "pool-lp-supply-consistency-abi",
                action_name,
            );
            assert_pool_invariant_blocker_class(
                pool_primitive,
                "lp-supply-consistency",
                "phase2-deferred-lp-supply-policy",
                action_name,
            );
            assert_pool_runtime_input_blocker_class(
                pool_primitive,
                "lp-supply-consistency",
                "phase2-deferred-lp-supply-policy",
                action_name,
            );
            assert!(
                pool_primitive.runtime_required_components.iter().any(|component| component == "lp-supply-consistency"),
                "{} should keep LP supply consistency as a Pool primitive runtime requirement",
                action_name
            );
        }
    }

    let add_liquidity = result.metadata.actions.iter().find(|action| action.name == "add_liquidity").expect("add_liquidity metadata");
    let pool_param = add_liquidity.params.iter().find(|param| param.name == "pool").expect("add_liquidity pool param");
    assert!(pool_param.schema_pointer_abi, "&mut Pool should still use the schema pointer ABI");
    assert!(pool_param.type_hash_pointer_abi, "&mut Pool type_hash should require a trusted TypeHash pointer ABI");
    assert!(pool_param.type_hash_length_abi, "&mut Pool type_hash should require a trusted TypeHash length ABI");
    assert_eq!(pool_param.type_hash_len, Some(32), "&mut Pool TypeHash ABI must be exactly 32 bytes");
    assert!(
        add_liquidity.fail_closed_runtime_features.is_empty(),
        "add_liquidity should verify &mut Pool type_hash through the parameter ABI without fail-closed debt: {:?}",
        add_liquidity.fail_closed_runtime_features
    );
    let remove_liquidity =
        result.metadata.actions.iter().find(|action| action.name == "remove_liquidity").expect("remove_liquidity metadata");
    assert!(
        remove_liquidity.fail_closed_runtime_features.is_empty(),
        "remove_liquidity should compare receipt.pool_id against the trusted Pool TypeHash bytes without fail-closed debt: {:?}",
        remove_liquidity.fail_closed_runtime_features
    );
    assert!(
        asm.contains("# cellscript abi: schema param pool type_hash pointer=a2 length=a3 size=32"),
        "&mut Pool type_hash ABI should be explicit in the verifier assembly:\n{}",
        asm
    );
    assert!(
        asm.contains("# cellscript abi: verify output bytes field LPReceipt.pool_id offset=0 size=32 against loaded bytes"),
        "LPReceipt.pool_id should be checked against loaded TypeHash bytes:\n{}",
        asm
    );
}

#[test]
fn launch_seed_pool_composition_is_scheduler_visible() {
    let result = compile_file(example_path("launch.cell"), CompileOptions::default()).expect("launch example should compile");
    let asm = String::from_utf8(result.artifact_bytes.clone()).expect("launch asm should be utf8");
    let launch_token = result.metadata.actions.iter().find(|action| action.name == "launch_token").expect("launch_token metadata");

    assert!(
        !launch_token.touches_shared.is_empty(),
        "launch_token calls seed_pool and returns Pool, so shared Pool touch metadata must not be lost"
    );
    assert!(!launch_token.parallelizable, "launch_token composes Pool creation and should not default to parallel execution");
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
        asm.contains("# cellscript abi: call seed_pool schema param token_a pointer=a0 length=a1"),
        "launch_token -> seed_pool must use pointer+length ABI for Token arguments:\n{}",
        asm
    );
    assert!(
        asm.contains(
            "# cellscript abi: call seed_pool schema param token_a has no tracked ABI length; pass zero length to fail closed"
        ),
        "launch_token must fail fast when its locally-created pool token cannot be represented as runtime schema bytes:\n{}",
        asm
    );
    assert!(
        asm.contains("# cellscript abi: call seed_pool schema param token_b pointer=a2 length=a3"),
        "launch_token -> seed_pool must preserve the second Token pointer+length ABI:\n{}",
        asm
    );
    assert!(
        asm.contains("# cellscript abi: call seed_pool fixed-byte param provider pointer=a5 length=a6 size=32"),
        "launch_token -> seed_pool must preserve Address pointer+length ABI:\n{}",
        asm
    );
    assert!(
        launch_token.fail_closed_runtime_features.is_empty(),
        "launch_token seed_pool tuple-return projection and fixed tuple-array distribution should be verifier-coverable: {:?}",
        launch_token.fail_closed_runtime_features
    );
    assert!(
        launch_token.verifier_obligations.iter().any(|obligation| {
            obligation.category == "pool-pattern"
                && obligation.feature == "pool-composition:Pool"
                && obligation.status == "runtime-required"
                && obligation.detail.contains("launch-builder/pool-pattern composition")
        }),
        "launch_token should inherit explicit pool-pattern obligations from seed_pool composition: {:?}",
        launch_token.verifier_obligations
    );
    let launch_pool_primitive = launch_token
        .pool_primitives
        .iter()
        .find(|primitive| primitive.feature == "pool-composition:Pool")
        .expect("launch_token should expose structured Pool composition primitive metadata");
    assert_eq!(launch_pool_primitive.operation, "composition");
    assert_eq!(launch_pool_primitive.status, "runtime-required");
    assert!(launch_pool_primitive.callee.as_deref().is_some_and(|callee| callee.contains("seed_pool")));
    assert_eq!(launch_pool_primitive.source_invariant_count, 3);
    assert_pool_component(launch_pool_primitive, "shared-touch-propagation=checked-metadata", "launch_token");
    assert_pool_component(launch_pool_primitive, "source-invariant:initial-mint-cap=checked-runtime", "launch_token");
    assert_pool_component(launch_pool_primitive, "source-invariant:pool-seed-cap=checked-runtime", "launch_token");
    assert_pool_component(launch_pool_primitive, "source-invariant:distribution-cap=checked-runtime", "launch_token");
    assert_pool_component(launch_pool_primitive, "launch-pool-atomicity:minted-equals-initial-mint=checked-runtime", "launch_token");
    assert_pool_component(launch_pool_primitive, "launch-pool-atomicity:seed-token-amount=checked-runtime", "launch_token");
    assert_pool_component(launch_pool_primitive, "launch-pool-atomicity:symbol-consistency=checked-runtime", "launch_token");
    assert_pool_component(
        launch_pool_primitive,
        "launch-pool-atomicity:distribution-sum-plus-seed-lte-initial-mint=checked-runtime",
        "launch_token",
    );
    assert_pool_component(launch_pool_primitive, "callee-pool-admission:seed-token-symbol-handoff=checked-runtime", "launch_token");
    assert_pool_component(launch_pool_primitive, "callee-pool-admission:paired-token-symbol-handoff=checked-runtime", "launch_token");
    assert_pool_component(launch_pool_primitive, "callee-pool-admission:fee-bound-handoff=checked-runtime", "launch_token");
    assert_pool_component(launch_pool_primitive, "pool-id-continuity:tuple-return-projection=checked-runtime", "launch_token");
    assert_pool_component(launch_pool_primitive, "pool-id-continuity:pool-type-hash-return-abi=checked-runtime", "launch_token");
    assert_pool_component(launch_pool_primitive, "pool-id-continuity:lp-receipt-pool-id-return-abi=checked-runtime", "launch_token");
    assert_pool_component(launch_pool_primitive, "pool-id-continuity:callee-output-field-equality=checked-runtime", "launch_token");
    assert_pool_invariant_family(
        launch_pool_primitive,
        "callee-pool-admission",
        "runtime-required",
        "pool-composition-callee-admission-abi",
        "launch_token",
    );
    assert_pool_invariant_family(
        launch_pool_primitive,
        "launch-pool-atomicity",
        "runtime-required",
        "launch-pool-atomicity-abi",
        "launch_token",
    );
    assert_pool_invariant_blocker_class(
        launch_pool_primitive,
        "callee-pool-admission",
        "phase2-deferred-pool-admission",
        "launch_token",
    );
    assert_pool_runtime_input_blocker_class(
        launch_pool_primitive,
        "callee-pool-admission",
        "phase2-deferred-pool-admission",
        "launch_token",
    );
    assert_pool_invariant_blocker_class(
        launch_pool_primitive,
        "launch-pool-atomicity",
        "phase2-deferred-launch-atomicity",
        "launch_token",
    );
    assert_pool_runtime_input_blocker_class(
        launch_pool_primitive,
        "launch-pool-atomicity",
        "phase2-deferred-launch-atomicity",
        "launch_token",
    );
    assert_pool_invariant_family(
        launch_pool_primitive,
        "pool-id-continuity",
        "checked-runtime",
        "callee-output-field-coupling+tuple-return-abi",
        "launch_token",
    );
    assert!(launch_pool_primitive.runtime_required_components.iter().any(|component| component == "callee-pool-admission"));
    assert!(launch_pool_primitive.runtime_required_components.iter().any(|component| component == "launch-pool-atomicity"));
    assert!(
        launch_pool_primitive.runtime_required_components.iter().all(|component| component != "pool-id-continuity"),
        "pool-id-continuity should be discharged for the controlled seed_pool tuple return path: {:?}",
        launch_pool_primitive.runtime_required_components
    );
    assert_pool_runtime_input_requirement(
        launch_pool_primitive,
        "callee-pool-admission",
        "Output",
        5,
        "create_Token",
        Some("type_hash"),
        "create-output-type-id-32",
        32,
        "launch_token",
    );
    assert_pool_runtime_input_requirement(
        launch_pool_primitive,
        "callee-pool-admission",
        "Param",
        4,
        "pool_paired_token",
        Some("type_hash"),
        "schema-param-type-id-32",
        32,
        "launch_token",
    );
    assert_pool_runtime_input_requirement(
        launch_pool_primitive,
        "callee-pool-admission",
        "Param",
        4,
        "pool_paired_token",
        Some("symbol"),
        "schema-param-field-bytes-8",
        8,
        "launch_token",
    );
    assert_pool_runtime_input_requirement(
        launch_pool_primitive,
        "callee-pool-admission",
        "Output",
        5,
        "create_Token",
        Some("symbol"),
        "create-output-field-bytes-8",
        8,
        "launch_token",
    );
    assert_pool_runtime_input_requirement(
        launch_pool_primitive,
        "callee-pool-admission",
        "Param",
        5,
        "fee_rate_bps",
        None,
        "param-u16",
        2,
        "launch_token",
    );
    assert_pool_runtime_input_requirement(
        launch_pool_primitive,
        "launch-pool-atomicity",
        "Param",
        2,
        "initial_mint",
        None,
        "param-u64",
        8,
        "launch_token",
    );
    assert_pool_runtime_input_requirement(
        launch_pool_primitive,
        "launch-pool-atomicity",
        "Param",
        3,
        "pool_seed_amount",
        None,
        "param-u64",
        8,
        "launch_token",
    );
    assert_pool_runtime_input_requirement(
        launch_pool_primitive,
        "launch-pool-atomicity",
        "Param",
        7,
        "distribution",
        None,
        "param-fixed-array-bytes-160",
        160,
        "launch_token",
    );
    assert_pool_runtime_input_requirement(
        launch_pool_primitive,
        "launch-pool-atomicity",
        "Output",
        0,
        "create_MintAuthority",
        Some("minted"),
        "create-output-field-u64",
        8,
        "launch_token",
    );
    assert_pool_runtime_input_requirement(
        launch_pool_primitive,
        "launch-pool-atomicity",
        "Output",
        0,
        "create_MintAuthority",
        Some("token_symbol"),
        "create-output-field-bytes-8",
        8,
        "launch_token",
    );
    assert_pool_runtime_input_requirement(
        launch_pool_primitive,
        "launch-pool-atomicity",
        "Output",
        5,
        "create_Token",
        Some("amount"),
        "create-output-field-u64",
        8,
        "launch_token",
    );
    assert_pool_runtime_input_requirement(
        launch_pool_primitive,
        "launch-pool-atomicity",
        "Output",
        5,
        "create_Token",
        Some("symbol"),
        "create-output-field-bytes-8",
        8,
        "launch_token",
    );
    assert!(
        launch_pool_primitive.runtime_input_requirements.iter().all(|requirement| requirement.component != "pool-id-continuity"),
        "pool-id-continuity runtime inputs should be discharged by tuple return ABI metadata: {:?}",
        launch_pool_primitive.runtime_input_requirements
    );
    assert!(
        asm.contains("# cellscript abi: tuple call return field .0 projected from return register")
            && asm.contains("# cellscript abi: tuple call return field .1 projected from return register"),
        "seed_pool tuple return should project Pool/LPReceipt from the call return ABI:\n{}",
        asm
    );
    assert!(
        asm.contains("# cellscript abi: construct tuple aggregate")
            && asm.contains("# cellscript abi: return tuple field .0 via a0")
            && asm.contains("# cellscript abi: return tuple field .1 via a1"),
        "seed_pool tuple callee should return Pool/LPReceipt through the register ABI:\n{}",
        asm
    );
    assert!(
        !asm.contains("field access symbolic runtime is not executable"),
        "launch example should not fall back to generic field-access fail-closed lowering:\n{}",
        asm
    );

    let simple_launch = result.metadata.actions.iter().find(|action| action.name == "simple_launch").expect("simple_launch metadata");
    assert!(
        simple_launch.touches_shared.is_empty(),
        "simple_launch does not compose Pool creation and should not inherit launch_token's shared touch"
    );
    let recipients = simple_launch.params.iter().find(|param| param.name == "recipients").expect("recipients param metadata");
    assert!(recipients.fixed_byte_pointer_abi);
    assert!(recipients.fixed_byte_length_abi);
    assert_eq!(recipients.fixed_byte_len, Some(320));
    assert!(
        simple_launch.fail_closed_runtime_features.is_empty(),
        "simple_launch fixed tuple-array distribution and recipient locks should be fully verifier-coverable: {:?}",
        simple_launch.fail_closed_runtime_features
    );
    assert!(
        simple_launch.verifier_obligations.iter().all(|obligation| obligation.category != "pool-pattern"),
        "simple_launch does not compose a Pool and should not inherit pool-pattern obligations: {:?}",
        simple_launch.verifier_obligations
    );
}
