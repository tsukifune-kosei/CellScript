//! Real compiler/checker boundary mutations. Rebinding sidecar and semantic
//! identities must not turn a contradictory builder/policy projection valid.
//! The machine cases cover the exact bounded policy wrapper and adapters; they
//! do not establish arbitrary program equivalence or action predicate meaning.

use cellscript::artifact::{ArtifactAction, ArtifactContext, ArtifactDeclaration, ArtifactDispatch};
use cellscript::{
    compile_path_with_executable_surface_policy, CellScriptEdition, CompileEntryScope, CompileOptions, ExecutableSurfacePolicy,
};
use cellscript_artifact_checker::{
    canonical_hash, check_bundle_values, parse_elf, CheckerBudgets, CheckerError, CheckerRejectionCode, EntryDispatchContract,
    PolicyWitnessContract, SourceArtifactMap, ValueProvenance, VerifiedLoweringRecord, LOWERING_RECORD_SCHEMA, SOURCE_MAP_SCHEMA,
    TYPED_SEMANTICS_SCHEMA,
};
use serde_json::Value;

const SOURCE: &str = r#"
module policy_artifact_checker
resource Token has store, consume { amount: u64 }
action check_z() { verification require true }
action check_a() { verification require true }
action mint(witness amount: u64, witness recipient: Address) {
    verification
    require amount > 0
    create Token { amount: amount } with_lock(recipient)
}
action burn(input token: Token) { verification consume token }
"#;

const STACK_ARGS_SOURCE: &str = r#"
module policy_stack_args
resource Token has store, consume { amount: u64 }
action mint(
    witness amount: u64, witness p1: u64, witness p2: u64,
    witness p3: u64, witness p4: u64, witness p5: u64,
    witness p6: u64, witness p7: u64, witness p8: u64,
    witness recipient: Address
) {
    verification
    require amount > 0
    create Token { amount: amount } with_lock(recipient)
}
"#;

fn declaration() -> ArtifactDeclaration {
    ArtifactDeclaration {
        name: "token-policy".to_string(),
        context: ArtifactContext::TypeGroup { resource: "Token".to_string() },
        dispatch: ArtifactDispatch::PolicyWitnessV1,
        actions: vec![ArtifactAction { tag: 40, action: "burn".to_string() }, ArtifactAction { tag: 10, action: "mint".to_string() }],
        common_checks: vec!["check_z".to_string(), "check_a".to_string()],
    }
}

#[derive(Clone)]
struct Fixture {
    artifact: Vec<u8>,
    metadata: Value,
    record: VerifiedLoweringRecord,
    source_map: SourceArtifactMap,
}

impl Fixture {
    fn new(edition: CellScriptEdition) -> Self {
        Self::new_with(edition, 0, declaration())
    }

    fn new_with(edition: CellScriptEdition, opt_level: u8, declaration: ArtifactDeclaration) -> Self {
        Self::new_source_with(SOURCE, edition, opt_level, declaration)
    }

    fn new_source_with(source_text: &str, edition: CellScriptEdition, opt_level: u8, declaration: ArtifactDeclaration) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("main.cell");
        std::fs::write(&source, source_text).unwrap();
        let result = compile_path_with_executable_surface_policy(
            source.to_str().unwrap(),
            CompileOptions { edition, opt_level, target: Some("riscv64-elf".to_string()), ..CompileOptions::default() },
            Some(CompileEntryScope::Artifact(declaration)),
            ExecutableSurfacePolicy::DenyFailClosed,
        )
        .unwrap();
        let fixture = Self {
            artifact: result.artifact_bytes,
            metadata: serde_json::to_value(result.metadata).unwrap(),
            record: result.verified_lowering_record.unwrap(),
            source_map: result.source_artifact_map.unwrap(),
        };
        fixture.check().unwrap();
        fixture
    }

    fn check(&self) -> Result<(), CheckerError> {
        check_bundle_values(&self.artifact, &self.metadata, &self.record, &self.source_map, &CheckerBudgets::default()).map(|_| ())
    }

    fn policy_mut(&mut self) -> &mut PolicyWitnessContract {
        let EntryDispatchContract::PolicyWitnessV1(policy) = &mut self.record.typed_semantics.foundation.entry_contract.dispatch
        else {
            panic!("expected policy dispatch");
        };
        policy
    }

    fn param_mut(&mut self, action: &str, index: usize) -> &mut Value {
        &mut self.metadata["actions"].as_array_mut().unwrap().iter_mut().find(|entry| entry["name"] == action).unwrap()["params"]
            [index]
    }

    fn rebind_sidecars(&mut self) {
        let record_hash = canonical_hash(LOWERING_RECORD_SCHEMA, &self.record).unwrap();
        self.source_map.lowering_record_hash = record_hash.clone();
        let source_map_hash = canonical_hash(SOURCE_MAP_SCHEMA, &self.source_map).unwrap();
        let verified_bundle_id = canonical_hash(
            "cellscript-verified-bundle-id-v1",
            &(
                self.record.artifact_hash.as_str(),
                self.record.typed_semantics_hash.as_str(),
                self.record.compatibility_profile_hash.as_str(),
                record_hash.as_str(),
                source_map_hash.as_str(),
                self.source_map.source_digest.as_str(),
            ),
        )
        .unwrap();
        self.metadata["verified_artifact"]["lowering_record_hash"] = record_hash.into();
        self.metadata["verified_artifact"]["source_map_hash"] = source_map_hash.into();
        self.metadata["verified_artifact"]["verified_bundle_id"] = verified_bundle_id.into();
    }

    fn bind_artifact_identity(&mut self) {
        let artifact_hash = cellscript_artifact_checker::hex_encode(&cellscript_artifact_checker::ckb_blake2b256(&self.artifact));
        self.record.artifact_hash.clone_from(&artifact_hash);
        self.record.artifact_size_bytes = self.artifact.len() as u64;
        self.source_map.artifact_hash.clone_from(&artifact_hash);
        self.metadata["artifact_hash"] = artifact_hash.clone().into();
        self.metadata["artifact_size_bytes"] = (self.artifact.len() as u64).into();
        self.metadata["verified_artifact"]["deployable_artifact_id"] = artifact_hash.into();
        self.rebind_sidecars();
    }

    fn replace_machine_word(&mut self, address: u64, word: u32) {
        let elf = parse_elf(&self.artifact, CheckerBudgets::default().instructions).unwrap();
        let offset = (elf.text.offset + address - elf.text.address) as usize;
        self.artifact[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
        for block in &mut self.record.blocks {
            let start = (elf.text.offset + block.range.start - elf.text.address) as usize;
            let end = (elf.text.offset + block.range.end - elf.text.address) as usize;
            block.byte_digest =
                cellscript_artifact_checker::domain_hash_bytes("cellscript-machine-block-v1", &self.artifact[start..end]);
        }
        self.bind_artifact_identity();
    }

    fn rebind_policy_identity(&mut self) {
        let typed = &mut self.record.typed_semantics;
        typed.canonicalize();
        let foundation = &mut typed.foundation;
        let contract = &mut foundation.entry_contract;
        let previous_node = contract.semantic_node_id.clone();
        contract.semantic_node_id = canonical_hash(
            "cellscript-semantic-node-entry-contract-v2",
            &(
                contract.script_role.as_str(),
                contract.trigger.as_str(),
                contract.exact_entry.as_str(),
                &contract.dispatch,
                contract.entry_payload_abi.as_str(),
                contract.witness_placement_abi.as_str(),
                contract.witness_placement_field.as_str(),
                contract.witness_placement_source.as_str(),
            ),
        )
        .unwrap();
        for mapping in &mut self.source_map.semantic_mappings {
            if mapping.semantic_node_id == previous_node {
                mapping.semantic_node_id = contract.semantic_node_id.clone();
            }
        }
        let roots = foundation
            .provenance
            .nodes
            .iter()
            .filter(|node| !matches!(node.provenance, ValueProvenance::Derived { .. }))
            .map(|node| node.id.as_str())
            .collect::<Vec<_>>();
        foundation.identities.core_semantic_id = canonical_hash(
            "cellscript-core-semantic-id-v2",
            &(
                typed.failure_semantics,
                &typed.types,
                &foundation.roles,
                &foundation.dispositions,
                &foundation.claims,
                &foundation.legacy_nodes,
            ),
        )
        .unwrap();
        foundation.identities.entry_contract_id = canonical_hash(
            "cellscript-entry-contract-id-v1",
            &(
                foundation.identities.core_semantic_id.as_str(),
                &foundation.entry_contract,
                roots,
                foundation.entry_contract.entry_payload_abi.as_str(),
                foundation.entry_contract.witness_placement_abi.as_str(),
            ),
        )
        .unwrap();
        foundation.identities.artifact_contract_id = canonical_hash(
            "cellscript-artifact-contract-id-v1",
            &(foundation.identities.entry_contract_id.as_str(), &foundation.artifact_contract),
        )
        .unwrap();
        self.source_map.canonicalize();
        self.metadata["verified_artifact"]["core_semantic_id"] = foundation.identities.core_semantic_id.clone().into();
        self.metadata["verified_artifact"]["entry_contract_id"] = foundation.identities.entry_contract_id.clone().into();
        self.metadata["verified_artifact"]["artifact_contract_id"] = foundation.identities.artifact_contract_id.clone().into();
        self.record.typed_semantics_hash = canonical_hash(TYPED_SEMANTICS_SCHEMA, typed).unwrap();
        self.metadata["typed_semantics"] = serde_json::to_value(typed).unwrap();
        self.metadata["typed_semantics_hash"] = self.record.typed_semantics_hash.clone().into();
        self.rebind_sidecars();
    }
}

fn policy_block<'a>(fixture: &'a Fixture, prefix: &str) -> &'a cellscript_artifact_checker::LoweringBlock {
    fixture
        .record
        .blocks
        .iter()
        .find(|block| {
            block.owner_entry == "wrapper:_cellscript_entry"
                && block.machine_label.as_deref().is_some_and(|label| {
                    label
                        .strip_prefix(prefix)
                        .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()))
                })
        })
        .unwrap()
}

#[test]
fn real_policy_bundle_and_unchanged_identity_rebinding_are_valid_in_both_editions() {
    for edition in [CellScriptEdition::Edition2026, CellScriptEdition::Edition2027] {
        let mut fixture = Fixture::new(edition);
        let original_record = canonical_hash(LOWERING_RECORD_SCHEMA, &fixture.record).unwrap();
        fixture.rebind_policy_identity();
        assert_eq!(canonical_hash(LOWERING_RECORD_SCHEMA, &fixture.record).unwrap(), original_record);
        fixture.check().unwrap();
    }
}

#[test]
fn policy_dispatch_machine_contract_covers_editions_optimizers_tag_extremes_and_no_common_checks() {
    for edition in [CellScriptEdition::Edition2026, CellScriptEdition::Edition2027] {
        for opt_level in 0..=3 {
            Fixture::new_with(edition, opt_level, declaration()).check().unwrap();
        }
    }

    let mut one_payload = declaration();
    one_payload.actions = vec![ArtifactAction { tag: 1, action: "mint".into() }];
    one_payload.common_checks = vec!["check_z".into()];
    let mut one_payload_free = declaration();
    one_payload_free.actions = vec![ArtifactAction { tag: 7, action: "burn".into() }];
    one_payload_free.common_checks.clear();
    for opt_level in 0..=3 {
        Fixture::new_with(CellScriptEdition::Edition2027, opt_level, one_payload.clone()).check().unwrap();
        Fixture::new_with(CellScriptEdition::Edition2027, opt_level, one_payload_free.clone()).check().unwrap();
    }

    let mut extreme = declaration();
    extreme.actions = vec![ArtifactAction { tag: u32::MAX, action: "burn".into() }, ArtifactAction { tag: 0, action: "mint".into() }];
    extreme.common_checks.clear();
    for opt_level in 0..=3 {
        Fixture::new_with(CellScriptEdition::Edition2027, opt_level, extreme.clone()).check().unwrap();
    }
}

#[test]
fn rebound_policy_machine_mutations_cannot_change_selector_dispatch_or_adapter_dataflow() {
    let valid = Fixture::new(CellScriptEdition::Edition2027);
    let elf = parse_elf(&valid.artifact, CheckerBudgets::default().instructions).unwrap();
    let wrapper_blocks =
        valid.record.blocks.iter().filter(|block| block.owner_entry == "wrapper:_cellscript_entry").collect::<Vec<_>>();
    let current_hash_syscall = elf
        .syscall_addresses
        .iter()
        .copied()
        .filter(|address| wrapper_blocks.iter().any(|block| block.range.contains(*address)))
        .max()
        .unwrap();
    let copied = policy_block(&valid, ".Lentry_witness_v2_copy_done_").range.start;
    let record_loop = policy_block(&valid, ".Lpolicy_record_").range.start;
    let record_base = elf
        .instructions
        .iter()
        .find(|instruction| {
            wrapper_blocks.iter().any(|block| block.range.contains(instruction.address)) && is_add(instruction.word, 15, 14, 5)
        })
        .unwrap()
        .address;
    let key_loop = policy_block(&valid, ".Lpolicy_key_order_loop_").range.start;
    let ordered = policy_block(&valid, ".Lpolicy_key_ordered_").range.start;
    let hash_loop = policy_block(&valid, ".Lpolicy_current_hash_loop_").range.start;
    let first_variant = valid
        .record
        .blocks
        .iter()
        .filter(|block| {
            block.owner_entry == "wrapper:_cellscript_entry"
                && block.machine_label.as_deref().is_some_and(|label| label.starts_with(".Lpolicy_variant_"))
        })
        .min_by_key(|block| block.range.start)
        .unwrap()
        .range
        .start;
    let first_adapter = valid
        .record
        .entries
        .iter()
        .filter(|entry| entry.name.starts_with(".Lpolicy_action_adapter_"))
        .min_by_key(|entry| valid.record.blocks.iter().find(|block| block.id == entry.entry_block).unwrap().range.start)
        .unwrap();
    let adapter_copy = valid
        .record
        .blocks
        .iter()
        .filter(|block| block.owner_entry == first_adapter.id)
        .find(|block| block.machine_label.as_deref().is_some_and(|label| label.starts_with(".Lpolicy_args_copy_")))
        .unwrap()
        .range
        .start;
    let common_target = valid
        .record
        .entries
        .iter()
        .find(|entry| entry.id == "action:check_z")
        .and_then(|entry| valid.record.blocks.iter().find(|block| block.id == entry.entry_block))
        .unwrap()
        .range
        .start;
    let common_call = elf
        .control_flow
        .iter()
        .find(|flow| flow.target == common_target && wrapper_blocks.iter().any(|block| block.range.contains(flow.address)))
        .unwrap()
        .address;
    let mutations = [
        ("current-script-hash-syscall", current_hash_syscall - 4),
        ("policy-magic", copied + 32),
        ("dynvec-record-bound", record_loop - 36),
        ("record-layout", record_base + 4),
        ("strict-key-order", key_loop + 24),
        ("type-role", ordered + 8),
        ("selected-tag", hash_loop + 68),
        ("common-check-failure", common_call + 4),
        ("variant-args-pointer", first_variant + 4),
        ("adapter-private-copy", adapter_copy + 8),
    ];
    for (name, address) in mutations {
        let mut changed = valid.clone();
        let word = elf.instructions.iter().find(|instruction| instruction.address == address).unwrap().word;
        changed.replace_machine_word(address, word ^ (1 << 20));
        let error = changed.check().unwrap_err();
        assert_eq!(error.code, CheckerRejectionCode::V2420TypedMachineBindingInvalid, "{name}: {error}");
    }
}

#[test]
fn typed_outgoing_stack_args_are_bound_to_the_policy_adapter_frame() {
    let declaration = ArtifactDeclaration {
        name: "stack-policy".into(),
        context: ArtifactContext::TypeGroup { resource: "Token".into() },
        dispatch: ArtifactDispatch::PolicyWitnessV1,
        actions: vec![ArtifactAction { tag: 1, action: "mint".into() }],
        common_checks: Vec::new(),
    };
    let valid = Fixture::new_source_with(STACK_ARGS_SOURCE, CellScriptEdition::Edition2027, 3, declaration);
    let adapter = valid.record.entries.iter().find(|entry| entry.name.starts_with(".Lpolicy_action_adapter_")).unwrap();
    assert!(adapter.frame_size_bytes > 5_376);

    let mut changed = valid.clone();
    let adapter_id = adapter.id.clone();
    changed.record.entries.iter_mut().find(|entry| entry.id == adapter_id).unwrap().frame_size_bytes += 16;
    for block in changed.record.blocks.iter_mut().filter(|block| block.owner_entry == adapter_id) {
        block.frame_size_bytes += 16;
    }
    changed.rebind_sidecars();
    let error = changed.check().unwrap_err();
    assert_eq!(error.code, CheckerRejectionCode::V2420TypedMachineBindingInvalid, "{error}");
    assert!(error.message.contains("policy positional adapter frame contract changed"), "{error}");
}

fn is_add(word: u32, rd: u32, rs1: u32, rs2: u32) -> bool {
    word & 0x7f == 0x33
        && (word >> 25) & 0x7f == 0
        && (word >> 12) & 0x7 == 0
        && (word >> 7) & 0x1f == rd
        && (word >> 15) & 0x1f == rs1
        && (word >> 20) & 0x1f == rs2
}

#[test]
fn raw_builder_param_mutations_reject_despite_rebound_outer_identities() {
    let fixture = Fixture::new(CellScriptEdition::Edition2027);
    for mutation in [
        "name",
        "type",
        "source",
        "mut",
        "ref",
        "cell-skip",
        "scalar-skip",
        "lock-args",
        "schema",
        "fixed-width",
        "fixed-flag",
        "hash-flag",
        "bounded",
    ] {
        let mut changed = fixture.clone();
        match mutation {
            "name" => changed.param_mut("mint", 0)["name"] = "other".into(),
            "type" => changed.param_mut("mint", 0)["ty"] = "u128".into(),
            "source" => changed.param_mut("mint", 0)["source"] = "lock_args".into(),
            "mut" => changed.param_mut("mint", 0)["is_mut"] = true.into(),
            "ref" => changed.param_mut("mint", 0)["is_ref"] = true.into(),
            "cell-skip" => changed.param_mut("burn", 0)["cell_bound_abi"] = false.into(),
            "scalar-skip" => changed.param_mut("mint", 0)["cell_bound_abi"] = true.into(),
            "lock-args" => changed.param_mut("mint", 0)["lock_args_data_source"] = true.into(),
            "schema" => changed.param_mut("mint", 0)["schema_pointer_abi"] = true.into(),
            "fixed-width" => changed.param_mut("mint", 1)["fixed_byte_len"] = 31.into(),
            "fixed-flag" => changed.param_mut("mint", 1)["fixed_byte_length_abi"] = false.into(),
            "hash-flag" => changed.param_mut("burn", 0)["type_hash_pointer_abi"] = true.into(),
            "bounded" => changed.param_mut("burn", 0)["bounded_runtime_contract"] = "type-group-inputs-v1".into(),
            _ => unreachable!(),
        }
        changed.rebind_sidecars();
        let error = changed.check().unwrap_err();
        assert_eq!(error.code, CheckerRejectionCode::V2410MetadataBindingMismatch, "{mutation}: {error}");
        assert!(error.message.contains("policy builder parameter"), "{mutation}: {error}");
    }
}

#[test]
fn raw_policy_declaration_and_outer_abi_mutations_reject_after_rebinding() {
    let fixture = Fixture::new(CellScriptEdition::Edition2027);
    for mutation in
        ["tag", "action", "common-order", "resource", "name", "records", "bytes", "payload", "placement", "field", "source", "missing"]
    {
        let mut changed = fixture.clone();
        let policy = &mut changed.metadata["runtime"]["policy_artifact"];
        match mutation {
            "tag" => policy["declaration"]["actions"][0]["tag"] = 11.into(),
            "action" => policy["declaration"]["actions"][0]["action"] = "burn".into(),
            "common-order" => policy["declaration"]["common_checks"].as_array_mut().unwrap().swap(0, 1),
            "resource" => policy["declaration"]["context"]["resource"] = "OtherToken".into(),
            "name" => policy["declaration"]["name"] = "other-policy".into(),
            "records" => policy["max_records"] = 9.into(),
            "bytes" => policy["max_witness_bytes"] = 4097.into(),
            "payload" => policy["payload_abi"] = "cellscript-entry-witness-v1".into(),
            "placement" => policy["placement_abi"] = "raw".into(),
            "field" => policy["placement_field"] = "lock".into(),
            "source" => policy["placement_source"] = "input[0]".into(),
            "missing" => {
                changed.metadata["runtime"].as_object_mut().unwrap().remove("policy_artifact");
            }
            _ => unreachable!(),
        }
        changed.rebind_sidecars();
        let error = changed.check().unwrap_err();
        assert_eq!(error.code, CheckerRejectionCode::V2410MetadataBindingMismatch, "{mutation}: {error}");
        assert!(error.message.contains("runtime.policy_artifact"), "{mutation}: {error}");
    }
}

#[test]
fn typed_policy_counts_payload_identity_and_selector_require_concrete_evidence() {
    let fixture = Fixture::new(CellScriptEdition::Edition2027);
    for mutation in ["input-count", "output-count", "payload-schema", "selector-content", "selector-label", "unknown", "wrapper"] {
        let mut changed = fixture.clone();
        match mutation {
            "input-count" => changed.policy_mut().variants[0].input_count = 1,
            "output-count" => changed.policy_mut().variants[0].output_count = 2,
            "payload-schema" => changed.policy_mut().variants[0].payload_schema_hash = "unbound-params".into(),
            "selector-label" => changed.policy_mut().selector_node_id = "caller-chosen-label".into(),
            "selector-content" => {
                let id = changed.policy_mut().selector_node_id.clone();
                let node = changed.record.typed_semantics.foundation.provenance.nodes.iter_mut().find(|node| node.id == id).unwrap();
                let ValueProvenance::EntryWitness { field_path, .. } = &mut node.provenance else { panic!("selector root") };
                *field_path = "input_type.unauthenticated_tag".into();
                node.id = canonical_hash("cellscript-value-provenance-node-v1", &node.provenance).unwrap();
                let replacement = node.id.clone();
                changed.policy_mut().selector_node_id = replacement;
            }
            "unknown" => changed.policy_mut().unknown_selector = "accept".into(),
            "wrapper" => changed.record.typed_semantics.foundation.entry_contract.exact_entry = "action:mint".into(),
            _ => unreachable!(),
        }
        changed.rebind_policy_identity();
        let error = changed.check().unwrap_err();
        assert_eq!(error.code, CheckerRejectionCode::V2419TypedSemanticsInvalid, "{mutation}: {error}");
    }
}
