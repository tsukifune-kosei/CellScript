use cellscript::{compile, CompileOptions, CompileResult, NEXT_EDITION};
use cellscript_artifact_checker::{
    canonical_bytes, canonical_hash, check_bundle, check_bundle_values, parse_elf, CheckerBudgets, CheckerRejectionCode, EdgeKind,
    SourceArtifactMap, TypedSemanticConstant, TypedSemanticOperation, TypedSemanticOperationDetail, VerifiedLoweringRecord,
    LOWERING_RECORD_SCHEMA, SOURCE_MAP_SCHEMA,
};
use serde_json::Value;

const FIXTURE_SOURCE: &str = r#"
module artifact_checker_fixture

fn increment(value: u64) -> u64 {
    return value + 1
}

action main(value: u64) -> u64 {
    verification
        return increment(value)
}
"#;

const RUNTIME_PROVENANCE_SOURCE: &str = r#"
module artifact_checker_runtime_provenance

resource Token has store { amount: u64 }

action inspect(witness source_index: u64, witness expected_data_hash: Hash) -> u64 {
    let input = ckb::input<Token>(source_index)
    let dep = ckb::cell_dep(source_index)
    let transaction_hash = ckb::transaction_hash()
    require input.capacity > 0
    require dep.data_hash == expected_data_hash
    require transaction_hash != Hash::zero()
    return 0
}
"#;

const BOUNDED_WITNESS_SOURCE: &str = r#"
module artifact_checker_bounded_witness

action inspect() -> u64 {
    verification
        let witness_args = witness::args(0)
        let bytes = witness::bounded_lock(witness_args, 64)
        require bytes.size <= 64
        require witness::byte(bytes, 0) >= 0
        require witness::blake2b(bytes) != Hash::zero()
        return 0
}
"#;

const SIGHASH_ZERO_LOCK_SOURCE: &str = r#"
module artifact_checker_sighash_zero_lock

action inspect() -> u64 {
    verification
        let digest = env::sighash_all_zero_lock(4, 8, 4, 4096)
        return 0
}
"#;

const EXACT_HANDLE_SOURCE: &str = r#"
module artifact_checker_exact_handle

resource Token has store { amount: u64 }

action inspect(witness handle: ExactScriptHandle) -> u64 {
    let dep = ckb::cell_dep(0)
    ckb::require_cell_dep_exact_verifier_handle(
        dep,
        handle,
        Hash::from_bytes(b"0123456789abcdef0123456789abcdef")
    )
    return 0
}
"#;

#[derive(Clone)]
struct Fixture {
    artifact: Vec<u8>,
    metadata: Value,
    record: VerifiedLoweringRecord,
    source_map: SourceArtifactMap,
}

impl Fixture {
    fn new() -> Self {
        let result =
            compile(FIXTURE_SOURCE, CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() }).unwrap();
        Self::from_result(result)
    }

    fn from_result(result: CompileResult) -> Self {
        let fixture = Self {
            artifact: result.artifact_bytes,
            metadata: serde_json::to_value(result.metadata).unwrap(),
            record: result.verified_lowering_record.unwrap(),
            source_map: result.source_artifact_map.unwrap(),
        };
        fixture.check().unwrap();
        fixture
    }

    fn from_source(source: &str) -> Self {
        let result = compile(source, CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() }).unwrap();
        Self::from_result(result)
    }

    fn check(&self) -> Result<(), CheckerRejectionCode> {
        check_bundle_values(&self.artifact, &self.metadata, &self.record, &self.source_map, &CheckerBudgets::default())
            .map(|_| ())
            .map_err(|error| error.code)
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
        self.metadata["verified_artifact"]["lowering_record_hash"] = Value::String(record_hash);
        self.metadata["verified_artifact"]["source_map_hash"] = Value::String(source_map_hash);
        self.metadata["verified_artifact"]["verified_bundle_id"] = Value::String(verified_bundle_id);
    }

    fn rebind_typed_semantics(&mut self) {
        self.record.typed_semantics_hash =
            canonical_hash(cellscript_artifact_checker::TYPED_SEMANTICS_SCHEMA, &self.record.typed_semantics).unwrap();
        self.metadata["typed_semantics"] = serde_json::to_value(&self.record.typed_semantics).unwrap();
        self.metadata["typed_semantics_hash"] = Value::String(self.record.typed_semantics_hash.clone());
        self.rebind_sidecars();
    }

    fn bind_artifact_identity(&mut self) {
        let artifact_hash = cellscript_artifact_checker::hex_encode(&cellscript_artifact_checker::ckb_blake2b256(&self.artifact));
        self.record.artifact_hash.clone_from(&artifact_hash);
        self.record.artifact_size_bytes = self.artifact.len() as u64;
        self.source_map.artifact_hash.clone_from(&artifact_hash);
        self.metadata["artifact_hash"] = Value::String(artifact_hash);
        self.metadata["artifact_size_bytes"] = Value::from(self.artifact.len() as u64);
        self.metadata["verified_artifact"]["deployable_artifact_id"] = Value::String(self.record.artifact_hash.clone());
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
}

fn bounded_lock_handle(metadata: &mut Value) -> &mut Value {
    metadata["runtime"]["transaction_view_handles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|handle| handle["handle_type"] == "WitnessBytesView<lock,64>")
        .expect("bounded lock witness handle")
}

fn exact_handle_operation(fixture: &mut Fixture) -> &mut TypedSemanticOperation {
    fixture
        .record
        .typed_semantics
        .entries
        .iter_mut()
        .flat_map(|entry| &mut entry.blocks)
        .flat_map(|block| &mut block.operations)
        .find(|operation| operation.call.as_ref().is_some_and(|call| call.target == "__ckb_require_cell_dep_exact_verifier_handle"))
        .expect("exact verifier handle operation")
}

#[test]
fn checker_rejects_vm2_isa_or_data2_contract_tampering() {
    let valid = Fixture::new();
    for pointer in ["/target_profile/minimum_vm_version", "/constraints/ckb/profile_abi_contract/minimum_vm_version"] {
        let mut changed = valid.clone();
        *changed.metadata.pointer_mut(pointer).unwrap() = Value::from(1);
        assert_code(&changed, CheckerRejectionCode::V2410MetadataBindingMismatch);
    }

    let mut changed = valid.clone();
    changed.metadata["target_profile"]["riscv_isa"] = Value::String("rv64imac".to_string());
    assert_code(&changed, CheckerRejectionCode::V2410MetadataBindingMismatch);

    let mut changed = valid.clone();
    changed.metadata["target_profile"]["deployment_hash_types"] = serde_json::json!(["data1"]);
    assert_code(&changed, CheckerRejectionCode::V2410MetadataBindingMismatch);
}

#[test]
fn checker_rejects_runtime_access_provenance_tampering_after_hash_rebinding() {
    let valid = Fixture::from_result(
        compile(
            RUNTIME_PROVENANCE_SOURCE,
            CompileOptions {
                edition: NEXT_EDITION,
                target: Some("riscv64-elf".to_string()),
                target_profile: Some("ckb".to_string()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    assert_eq!(valid.metadata["metadata_schema_version"], Value::from(71));
    assert_eq!(
        valid.metadata["runtime"]["ckb_runtime_access_provenance_contract"],
        Value::String("cellscript-ckb-runtime-access-provenance-v1".to_string())
    );

    let mut changed = valid.clone();
    changed.metadata["runtime"]["ckb_runtime_access_provenance_contract"] = Value::String("tampered".to_string());
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2410MetadataBindingMismatch);

    let mutate_matching_accesses = |metadata: &mut Value, mutation: fn(&mut Value)| {
        for pointer in ["/runtime/ckb_runtime_accesses", "/actions/0/ckb_runtime_accesses"] {
            let accesses = metadata.pointer_mut(pointer).and_then(Value::as_array_mut).unwrap();
            let access = accesses
                .iter_mut()
                .find(|access| access["operation"] == "cell-data-hash-field")
                .expect("dynamic CellDep data-hash access");
            mutation(access);
        }
    };

    let mut changed = valid.clone();
    mutate_matching_accesses(&mut changed.metadata, |access| {
        access["provenance"]["index"]["max_inclusive"] = Value::from(u64::from(u32::MAX) - 1);
    });
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2410MetadataBindingMismatch);

    let mut changed = valid.clone();
    mutate_matching_accesses(&mut changed.metadata, |access| {
        access["provenance"]["source"]["resolved_source"] = Value::String("HeaderDep".to_string());
    });
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2410MetadataBindingMismatch);

    let mut changed = valid.clone();
    mutate_matching_accesses(&mut changed.metadata, |access| {
        access["provenance"]["range"]["length"]["value"] = Value::from(0);
    });
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2410MetadataBindingMismatch);

    let mut changed = valid.clone();
    changed.metadata["actions"][0]["ckb_runtime_accesses"][0]["binding"] = Value::String("tampered".to_string());
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2410MetadataBindingMismatch);

    let set_transaction_hash_access_field = |metadata: &mut Value, field: &str, value: &Value| {
        for pointer in ["/runtime/ckb_runtime_accesses", "/actions/0/ckb_runtime_accesses"] {
            let accesses = metadata.pointer_mut(pointer).and_then(Value::as_array_mut).unwrap();
            let access = accesses
                .iter_mut()
                .find(|access| access["operation"] == "transaction-hash")
                .expect("canonical transaction-hash access");
            access[field] = value.clone();
        }
    };

    for mutation in [
        ("operation", Value::String("transaction-hash-unbound".to_string())),
        ("syscall", Value::String("LOAD_TRANSACTION".to_string())),
        ("binding", Value::String("ckb::transaction_bytes".to_string())),
    ] {
        let mut changed = valid.clone();
        set_transaction_hash_access_field(&mut changed.metadata, mutation.0, &mutation.1);
        changed.rebind_sidecars();
        assert_code(&changed, CheckerRejectionCode::V2410MetadataBindingMismatch);
    }

    let mut changed = valid.clone();
    for pointer in ["/runtime/ckb_runtime_accesses", "/actions/0/ckb_runtime_accesses"] {
        let access = changed
            .metadata
            .pointer_mut(pointer)
            .and_then(Value::as_array_mut)
            .unwrap()
            .iter_mut()
            .find(|access| access["operation"] == "transaction-hash")
            .expect("canonical transaction-hash access");
        access["provenance"]["range"]["length"]["value"] = Value::from(31);
        access["provenance"]["range"]["length"]["max_inclusive"] = Value::from(31);
    }
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2410MetadataBindingMismatch);

    let mut changed = valid;
    let handle = changed.metadata["runtime"]["transaction_view_handles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|handle| handle["handle_type"] == "InputView<Token>")
        .expect("typed Input view handle");
    handle["provenance"]["index"]["binding"] = Value::String(String::new());
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2410MetadataBindingMismatch);
}

#[test]
fn checker_binds_bounded_witness_owner_limit_range_and_typed_retyping() {
    let valid = Fixture::from_result(
        compile(
            BOUNDED_WITNESS_SOURCE,
            CompileOptions {
                edition: NEXT_EDITION,
                target: Some("riscv64-elf".to_string()),
                target_profile: Some("ckb".to_string()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    assert_eq!(valid.metadata["metadata_schema_version"], Value::from(71));

    let mutate_bounded_accesses = |metadata: &mut Value, mutation: fn(&mut Value)| {
        for pointer in ["/runtime/ckb_runtime_accesses", "/actions/0/ckb_runtime_accesses"] {
            let accesses = metadata.pointer_mut(pointer).and_then(Value::as_array_mut).unwrap();
            for access in accesses
                .iter_mut()
                .filter(|access| access["operation"].as_str().is_some_and(|operation| operation.starts_with("witness-bounded-lock-")))
            {
                mutation(access);
            }
        }
    };

    let mut changed = valid.clone();
    bounded_lock_handle(&mut changed.metadata)["witness_owner"] = Value::String("entry".to_string());
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2410MetadataBindingMismatch);

    let mut changed = valid.clone();
    bounded_lock_handle(&mut changed.metadata)["max_bytes"] = Value::from(63);
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2410MetadataBindingMismatch);

    let mut changed = valid.clone();
    bounded_lock_handle(&mut changed.metadata)["provenance"]["range"]["length"]["max_inclusive"] = Value::from(63);
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2410MetadataBindingMismatch);

    let mut changed = valid.clone();
    mutate_bounded_accesses(&mut changed.metadata, |access| {
        access["provenance"]["range"]["offset"]["max_inclusive"] = Value::from(63);
    });
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2410MetadataBindingMismatch);

    let mut changed = valid;
    let local = changed
        .record
        .typed_semantics
        .entries
        .iter_mut()
        .flat_map(|entry| &mut entry.locals)
        .find(|local| local.ty == "WitnessBytesView<lock,64>")
        .expect("typed bounded witness local");
    local.ty = "WitnessBytesView<signer,64>".to_string();
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);
}

#[test]
fn checker_binds_zero_lock_signing_domain_to_runtime_access_and_typed_call() {
    let valid = Fixture::from_result(
        compile(
            SIGHASH_ZERO_LOCK_SOURCE,
            CompileOptions {
                edition: NEXT_EDITION,
                target: Some("riscv64-elf".to_string()),
                target_profile: Some("ckb".to_string()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    assert_eq!(valid.metadata["metadata_schema_version"], Value::from(71));
    assert_eq!(valid.metadata["runtime"]["signing_message_domains"].as_array().unwrap().len(), 1);

    for (field, tampered) in [
        ("contract", "tampered-signing-domain"),
        ("digest_type", "Hash"),
        ("first_witness_lock_transform", "preserve-prefix-and-zero-signatures"),
        ("runtime_helper", "__tampered_sighash"),
    ] {
        let mut changed = valid.clone();
        changed.metadata["runtime"]["signing_message_domains"][0][field] = Value::String(tampered.to_string());
        changed.rebind_sidecars();
        assert_code(&changed, CheckerRejectionCode::V2410MetadataBindingMismatch);
    }

    let mut changed = valid.clone();
    changed.metadata["runtime"]["signing_message_domains"] = serde_json::json!([]);
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2410MetadataBindingMismatch);

    let mut changed = valid;
    changed.metadata["runtime"]["signing_message_domains"][0]["max_group_inputs"] = Value::from(5);
    for pointer in ["/runtime/ckb_runtime_accesses", "/actions/0/ckb_runtime_accesses"] {
        let access = changed
            .metadata
            .pointer_mut(pointer)
            .and_then(Value::as_array_mut)
            .unwrap()
            .iter_mut()
            .find(|access| access["operation"] == "sighash-all-zero-lock-v1")
            .expect("bounded sighash runtime access");
        access["provenance"]["index"]["max_inclusive"] = Value::from(4);
    }
    changed.rebind_sidecars();
    let error =
        check_bundle_values(&changed.artifact, &changed.metadata, &changed.record, &changed.source_map, &CheckerBudgets::default())
            .expect_err("metadata and access bounds cannot diverge from the typed call");
    assert_eq!(error.code, CheckerRejectionCode::V2410MetadataBindingMismatch);
    assert!(error.message.contains("typed bounded sighash call"), "{error}");
}

#[test]
fn terminal_verifier_failures_reject_hash_rebound_machine_and_record_mutations() {
    let source = "module fatal_checker\naction main(value: u64) { verification require value > 0 }";
    for edition in [cellscript::CellScriptEdition::Edition2026, NEXT_EDITION] {
        let valid = Fixture::from_result(
            compile(source, CompileOptions { edition, target: Some("riscv64-elf".into()), opt_level: 0, ..Default::default() })
                .unwrap(),
        );
        let failure = valid.record.verifier_failure_exits.iter().find(|exit| exit.code == 5).unwrap().clone();
        let elf = parse_elf(&valid.artifact, CheckerBudgets::default().instructions).unwrap();
        // Small failure codes now materialize with a single ADDI, so the
        // recorded failure address points directly at the constant.
        let constant_last = elf.instructions.iter().find(|instruction| instruction.address == failure.address).unwrap();
        assert_eq!(constant_last.word >> 20, 5, "fixture uses the assembler's single-ADDI materialization");
        let sink = valid.record.entries.iter().find(|entry| entry.name == "__cellscript_abort").unwrap();
        let sink_block = valid.record.blocks.iter().find(|block| block.id == sink.entry_block).unwrap();
        let sink_start = sink_block.range.start;

        let mut changed = valid.clone();
        changed.replace_machine_word(failure.address, constant_last.word & 0x000f_ffff);
        assert_code(&changed, CheckerRejectionCode::V2414ControlFlowInvalid);

        let mut changed = valid.clone();
        // The sink's exit-code constant is a single ADDI now, so the ECALL
        // sits directly at sink_start + 4: corrupting it trips the
        // instruction allowlist (V2413) instead of the constant check.
        let syscall_word = elf.instructions.iter().find(|instruction| instruction.address == sink_start + 4).unwrap().word;
        changed.replace_machine_word(sink_start + 4, syscall_word ^ (1 << 20));
        assert_code(&changed, CheckerRejectionCode::V2413InstructionInvalid);

        let mut changed = valid.clone();
        changed.replace_machine_word(sink_start + 8, 0x0000_8067); // ret instead of EXIT
        assert_code(&changed, CheckerRejectionCode::V2414ControlFlowInvalid);

        let mut changed = valid.clone();
        changed.record.verifier_failure_exits.retain(|exit| exit.address != failure.address);
        changed.rebind_sidecars();
        assert_code(&changed, CheckerRejectionCode::V2414ControlFlowInvalid);

        let mut changed = valid.clone();
        changed.record.verifier_failure_exits.iter_mut().find(|exit| exit.address == failure.address).unwrap().address += 4;
        changed.rebind_sidecars();
        assert_code(&changed, CheckerRejectionCode::V2414ControlFlowInvalid);

        let mut changed = valid.clone();
        let success = changed
            .record
            .blocks
            .iter()
            .find(|block| {
                block.owner_entry == "action:main" && block.terminator == cellscript_artifact_checker::MachineTerminator::Return
            })
            .unwrap();
        let success_id = success.id.clone();
        let target = success.range.start;
        let jump_address = failure.address + 8;
        for edge in &mut changed.record.edges {
            if edge.from == failure.block_id && edge.kind == EdgeKind::Jump {
                edge.to = success_id.clone();
            }
        }
        changed.record.canonicalize();
        changed.replace_machine_word(jump_address, encode_jal((target as i64 - jump_address as i64) as i32));
        assert_code(&changed, CheckerRejectionCode::V2414ControlFlowInvalid);

        // Keep the claimed CFG edge intact: its target block still contains the
        // forged address. The checker must reject entering after the error load.
        let incoming = elf.control_flow.iter().find(|edge| edge.target == failure.address).unwrap();
        let word = elf.instructions.iter().find(|instruction| instruction.address == incoming.address).unwrap().word;
        assert_eq!(word & 0x7f, 0x63, "require fixture branches to failure");
        let offset = (failure.address + 8) as i64 - incoming.address as i64;
        assert!((-4096..4096).contains(&offset));
        let immediate = offset as u32;
        let branch = (word & 0x01ff_f07f)
            | (((immediate >> 12) & 1) << 31)
            | (((immediate >> 5) & 0x3f) << 25)
            | (((immediate >> 1) & 0xf) << 8)
            | (((immediate >> 11) & 1) << 7);
        let mut changed = valid.clone();
        changed.replace_machine_word(incoming.address, branch);
        assert_code(&changed, CheckerRejectionCode::V2414ControlFlowInvalid);

        let mut changed = valid.clone();
        let block = changed
            .record
            .typed_semantics
            .entries
            .iter_mut()
            .flat_map(|entry| &mut entry.blocks)
            .find(|block| block.runtime_error.is_some())
            .unwrap();
        block.runtime_error = None;
        changed.rebind_typed_semantics();
        assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

        assert_eq!(valid.metadata["typed_semantics"]["failure_semantics"], "current-vm-process-exit-v1");
        let mut malformed = valid.metadata["typed_semantics"].clone();
        malformed.as_object_mut().unwrap().remove("failure_semantics");
        assert!(serde_json::from_value::<cellscript_artifact_checker::TypedSemanticRecord>(malformed).is_err());
    }
}

#[test]
fn terminal_verifier_operations_cannot_be_inserted_before_continuation_after_rebinding() {
    let source = "module fatal_operation_checker\naction main(value: u64) { verification require value > 0 }";
    for edition in [cellscript::CellScriptEdition::Edition2026, NEXT_EDITION] {
        let valid = Fixture::from_result(
            compile(source, CompileOptions { edition, target: Some("riscv64-elf".into()), opt_level: 0, ..Default::default() })
                .unwrap(),
        );
        let failure = valid
            .record
            .typed_semantics
            .entries
            .iter()
            .flat_map(|entry| &entry.blocks)
            .find(|block| block.runtime_error.is_some())
            .unwrap()
            .operations
            .last()
            .unwrap()
            .clone();
        for (terminator, code) in [("return", 0), ("return", 20), ("verifier-failure", 5)] {
            let mut changed = valid.clone();
            let entry = changed.record.typed_semantics.entries.iter_mut().find(|entry| entry.name == "main").unwrap();
            let entry_id = entry.id.clone();
            let block = entry.blocks.iter_mut().find(|block| block.terminator == terminator).unwrap();
            let mut inserted = failure.clone();
            inserted.operands[0].constant = Some(TypedSemanticConstant::U64(code.to_string()));
            block.operations.insert(block.operations.len() - 1, inserted);
            for (index, operation) in block.operations.iter_mut().enumerate() {
                operation.index = u32::try_from(index).unwrap();
            }
            let block_id = block.id;
            let block_hash = canonical_hash("cellscript-typed-block-v1", block).unwrap();
            // Rebind even the per-block typed/machine hashes: rejection must
            // come from terminal semantics, not a stale sidecar digest.
            changed
                .record
                .entries
                .iter_mut()
                .find(|entry| entry.id == entry_id)
                .unwrap()
                .typed_blocks
                .iter_mut()
                .find(|binding| binding.id == block_id)
                .unwrap()
                .hash
                .clone_from(&block_hash);
            for machine_block in &mut changed.record.blocks {
                if machine_block.owner_entry == entry_id && machine_block.lowering_block_id == Some(block_id) {
                    machine_block.typed_block_hash = Some(block_hash.clone());
                }
            }
            changed.rebind_typed_semantics();
            assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);
        }
    }
}

#[test]
fn implicit_verifier_exit_inventory_cannot_be_hidden_by_renaming_the_sink() {
    let valid = Fixture::from_source("module implicit_failure\nfn divide(value: u64) -> u64 { return 7 / value }\naction main(value: u64) -> u64 { verification return divide(value) }");
    assert!(valid.record.typed_semantics.entries.iter().flat_map(|entry| &entry.blocks).all(|block| block.runtime_error.is_none()));
    let mut changed = valid.clone();
    changed.record.entries.iter_mut().find(|entry| entry.name == "__cellscript_abort").unwrap().name = "renamed_abort".into();
    changed.record.verifier_failure_exits.clear();
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2414ControlFlowInvalid);
}

#[test]
fn common_policy_calls_keep_a_bounded_retained_body_contract_after_rebinding() {
    use cellscript::artifact::{compile_artifact, ArtifactAction, ArtifactContext, ArtifactDeclaration, ArtifactDispatch};
    let source = r#"
module common_calls
resource Token has consume { amount: u64 }
fn checked(value: u64) -> u64 { return 7 / value }
action common() { verification require checked(7) == 1 }
action burn(input token: Token) { verification consume token }
"#;
    for edition in [cellscript::CURRENT_EDITION, NEXT_EDITION] {
        let valid = Fixture::from_result(
            compile_artifact(
                source,
                CompileOptions { edition, target: Some("riscv64-elf".into()), opt_level: 0, ..Default::default() },
                ArtifactDeclaration {
                    name: "TokenPolicy".into(),
                    context: ArtifactContext::TypeGroup { resource: "Token".into() },
                    dispatch: ArtifactDispatch::PolicyWitnessV1,
                    actions: vec![ArtifactAction { tag: 7, action: "burn".into() }],
                    common_checks: vec!["common".into()],
                },
                cellscript::ExecutableSurfacePolicy::DenyFailClosed,
            )
            .unwrap(),
        );
        for mutation in
            ["unknown", "foreign-contract", "field", "wide", "reference-return", "physical-cell", "loop", "unsupported-error"]
        {
            let mut changed = valid.clone();
            let typed = &mut changed.record.typed_semantics;
            let binding = typed.entries.iter().find(|entry| entry.name == "burn").unwrap().cell_bindings[0].clone();
            if matches!(mutation, "unknown" | "foreign-contract") {
                let call = typed
                    .entries
                    .iter_mut()
                    .find(|entry| entry.name == "common")
                    .unwrap()
                    .blocks
                    .iter_mut()
                    .flat_map(|block| &mut block.operations)
                    .find_map(|operation| operation.call.as_mut())
                    .unwrap();
                if mutation == "unknown" {
                    call.target = "absent".into();
                } else {
                    call.contract = "raw-status".into();
                }
            } else {
                let callee = typed.entries.iter_mut().find(|entry| entry.name == "checked").unwrap();
                match mutation {
                    "field" => callee.blocks[0].operations[0].opcode = "field-access".into(),
                    "wide" => callee.params[0].ty = "u128".into(),
                    "reference-return" => callee.return_type = "&Token".into(),
                    "physical-cell" => callee.cell_bindings.push(binding),
                    "loop" => {
                        let id = callee.blocks[0].id;
                        callee.blocks[0].successors = vec![id];
                        callee.blocks[0].terminator = "jump".into();
                    }
                    "unsupported-error" => {
                        callee.blocks[0].runtime_error =
                            Some(cellscript_artifact_checker::TypedSemanticRuntimeError { code: 1, name: "syscall-failed".into() });
                        callee.blocks[0].terminator = "verifier-failure".into();
                    }
                    _ => unreachable!(),
                }
            }
            if mutation == "reference-return" {
                let call = typed
                    .entries
                    .iter_mut()
                    .find(|entry| entry.name == "common")
                    .unwrap()
                    .blocks
                    .iter_mut()
                    .flat_map(|block| &mut block.operations)
                    .find_map(|operation| operation.call.as_mut())
                    .unwrap();
                call.return_type = "&Token".into();
            }
            changed.rebind_typed_semantics();
            let error =
                cellscript_artifact_checker::validate_policy_metadata(&changed.metadata, &changed.record.typed_semantics).unwrap_err();
            assert_eq!(error.code, CheckerRejectionCode::V2419TypedSemanticsInvalid, "{edition:?}: {mutation}: {error}");
            assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);
        }
    }
}

const REFERENCE_ENTRY_SOURCE: &str = r#"
module artifact_checker_reference_fixture

resource Token has consume {
    amount: u64,
}

fn inspect(token: &Token) -> u64 {
    return token.amount
}

action main() -> u64 {
    verification
        return 0
}
"#;

const NATIVE_EDITION_2027_SOURCE: &str = r#"
module artifact_checker_native_2027

resource Token has store, replace, relock {
    owner: Address,
    amount: u64,
}

type_script TokenTransfer on type_group<Token> {
    entry transfer(
        input token: Token from group_input[0],
        witness recipient: Address from group_witness.input_type,
        output next: Token from group_output[0],
    ) {
        verify {
            enforce token.amount > 0
        }

        effects {
            replace token -> next {
                data {
                    owner = same
                    amount = same
                }
                identity = same
                type_script = same
                lock_script = exact_hash(recipient)
                capacity = same
                cardinality = one_to_one
            }
        }
    }
}
"#;

const NATIVE_FRESH_AUDIT_EDITION_2027_SOURCE: &str = r#"
module artifact_checker_native_fresh_2027
#[type_id("artifact-checker::Token:v1")]
resource Token has store, create, burn identity(ckb_type_id) { amount: u64 }
type_script TokenMint on type_group<Token> {
    entry mint(
        witness amount: u64 from group_witness.input_type,
        witness recipient: Address from group_witness.input_type,
        output next: Token from group_output[0],
    ) {
        verify { enforce amount > 0 }
        audit issuance_policy {
            expected_evidence = external_policy(recipient)
        }
        effects {
            fresh next {
                data { amount = amount }
                identity = ckb_type_id
                type_script = declared
                lock_script = exact_hash(recipient)
                capacity = builder_computed
                cardinality = one
            }
        }
    }
}
"#;

const NATIVE_RETIRE_EDITION_2027_SOURCE: &str = r#"
module artifact_checker_native_retire_2027
resource Note has store, consume, burn identity(field(note_id)) { note_id: u64, amount: u64 }
type_script NoteRetirement on type_group<Note> {
    entry retire_note(input note: Note from group_input[0]) {
        verify { enforce note.amount == 0 }
        effects {
            retire note {
                absence = field(note_id)
                data = discarded
                lock_script = none
                type_script = absent
                capacity = released
                cardinality = one
            }
        }
    }
}
"#;

const NATIVE_POOL_EDITION_2027_SOURCE: &str = r#"
module artifact_checker_native_pool_2027
resource Token has store, create, consume { owner: Address, amount: u64 }
type_script TokenPool on type_group<Token> {
    entry merge(
        input left: Token from group_input[0],
        input right: Token from group_input[1],
        witness recipient: Address from group_witness.input_type,
        output merged: Token from group_output[0],
    ) {
        verify { enforce left.amount > 0 }
        effects {
            pool value_flow {
                inputs { left, right }
                outputs { merged }
                data {
                    owner { merged = recipient }
                    amount = conserve
                }
                identity = pooled
                type_script = same
                lock_script { merged = exact_hash(recipient) }
                capacity = builder_computed
                cardinality = declared
            }
        }
    }
}
"#;

const LEGACY_LOCK_SOURCE: &str = r#"
module artifact_checker_lock_2027
resource Vault has store { owner: Address }
lock unlock(protected vault: Vault, lock_args owner: Address, witness claimed_owner: Address) -> bool {
    verification
        require vault.owner == owner
        require claimed_owner == owner
}
"#;

const NATIVE_LOCK_EDITION_2027_SOURCE: &str = r#"
module artifact_checker_lock_2027
resource Vault has store { owner: Address }
lock_script VaultOwner on lock_group {
    entry unlock(
        protected vault: Vault from group_input[0],
        lock_args owner: Address from current_script.args,
        witness claimed_owner: Address from group_witness.input_type,
    ) {
        verify {
            enforce vault.owner == owner
            enforce claimed_owner == owner
        }
    }
}
"#;

fn assert_code(fixture: &Fixture, expected: CheckerRejectionCode) {
    match fixture.check() {
        Ok(()) => panic!("mutation unexpectedly passed; expected {}", expected.as_str()),
        Err(actual) => assert_eq!(actual, expected),
    }
}

#[test]
fn verified_artifact_sidecars_are_deterministic_and_canonical() {
    let first = Fixture::new();
    let second = Fixture::new();
    assert_eq!(first.artifact, second.artifact);
    assert_eq!(canonical_bytes(&first.record).unwrap(), canonical_bytes(&second.record).unwrap());
    assert_eq!(canonical_bytes(&first.source_map).unwrap(), canonical_bytes(&second.source_map).unwrap());
    assert!(first.source_map.intervals.iter().all(|interval| interval.source_path == "<memory>"));
    let foundation = &first.record.typed_semantics.foundation;
    assert_eq!(foundation.schema, cellscript_artifact_checker::SEMANTIC_FOUNDATION_SCHEMA);
    assert!(!foundation.identities.core_semantic_id.is_empty());
    assert!(!foundation.identities.entry_contract_id.is_empty());
    assert!(!foundation.identities.artifact_contract_id.is_empty());
    assert_eq!(first.metadata["verified_artifact"]["deployable_artifact_id"], Value::String(first.record.artifact_hash.clone()));
    assert_eq!(
        first.metadata["verified_artifact"]["boundary_schema"],
        Value::String(cellscript_artifact_checker::VERIFIED_ARTIFACT_BOUNDARY_SCHEMA.to_string())
    );
    let mapped = first
        .source_map
        .semantic_mappings
        .iter()
        .map(|mapping| mapping.semantic_node_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(foundation.provenance.nodes.iter().all(|node| mapped.contains(node.id.as_str())));
}

#[test]
fn checker_accepts_native_edition_2027_type_script_trigger_and_disposition() {
    let result = compile(
        NATIVE_EDITION_2027_SOURCE,
        CompileOptions { edition: NEXT_EDITION, target: Some("riscv64-elf".to_string()), ..CompileOptions::default() },
    )
    .unwrap();
    let fixture = Fixture::from_result(result);
    let foundation = &fixture.record.typed_semantics.foundation;
    assert_eq!(foundation.entry_contract.trigger, "type-group<Token>");
    assert_eq!(foundation.entry_contract.exact_entry, "action:transfer");
    assert!(foundation.dispositions.iter().any(|disposition| {
        matches!(
            &disposition.input,
            Some(cellscript_artifact_checker::InputDisposition::Successor { output_role })
                if output_role.ends_with(":next:output[0]")
        ) && disposition.envelope.completeness == "exhaustive"
    }));
    let enforced = foundation.claims.iter().find(|claim| claim.execution.is_some()).expect("native enforce claim");
    assert_eq!(enforced.statement, "require token.amount > 0");
    assert_eq!(enforced.enforcement, "checked-runtime");
    assert!(enforced.on_chain_checked);
    let mapping = fixture
        .source_map
        .semantic_mappings
        .iter()
        .find(|mapping| mapping.semantic_node_id == enforced.semantic_node_id)
        .expect("native enforce claim must have a source mapping");
    let mapped_source = &NATIVE_EDITION_2027_SOURCE[mapping.source_start as usize..mapping.source_end as usize];
    assert_eq!(mapped_source, "enforce token.amount > 0");

    let mut invalid = fixture.clone();
    invalid
        .record
        .typed_semantics
        .foundation
        .claims
        .iter_mut()
        .find_map(|claim| claim.execution.as_mut())
        .expect("native enforce execution binding")
        .condition_node_id = "00".repeat(32);
    invalid.rebind_typed_semantics();
    assert_code(&invalid, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut invalid = fixture.clone();
    let execution = invalid
        .record
        .typed_semantics
        .foundation
        .claims
        .iter_mut()
        .find_map(|claim| claim.execution.as_mut())
        .expect("native enforce execution binding");
    std::mem::swap(&mut execution.success_block, &mut execution.failure_block);
    invalid.rebind_typed_semantics();
    assert_code(&invalid, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut invalid = fixture;
    invalid
        .record
        .typed_semantics
        .foundation
        .claims
        .iter_mut()
        .find_map(|claim| claim.execution.as_mut())
        .expect("native enforce execution binding")
        .failure_error_code = 1;
    invalid.rebind_typed_semantics();
    assert_code(&invalid, CheckerRejectionCode::V2419TypedSemanticsInvalid);
}

#[test]
fn checker_accepts_fresh_retire_and_audit_but_rejects_reclassified_evidence() {
    let fresh = compile(
        NATIVE_FRESH_AUDIT_EDITION_2027_SOURCE,
        CompileOptions { edition: NEXT_EDITION, target: Some("riscv64-elf".to_string()), ..CompileOptions::default() },
    )
    .unwrap();
    let fixture = Fixture::from_result(fresh);
    let foundation = &fixture.record.typed_semantics.foundation;
    assert!(matches!(
        foundation.dispositions[0].output,
        Some(cellscript_artifact_checker::OutputOrigin::Fresh { ref identity_policy }) if identity_policy == "ckb-type-id"
    ));
    let fresh_mapping = fixture
        .source_map
        .semantic_mappings
        .iter()
        .find(|mapping| mapping.semantic_node_id == foundation.dispositions[0].semantic_node_id)
        .expect("fresh disposition source mapping");
    assert!(NATIVE_FRESH_AUDIT_EDITION_2027_SOURCE[fresh_mapping.source_start as usize..fresh_mapping.source_end as usize]
        .starts_with("fresh next"));
    let audit = foundation.claims.iter().find(|claim| claim.category == "audit").expect("audit claim");
    assert_eq!(audit.enforcement, "metadata-only");
    assert!(!audit.on_chain_checked);
    assert!(audit.execution.is_none());
    let audit_mapping = fixture
        .source_map
        .semantic_mappings
        .iter()
        .find(|mapping| mapping.semantic_node_id == audit.semantic_node_id)
        .expect("audit claim source mapping");
    assert!(NATIVE_FRESH_AUDIT_EDITION_2027_SOURCE[audit_mapping.source_start as usize..audit_mapping.source_end as usize]
        .starts_with("audit issuance_policy"));

    let mut invalid = fixture.clone();
    invalid.record.typed_semantics.foundation.claims.iter_mut().find(|claim| claim.category == "audit").unwrap().evidence_reference =
        "proof-plan:pretend-on-chain".to_string();
    invalid.rebind_typed_semantics();
    assert_code(&invalid, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut invalid = fixture;
    invalid.record.typed_semantics.foundation.claims.iter_mut().find(|claim| claim.category == "audit").unwrap().on_chain_checked =
        true;
    invalid.rebind_typed_semantics();
    assert_code(&invalid, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let retired = compile(
        NATIVE_RETIRE_EDITION_2027_SOURCE,
        CompileOptions { edition: NEXT_EDITION, target: Some("riscv64-elf".to_string()), ..CompileOptions::default() },
    )
    .unwrap();
    let fixture = Fixture::from_result(retired);
    assert!(matches!(
        fixture.record.typed_semantics.foundation.dispositions[0].input,
        Some(cellscript_artifact_checker::InputDisposition::Retired { ref absence_policy })
            if absence_policy == "same-field-identity-output-absent:note_id"
    ));

    let mut invalid = fixture;
    invalid.record.typed_semantics.foundation.dispositions[0].envelope.completeness = "partial".to_string();
    invalid.rebind_typed_semantics();
    assert_code(&invalid, CheckerRejectionCode::V2419TypedSemanticsInvalid);
}

#[test]
fn checker_accepts_checked_pool_and_rejects_divergent_accounting() {
    let result = compile(
        NATIVE_POOL_EDITION_2027_SOURCE,
        CompileOptions { edition: NEXT_EDITION, target: Some("riscv64-elf".to_string()), ..CompileOptions::default() },
    )
    .unwrap();
    let fixture = Fixture::from_result(result);
    let foundation = &fixture.record.typed_semantics.foundation;
    assert_eq!(
        foundation
            .dispositions
            .iter()
            .filter(|disposition| matches!(disposition.input, Some(cellscript_artifact_checker::InputDisposition::Pooled { .. })))
            .count(),
        2
    );
    assert!(foundation.dispositions.iter().any(|disposition| {
        matches!(
            disposition.output,
            Some(cellscript_artifact_checker::OutputOrigin::PoolResult {
                ref accounting_obligation,
                ..
            }) if accounting_obligation == "checked-u128-field-sum-equality:amount"
        )
    }));
    let pool_result = foundation
        .dispositions
        .iter()
        .find(|disposition| matches!(disposition.output, Some(cellscript_artifact_checker::OutputOrigin::PoolResult { .. })))
        .unwrap();
    let pool_mapping = fixture
        .source_map
        .semantic_mappings
        .iter()
        .find(|mapping| mapping.semantic_node_id == pool_result.semantic_node_id)
        .expect("pool disposition source mapping");
    assert!(NATIVE_POOL_EDITION_2027_SOURCE[pool_mapping.source_start as usize..pool_mapping.source_end as usize]
        .starts_with("pool value_flow"));
    assert!(foundation.claims.iter().any(|claim| {
        claim.statement == "require left.amount as u128 + right.amount as u128 == merged.amount as u128"
            && claim.on_chain_checked
            && claim.execution.is_some()
    }));

    let mut invalid = fixture.clone();
    let Some(cellscript_artifact_checker::OutputOrigin::PoolResult { accounting_obligation, .. }) =
        invalid.record.typed_semantics.foundation.dispositions.iter_mut().find_map(|disposition| disposition.output.as_mut())
    else {
        panic!("pool result disposition");
    };
    *accounting_obligation = "checked-u128-field-sum-equality:forged".to_string();
    invalid.rebind_typed_semantics();
    assert_code(&invalid, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut invalid = fixture;
    for disposition in &mut invalid.record.typed_semantics.foundation.dispositions {
        if let Some(cellscript_artifact_checker::InputDisposition::Pooled { accounting_obligation, .. }) = &mut disposition.input {
            accounting_obligation.clear();
        }
        if let Some(cellscript_artifact_checker::OutputOrigin::PoolResult { accounting_obligation, .. }) = &mut disposition.output {
            accounting_obligation.clear();
        }
    }
    invalid.rebind_typed_semantics();
    assert_code(&invalid, CheckerRejectionCode::V2419TypedSemanticsInvalid);
}

#[test]
fn checker_accepts_native_lock_script_with_byte_identical_legacy_lowering() {
    let legacy =
        compile(LEGACY_LOCK_SOURCE, CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() }).unwrap();
    let native = compile(
        NATIVE_LOCK_EDITION_2027_SOURCE,
        CompileOptions { edition: NEXT_EDITION, target: Some("riscv64-elf".to_string()), ..CompileOptions::default() },
    )
    .unwrap();
    assert_eq!(legacy.artifact_bytes, native.artifact_bytes);
    assert_eq!(legacy.metadata.typed_semantics.foundation.identities, native.metadata.typed_semantics.foundation.identities);
    let legacy_claim = legacy
        .metadata
        .typed_semantics
        .foundation
        .claims
        .iter()
        .find(|claim| claim.execution.is_some())
        .expect("legacy require claim");
    let legacy_mapping = legacy
        .source_artifact_map
        .as_ref()
        .unwrap()
        .semantic_mappings
        .iter()
        .find(|mapping| mapping.semantic_node_id == legacy_claim.semantic_node_id)
        .expect("legacy require claim must have a source mapping");
    assert_eq!(
        &LEGACY_LOCK_SOURCE[legacy_mapping.source_start as usize..legacy_mapping.source_end as usize],
        "require vault.owner == owner"
    );

    let fixture = Fixture::from_result(native);
    let contract = &fixture.record.typed_semantics.foundation.entry_contract;
    assert_eq!(contract.script_role, "lock");
    assert_eq!(contract.trigger, "lock-group");
    assert_eq!(contract.exact_entry, "lock:unlock");

    let mut invalid = fixture;
    let disposition = invalid.record.typed_semantics.foundation.dispositions.first_mut().expect("lock disposition");
    let Some(cellscript_artifact_checker::InputDisposition::AuthorizationOnly { disposition_owner }) = &mut disposition.input else {
        panic!("native Lock Script must emit AuthorizationOnly");
    };
    disposition_owner.clear();
    invalid.rebind_typed_semantics();
    assert_code(&invalid, CheckerRejectionCode::V2419TypedSemanticsInvalid);
}

#[test]
fn semantic_foundation_and_source_mapping_mutations_are_rejected() {
    let valid = Fixture::new();

    let mut changed = valid.clone();
    changed.record.typed_semantics.foundation.provenance.nodes[0].id = "00".repeat(32);
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = valid.clone();
    changed.record.typed_semantics.foundation.identities.core_semantic_id = "11".repeat(32);
    changed.metadata["verified_artifact"]["core_semantic_id"] = Value::String("11".repeat(32));
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = valid;
    changed.source_map.semantic_mappings[0].semantic_node_id = "22".repeat(32);
    changed.source_map.canonicalize();
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2416SourceMapInvalid);
}

#[test]
fn fixed_cell_binding_mutations_are_rejected_after_outer_hash_rebinding() {
    use cellscript_artifact_checker::{CellBindingMembership, CellBindingSource};
    let valid = Fixture::from_source(
        r#"
module fixed_binding_mutations
resource Token has consume { amount: u64 }
shared Config { value: u64 }
action inspect(input token: Token, read config: Config, witness expected: u64) -> u64 {
    verification
        require token.amount == expected
        require config.value == expected
        consume token
        return 0
}
"#,
    );
    assert_eq!(valid.record.typed_semantics.entries[0].cell_bindings.len(), 2);

    let mut changed = valid.clone();
    changed.record.typed_semantics.entries[0].cell_bindings[0].ordinal += 1;
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = valid.clone();
    let binding = changed.record.typed_semantics.entries[0]
        .cell_bindings
        .iter_mut()
        .find(|binding| binding.source == CellBindingSource::Input)
        .unwrap();
    binding.source = CellBindingSource::GroupInput;
    binding.membership = CellBindingMembership::CurrentTypeGroup;
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = valid.clone();
    let binding = changed.record.typed_semantics.entries[0]
        .cell_bindings
        .iter_mut()
        .find(|binding| binding.source == CellBindingSource::CellDep)
        .unwrap();
    binding.membership = CellBindingMembership::CurrentTypeGroup;
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = valid.clone();
    changed.record.typed_semantics.entries[0].cell_bindings.remove(0);
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = valid.clone();
    let entry = &mut changed.record.typed_semantics.entries[0];
    let removed = entry
        .cell_bindings
        .remove(entry.cell_bindings.iter().position(|binding| binding.source == CellBindingSource::CellDep).unwrap());
    let removed_role = removed.role_id(&entry.id);
    changed.record.typed_semantics.foundation.roles.retain(|role| role.role_id != removed_role);
    changed.rebind_typed_semantics();
    let error =
        check_bundle_values(&changed.artifact, &changed.metadata, &changed.record, &changed.source_map, &CheckerBudgets::default())
            .unwrap_err();
    assert_eq!(error.code, CheckerRejectionCode::V2419TypedSemanticsInvalid);
    assert!(error.message.contains("fixed Cell parameter 'config' has no resolved binding"), "{error:?}");

    let mut changed = valid;
    let duplicate = changed.record.typed_semantics.entries[0].cell_bindings[0].clone();
    changed.record.typed_semantics.entries[0].cell_bindings.insert(0, duplicate);
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);
}

#[test]
fn deferred_sighash_effect_cannot_be_reclassified_after_hash_rebinding() {
    let source = r#"
module deferred_sighash_checker
action main() -> u64 {
    verification
    let digest = env::sighash_all(source::group_input(0))
    return 0
}
"#;
    let fixture = Fixture::from_result(
        compile(source, CompileOptions { opt_level: 0, target: Some("riscv64-elf".to_string()), ..Default::default() }).unwrap(),
    );
    for effect in ["runtime-contract", "deferred-runtime-fail-closed:0:ckb-sighash-all-deferred", "Pure"] {
        let mut changed = fixture.clone();
        let call = changed
            .record
            .typed_semantics
            .entries
            .iter_mut()
            .flat_map(|entry| &mut entry.blocks)
            .flat_map(|block| &mut block.operations)
            .filter_map(|operation| operation.call.as_mut())
            .find(|call| call.target == "__ckb_sighash_all")
            .expect("deferred call is present");
        call.effect = effect.to_string();
        changed.rebind_typed_semantics();
        let error = check_bundle_values(
            &changed.artifact,
            &changed.metadata,
            &changed.record,
            &changed.source_map,
            &CheckerBudgets::default(),
        )
        .expect_err("deferred failure classification cannot be stripped");
        assert_eq!(error.code, CheckerRejectionCode::V2419TypedSemanticsInvalid);
        assert!(error.message.contains("deferred sighash call"), "{error}");
    }
}

#[test]
fn exact_handle_contract_cannot_be_reclassified_after_hash_rebinding() {
    let fixture = Fixture::from_result(
        compile(
            EXACT_HANDLE_SOURCE,
            CompileOptions {
                edition: NEXT_EDITION,
                opt_level: 0,
                target: Some("riscv64-elf".to_string()),
                target_profile: Some("ckb".to_string()),
                ..Default::default()
            },
        )
        .unwrap(),
    );

    let mut changed = fixture.clone();
    exact_handle_operation(&mut changed).call.as_mut().unwrap().target = "__foreign_exact_handle".to_string();
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = fixture.clone();
    exact_handle_operation(&mut changed).call.as_mut().unwrap().effect = "Pure".to_string();
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = fixture.clone();
    let operation = exact_handle_operation(&mut changed);
    operation.operands[2].ty = "address".to_string();
    operation.operands[2].constant = Some(TypedSemanticConstant::Address("00".repeat(32)));
    operation.call.as_mut().unwrap().params[2] = "address".to_string();
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = fixture;
    let operation = exact_handle_operation(&mut changed);
    let Some(TypedSemanticConstant::Hash(hash)) = operation.operands[2].constant.as_mut() else {
        panic!("expected exact-handle hash constant")
    };
    hash.replace_range(0..2, "ff");
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2420TypedMachineBindingInvalid);
}

#[test]
fn checker_accepts_an_explicit_versioned_dispatch_contract() {
    let mut fixture = Fixture::new();
    let foundation = &mut fixture.record.typed_semantics.foundation;
    let selector_node_id = foundation
        .provenance
        .nodes
        .iter()
        .find(|node| !matches!(node.provenance, cellscript_artifact_checker::ValueProvenance::Derived { .. }))
        .expect("fixture must have a provenance root")
        .id
        .clone();
    let exact_entry = foundation.entry_contract.exact_entry.clone();
    let previous_contract_node = foundation.entry_contract.semantic_node_id.clone();
    foundation.entry_contract.dispatch = cellscript_artifact_checker::EntryDispatchContract::ExplicitVersionedDispatch {
        selector_node_id,
        selector_type: "u32-le".to_string(),
        variants: vec![cellscript_artifact_checker::EntryDispatchVariant { tag: "0".to_string(), entry_id: exact_entry.clone() }],
        unknown_selector: "reject".to_string(),
    };
    foundation.entry_contract.semantic_node_id = canonical_hash(
        "cellscript-semantic-node-entry-contract-v1",
        &(
            foundation.entry_contract.script_role.as_str(),
            foundation.entry_contract.trigger.as_str(),
            exact_entry.as_str(),
            "explicit-versioned-dispatch",
            foundation.entry_contract.entry_payload_abi.as_str(),
            foundation.entry_contract.witness_placement_abi.as_str(),
            foundation.entry_contract.witness_placement_field.as_str(),
            foundation.entry_contract.witness_placement_source.as_str(),
        ),
    )
    .unwrap();
    let roots = foundation
        .provenance
        .nodes
        .iter()
        .filter(|node| !matches!(node.provenance, cellscript_artifact_checker::ValueProvenance::Derived { .. }))
        .map(|node| node.id.as_str())
        .collect::<Vec<_>>();
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
    let replacement_contract_node = foundation.entry_contract.semantic_node_id.clone();
    for mapping in &mut fixture.source_map.semantic_mappings {
        if mapping.semantic_node_id == previous_contract_node {
            mapping.semantic_node_id.clone_from(&replacement_contract_node);
        }
    }
    fixture.source_map.canonicalize();
    fixture.metadata["verified_artifact"]["entry_contract_id"] = Value::String(foundation.identities.entry_contract_id.clone());
    fixture.metadata["verified_artifact"]["artifact_contract_id"] = Value::String(foundation.identities.artifact_contract_id.clone());
    fixture.rebind_typed_semantics();

    assert!(fixture.check().is_ok());
}

#[test]
fn stable_rejection_codes_cover_json_budget_graph_abi_proof_and_binding_mutations() {
    let valid = Fixture::new();
    let budgets = CheckerBudgets::default();
    let metadata_bytes = serde_json::to_vec(&valid.metadata).unwrap();
    let record_bytes = canonical_bytes(&valid.record).unwrap();
    let source_map_bytes = canonical_bytes(&valid.source_map).unwrap();

    let mut tiny = budgets.clone();
    tiny.artifact_bytes = 1;
    assert_eq!(
        check_bundle(&valid.artifact, &metadata_bytes, &record_bytes, &source_map_bytes, &tiny).unwrap_err().code,
        CheckerRejectionCode::V2400BudgetExceeded,
    );
    assert_eq!(
        check_bundle(&valid.artifact, &metadata_bytes, b"{", &source_map_bytes, &budgets).unwrap_err().code,
        CheckerRejectionCode::V2401MalformedJson,
    );
    assert_eq!(
        check_bundle(
            &valid.artifact,
            &metadata_bytes,
            &serde_json::to_vec_pretty(&valid.record).unwrap(),
            &source_map_bytes,
            &budgets,
        )
        .unwrap_err()
        .code,
        CheckerRejectionCode::V2402NonCanonicalJson,
    );

    let mut changed = valid.clone();
    changed.record.schema = "future-schema".to_string();
    assert_code(&changed, CheckerRejectionCode::V2403UnsupportedSchema);

    let mut changed = valid.clone();
    changed.record.entries[0].id = "zz-noncanonical".to_string();
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2404CanonicalOrder);

    let mut changed = valid.clone();
    changed.record.entries[0].entry_block = "missing:block".to_string();
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2405ReferentialIntegrity);

    let mut changed = valid.clone();
    let index = changed
        .record
        .blocks
        .iter()
        .position(|block| changed.record.edges.iter().any(|edge| edge.from == block.id && edge.kind != EdgeKind::Call))
        .expect("fixture must contain a non-return CFG edge");
    changed.record.blocks[index].terminator = cellscript_artifact_checker::MachineTerminator::Return;
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2406CfgInvalid);

    let mut changed = valid.clone();
    changed.record.runtime_error_exits.push(cellscript_artifact_checker::RuntimeErrorExit {
        block_id: changed.record.blocks[0].id.clone(),
        address: changed.record.blocks[0].range.end,
        code: 5,
        name: "assertion-failed".to_string(),
    });
    changed.record.canonicalize();
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2406CfgInvalid);

    let mut changed = valid.clone();
    changed.record.blocks[0].reachable = !changed.record.blocks[0].reachable;
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2406CfgInvalid);

    let mut changed = valid.clone();
    let param = changed.record.entries.iter_mut().find_map(|entry| entry.params.first_mut()).unwrap();
    param.alignment_bytes = 3;
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2407AbiOrStackInvalid);

    let mut changed = valid.clone();
    let framed_entry =
        changed.record.entries.iter().position(|entry| entry.frame_size_bytes > 0).expect("fixture must contain a stack-framed entry");
    let owner = changed.record.entries[framed_entry].id.clone();
    changed.record.entries[framed_entry].frame_size_bytes = 0;
    changed.record.entries[framed_entry].outgoing_argument_bytes = 0;
    for block in changed.record.blocks.iter_mut().filter(|block| block.owner_entry == owner) {
        block.frame_size_bytes = 0;
        block.outgoing_argument_bytes = 0;
        block.stack_slots.clear();
    }
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2407AbiOrStackInvalid);

    let mut changed = valid.clone();
    changed.record.entries[0].proof_ids.push("zz-missing-proof".to_string());
    changed.record.entries[0].proof_ids.sort();
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2408ProofCoverageInvalid);

    let mut changed = valid.clone();
    changed.artifact[0] ^= 1;
    assert_code(&changed, CheckerRejectionCode::V2409ArtifactIdentityMismatch);

    let mut changed = valid.clone();
    changed.metadata["module"] = Value::String("tampered".to_string());
    assert_code(&changed, CheckerRejectionCode::V2410MetadataBindingMismatch);

    let mut changed = valid.clone();
    changed.record.typed_semantics.entries[0].effect = "tampered".to_string();
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = valid.clone();
    let typed_param = changed
        .record
        .typed_semantics
        .entries
        .iter_mut()
        .find_map(|entry| entry.params.first_mut())
        .expect("fixture must contain a typed parameter");
    typed_param.ty = "u128".to_string();
    let binding_id = typed_param.binding_id;
    let typed_local = changed
        .record
        .typed_semantics
        .entries
        .iter_mut()
        .flat_map(|entry| entry.locals.iter_mut())
        .find(|local| local.id == binding_id)
        .expect("typed parameter must bind a local");
    typed_local.ty = "u128".to_string();
    changed.record.typed_semantics_hash =
        canonical_hash(cellscript_artifact_checker::TYPED_SEMANTICS_SCHEMA, &changed.record.typed_semantics).unwrap();
    changed.metadata["typed_semantics"] = serde_json::to_value(&changed.record.typed_semantics).unwrap();
    changed.metadata["typed_semantics_hash"] = Value::String(changed.record.typed_semantics_hash.clone());
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2420TypedMachineBindingInvalid);

    let mut changed = valid.clone();
    if let Some(interval) = changed.source_map.intervals.first_mut() {
        interval.source_path = "../escape.cell".to_string();
    } else {
        changed.source_map.schema = "bad-map".to_string();
    }
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2416SourceMapInvalid);

    let mut changed = valid.clone();
    if let Some(site) = changed.record.syscall_sites.first_mut() {
        site.contract.clear();
    } else {
        changed.record.syscall_sites.push(cellscript_artifact_checker::SyscallSite {
            block_id: changed.record.blocks[0].id.clone(),
            address: changed.record.blocks[0].range.start,
            syscall_number: None,
            contract: "declared-but-not-present".to_string(),
            source_domain: "test".to_string(),
            index_domain: "test".to_string(),
            return_code_checked: true,
            buffer_limit_bytes: 1,
        });
    }
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2417SyscallContractInvalid);

    let mut changed = valid.clone();
    let distinct = changed
        .record
        .entries
        .iter()
        .enumerate()
        .find_map(|(left, a)| changed.record.entries.iter().enumerate().find(|(_, b)| b.id != a.id).map(|(right, _)| (left, right)))
        .unwrap();
    let left = changed.record.entries[distinct.0].entry_block.clone();
    let right = changed.record.entries[distinct.1].entry_block.clone();
    changed.record.edges.push(cellscript_artifact_checker::LoweringEdge {
        from: left.clone(),
        to: right.clone(),
        kind: EdgeKind::Call,
    });
    changed.record.edges.push(cellscript_artifact_checker::LoweringEdge { from: right, to: left, kind: EdgeKind::Call });
    changed.record.canonicalize();
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2418RecursionPolicyInvalid);
}

#[test]
fn stable_rejection_codes_cover_elf_sections_instructions_flow_and_digests() {
    let valid = Fixture::new();

    let mut changed = valid.clone();
    changed.artifact[0] = 0;
    changed.bind_artifact_identity();
    assert_code(&changed, CheckerRejectionCode::V2411ElfFormatInvalid);

    let mut changed = valid.clone();
    let section_table = u64::from_le_bytes(changed.artifact[40..48].try_into().unwrap()) as usize;
    let rodata_type = section_table + 2 * 64 + 4;
    changed.artifact[rodata_type..rodata_type + 4].copy_from_slice(&6_u32.to_le_bytes());
    changed.bind_artifact_identity();
    assert_code(&changed, CheckerRejectionCode::V2412ElfSectionInvalid);

    let elf = parse_elf(&valid.artifact, CheckerBudgets::default().instructions).unwrap();
    let text_offset = elf.text.offset as usize;

    let mut changed = valid.clone();
    changed.artifact[text_offset..text_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    changed.bind_artifact_identity();
    assert_code(&changed, CheckerRejectionCode::V2413InstructionInvalid);

    let mut changed = valid.clone();
    changed.artifact[text_offset..text_offset + 4].copy_from_slice(&encode_jal(1_048_574).to_le_bytes());
    changed.bind_artifact_identity();
    assert_code(&changed, CheckerRejectionCode::V2414ControlFlowInvalid);

    let mut changed = valid.clone();
    let candidate = elf
        .instructions
        .windows(2)
        .find(|pair| {
            let word = pair[0].word;
            let rd = (word >> 7) & 0x1f;
            let next = pair[1].word;
            let next_uses_rd_for_sp =
                next & 0x7f == 0x33 && (next >> 7) & 0x1f == 2 && (next >> 15) & 0x1f == 2 && (next >> 20) & 0x1f == rd;
            valid.record.text_range.contains(pair[0].address)
                && word & 0x7f == 0x13
                && rd != 2
                && !next_uses_rd_for_sp
                && valid
                    .record
                    .blocks
                    .iter()
                    .any(|block| block.range.contains(pair[0].address) && pair[0].address + 4 < block.range.end)
        })
        .map(|pair| pair[0])
        .expect("fixture must contain a non-terminating add-immediate instruction");
    let block_offset = elf.text.offset as usize + (candidate.address - elf.text.address) as usize;
    changed.artifact[block_offset..block_offset + 4].copy_from_slice(&(candidate.word ^ (1 << 20)).to_le_bytes());
    changed.bind_artifact_identity();
    assert_code(&changed, CheckerRejectionCode::V2415BlockDigestMismatch);
}

#[test]
fn typed_semantics_rejects_operator_and_constant_mutations_after_rebinding() {
    let valid = Fixture::new();

    let mut changed = valid.clone();
    let binary = changed
        .record
        .typed_semantics
        .entries
        .iter_mut()
        .flat_map(|entry| &mut entry.blocks)
        .flat_map(|block| &mut block.operations)
        .find(|operation| operation.opcode == "binary")
        .expect("fixture must contain a binary operation");
    binary.detail = TypedSemanticOperationDetail::BinaryOperator { operator: "and".to_string() };
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = valid.clone();
    let constant = changed
        .record
        .typed_semantics
        .entries
        .iter_mut()
        .flat_map(|entry| &mut entry.blocks)
        .flat_map(|block| &mut block.operations)
        .flat_map(|operation| &mut operation.operands)
        .find_map(|operand| operand.constant.as_mut())
        .expect("fixture must contain a constant operand");
    *constant = TypedSemanticConstant::U64("01".to_string());
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = valid.clone();
    let constant = changed
        .record
        .typed_semantics
        .entries
        .iter_mut()
        .flat_map(|entry| &mut entry.blocks)
        .flat_map(|block| &mut block.operations)
        .flat_map(|operation| &mut operation.operands)
        .find_map(|operand| match &mut operand.constant {
            Some(TypedSemanticConstant::U64(value)) => Some(value),
            _ => None,
        })
        .expect("fixture must contain a u64 constant operand");
    *constant = "2".to_string();
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2420TypedMachineBindingInvalid);
}

#[test]
fn typed_semantics_rejects_cross_domain_epoch_since_comparison() {
    let valid = Fixture::from_source(
        r#"
module checker::temporal

action main() -> bool {
    verification
        let left = ckb::since_absolute_epoch(42, 3, 10)
        let right = ckb::since_absolute_epoch(43, 0, 10)
        return left < right
}
"#,
    );
    let binary = valid
        .record
        .typed_semantics
        .entries
        .iter()
        .flat_map(|entry| &entry.blocks)
        .flat_map(|block| &block.operations)
        .find(|operation| matches!(&operation.detail, TypedSemanticOperationDetail::BinaryOperator { operator } if operator == "lt"))
        .expect("fixture must contain the temporal comparison");
    assert!(binary.operands.iter().all(|operand| operand.ty == "AbsoluteEpochSince"));

    let mut changed = valid.clone();
    let binary = changed
        .record
        .typed_semantics
        .entries
        .iter_mut()
        .flat_map(|entry| &mut entry.blocks)
        .flat_map(|block| &mut block.operations)
        .find(|operation| matches!(&operation.detail, TypedSemanticOperationDetail::BinaryOperator { operator } if operator == "lt"))
        .expect("fixture must contain the temporal comparison");
    binary.operands[1].ty = "RelativeEpochSince".to_string();
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let valid = Fixture::from_source(
        r#"
module checker::temporal_scalar

action main() -> bool {
    verification
        let left = ckb::since_absolute_block(42)
        let right = ckb::since_absolute_block(43)
        return left < right
}
"#,
    );
    let mut changed = valid.clone();
    let binary = changed
        .record
        .typed_semantics
        .entries
        .iter_mut()
        .flat_map(|entry| &mut entry.blocks)
        .flat_map(|block| &mut block.operations)
        .find(|operation| matches!(&operation.detail, TypedSemanticOperationDetail::BinaryOperator { operator } if operator == "lt"))
        .expect("fixture must contain the temporal comparison");
    assert!(binary.operands.iter().all(|operand| operand.ty == "AbsoluteBlockSince"));
    binary.operands[1].ty = "AbsoluteTimestampSince".to_string();
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let valid = Fixture::from_source(
        r#"
module checker::header_timestamp

action main() -> bool {
    verification
        let header = ckb::header_dep(0)
        return header.timestamp <= header.timestamp
}
"#,
    );
    let mut changed = valid.clone();
    let binary = changed
        .record
        .typed_semantics
        .entries
        .iter_mut()
        .flat_map(|entry| &mut entry.blocks)
        .flat_map(|block| &mut block.operations)
        .find(|operation| matches!(&operation.detail, TypedSemanticOperationDetail::BinaryOperator { operator } if operator == "le"))
        .expect("fixture must contain the timestamp comparison");
    assert!(binary.operands.iter().all(|operand| operand.ty == "TimestampMillis"));
    binary.operands[1].ty = "BlockNumber".to_string();
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);
}

#[test]
fn typed_semantics_accepts_declared_vec_constructors_and_unsigned_widening() {
    let widened = Fixture::from_source(
        r#"
module checker::widening

action multiply(amount: u64, basis_points: u16) -> u64 {
    verification
        return amount * basis_points
}
"#,
    );
    assert!(widened.check().is_ok());

    let empty_array = Fixture::from_source(
        r#"
module checker::empty_array

action empty() -> [u8; 0] {
    verification
        return []
}
"#,
    );
    assert!(empty_array.check().is_ok());

    let script_tuple = Fixture::from_source(
        r#"
module checker::script_tuple

action script_value() -> u64 {
    verification
        let args = script::args_empty()
        let value = script::new(Hash::zero(), 0, args)
        return 0
}
"#,
    );
    assert!(script_tuple.check().is_ok());

    let collection = Fixture::from_source(include_str!("../examples/language/collections/order_book.cell"));
    assert!(collection.check().is_ok());

    let mut changed = collection;
    let declared_type = changed
        .record
        .typed_semantics
        .entries
        .iter_mut()
        .flat_map(|entry| &mut entry.blocks)
        .flat_map(|block| &mut block.operations)
        .find_map(|operation| match &mut operation.detail {
            TypedSemanticOperationDetail::Collection { declared_type } => Some(declared_type),
            _ => None,
        })
        .expect("fixture must contain a collection constructor");
    *declared_type = "Map".to_string();
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);
}

#[test]
fn bounded_cell_runtime_contract_is_bound_to_typed_and_machine_evidence() {
    let valid = Fixture::from_source(
        r#"
module checker::bounded_cells

resource Token has store, consume { amount: u64 }

action verify(input inputs: BoundedCellSet<Token, 2>) -> u64 {
    verification
        consume_each token in inputs {
            require token.amount > 0
        }
        return 0
}
"#,
    );
    assert!(valid.check().is_ok());

    let mut changed = valid.clone();
    let declared_type = changed
        .record
        .typed_semantics
        .entries
        .iter_mut()
        .flat_map(|entry| &mut entry.blocks)
        .flat_map(|block| &mut block.operations)
        .find_map(|operation| match (&*operation.opcode, &mut operation.detail) {
            ("bounded-cell-load", TypedSemanticOperationDetail::Collection { declared_type }) => Some(declared_type),
            _ => None,
        })
        .expect("fixture must contain the bounded Cell load contract");
    *declared_type = "BoundedCellSet<Token, 0>".to_string();
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = valid;
    let (entry_id, typed_block_id) = changed
        .record
        .typed_semantics
        .entries
        .iter()
        .find_map(|entry| {
            entry
                .blocks
                .iter()
                .find(|block| block.operations.iter().any(|operation| operation.opcode == "bounded-cell-load"))
                .map(|block| (entry.id.clone(), block.id))
        })
        .expect("fixture must bind the bounded Cell load to a typed block");
    let binding = changed
        .record
        .entries
        .iter_mut()
        .find(|entry| entry.id == entry_id)
        .and_then(|entry| entry.typed_blocks.iter_mut().find(|binding| binding.id == typed_block_id))
        .expect("fixture must contain a machine binding for the bounded Cell load");
    binding.machine_block_ids.pop().expect("bounded Cell load must map to machine code");
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2420TypedMachineBindingInvalid);
}

#[test]
fn bounded_output_plan_contract_is_bound_to_typed_and_machine_evidence() {
    let valid = Fixture::from_source(
        r#"
module checker::bounded_outputs

struct Plan { owner: Address, amount: u64 }
resource Token has store, create
with_capacity_floor(10000000000)
{ amount: u64 }

action verify(witness plans: BoundedList<Plan, 2>) -> u64 {
    verification
        create_each plan in plans {
            require plan.amount > 0
            create Token { amount: plan.amount } with_lock(plan.owner)
        }
        return 0
}
"#,
    );
    assert!(valid.check().is_ok());

    let mut changed = valid.clone();
    let declared_type = changed
        .record
        .typed_semantics
        .entries
        .iter_mut()
        .flat_map(|entry| &mut entry.blocks)
        .flat_map(|block| &mut block.operations)
        .find_map(|operation| match (&*operation.opcode, &mut operation.detail) {
            ("bounded-plan-load", TypedSemanticOperationDetail::Collection { declared_type }) => Some(declared_type),
            _ => None,
        })
        .expect("fixture must contain the bounded output plan decoder");
    *declared_type = "BoundedList<Plan, 0>".to_string();
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = valid;
    let (entry_id, typed_block_id) = changed
        .record
        .typed_semantics
        .entries
        .iter()
        .find_map(|entry| {
            entry
                .blocks
                .iter()
                .find(|block| block.operations.iter().any(|operation| operation.opcode == "bounded-output-verify"))
                .map(|block| (entry.id.clone(), block.id))
        })
        .expect("fixture must bind output verification to a typed block");
    let binding = changed
        .record
        .entries
        .iter_mut()
        .find(|entry| entry.id == entry_id)
        .and_then(|entry| entry.typed_blocks.iter_mut().find(|binding| binding.id == typed_block_id))
        .expect("fixture must contain a machine binding for bounded output verification");
    binding.machine_block_ids.clear();
    changed.rebind_sidecars();
    assert_code(&changed, CheckerRejectionCode::V2420TypedMachineBindingInvalid);
}

#[test]
fn typed_semantics_requires_reference_coercion_for_reference_calls() {
    let valid = Fixture::from_source(
        r#"
module checker::reference_call

struct Wallet {
    amount: u64,
}

fn inspect(wallet: &Wallet) -> u64 {
    return wallet.amount
}

action main(wallet: Wallet) -> u64 {
    verification
        return inspect(&wallet)
}
"#,
    );
    assert!(valid.check().is_ok());

    let mut changed = valid;
    let operator = changed
        .record
        .typed_semantics
        .entries
        .iter_mut()
        .flat_map(|entry| &mut entry.blocks)
        .flat_map(|block| &mut block.operations)
        .find_map(|operation| match &mut operation.detail {
            TypedSemanticOperationDetail::UnaryOperator { operator } if operator == "ref" => Some(operator),
            _ => None,
        })
        .expect("fixture must contain a reference coercion");
    *operator = "deref".to_string();
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);
}

#[test]
fn typed_semantics_requires_exact_guard_for_unsigned_narrowing() {
    let valid = Fixture::from_source(
        r#"
module checker::narrowing

action narrow(value: u64) -> u8 {
    verification
        return value as u8
}
"#,
    );
    assert!(valid.check().is_ok());

    let mut changed = valid;
    let bound = changed
        .record
        .typed_semantics
        .entries
        .iter_mut()
        .flat_map(|entry| &mut entry.blocks)
        .flat_map(|block| &mut block.operations)
        .flat_map(|operation| &mut operation.operands)
        .find_map(|operand| match &mut operand.constant {
            Some(TypedSemanticConstant::U64(value)) if value == "255" => Some(value),
            _ => None,
        })
        .expect("fixture must contain the u8 narrowing bound");
    *bound = "256".to_string();
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);
}

#[test]
fn typed_semantics_rejects_field_enum_layout_and_instantiation_mutations() {
    let valid = Fixture::from_source(include_str!("syntax_combo/seeds/generic-value.cell"));

    let mut changed = valid.clone();
    let field = changed
        .record
        .typed_semantics
        .entries
        .iter_mut()
        .flat_map(|entry| &mut entry.blocks)
        .flat_map(|block| &mut block.operations)
        .find_map(|operation| match &mut operation.detail {
            TypedSemanticOperationDetail::Field { name } => Some(name),
            _ => None,
        })
        .expect("fixture must contain a field access");
    *field = "missing".to_string();
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = valid.clone();
    let variant = changed
        .record
        .typed_semantics
        .entries
        .iter_mut()
        .flat_map(|entry| &mut entry.blocks)
        .flat_map(|block| &mut block.operations)
        .find_map(|operation| match &mut operation.detail {
            TypedSemanticOperationDetail::EnumConstruct { variant, .. } => Some(variant),
            _ => None,
        })
        .expect("fixture must contain an enum constructor");
    *variant = "Missing".to_string();
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = valid.clone();
    let field_index = changed
        .record
        .typed_semantics
        .entries
        .iter_mut()
        .flat_map(|entry| &mut entry.blocks)
        .flat_map(|block| &mut block.operations)
        .find_map(|operation| match &mut operation.detail {
            TypedSemanticOperationDetail::EnumPayload { field_index, .. } => Some(field_index),
            _ => None,
        })
        .expect("fixture must contain an enum payload read");
    *field_index = u32::MAX;
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = valid.clone();
    changed.record.typed_semantics.types[0].layout_hash = "00".repeat(32);
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = valid.clone();
    changed.record.typed_semantics.instantiations[0].identity.push_str("::tampered");
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);
}

#[test]
fn typed_semantics_rejects_borrow_ownership_cfg_and_reference_mutations() {
    let valid = Fixture::from_source(include_str!("syntax_combo/seeds/explicit-borrow.cell"));

    let mut changed = valid.clone();
    changed.record.typed_semantics.entries[0].borrows[0].start_operation = u32::MAX;
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = valid.clone();
    changed.record.typed_semantics.entries[0].ownership[0].final_state = "available".to_string();
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = valid.clone();
    let block = changed
        .record
        .typed_semantics
        .entries
        .iter_mut()
        .flat_map(|entry| &mut entry.blocks)
        .find(|block| !block.successors.is_empty())
        .expect("fixture must contain a CFG edge");
    block.successors[0] = u32::MAX;
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2419TypedSemanticsInvalid);

    let mut changed = Fixture::from_source(REFERENCE_ENTRY_SOURCE);
    let entry = changed
        .record
        .typed_semantics
        .entries
        .iter_mut()
        .find(|entry| entry.name == "inspect")
        .expect("fixture must contain the reference helper");
    let binding_id = entry.params[0].binding_id;
    entry.params[0].ty = "Token".to_string();
    entry.locals.iter_mut().find(|local| local.id == binding_id).unwrap().ty = "Token".to_string();
    for operand in entry.blocks.iter_mut().flat_map(|block| &mut block.operations).flat_map(|operation| &mut operation.operands) {
        if operand.local == Some(binding_id) {
            operand.ty = "Token".to_string();
        }
    }
    changed.rebind_typed_semantics();
    assert_code(&changed, CheckerRejectionCode::V2420TypedMachineBindingInvalid);
}

fn encode_jal(offset: i32) -> u32 {
    let immediate = offset as u32;
    (((immediate >> 20) & 1) << 31)
        | (((immediate >> 1) & 0x03ff) << 21)
        | (((immediate >> 11) & 1) << 20)
        | (((immediate >> 12) & 0x00ff) << 12)
        | 0x6f
}
