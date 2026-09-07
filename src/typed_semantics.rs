//! Compiler emission of the versioned typed-semantic record consumed by the
//! standalone artifact checker. The checker owns validation; this module only
//! translates checked IR into the shared, parser-free schema.

use crate::ir::{self, IrInstruction, IrOperand, IrTerminator, IrType, IrVar};
use crate::CompileMetadata;
use cellscript_artifact_checker::{
    canonical_hash, ArtifactContractDescriptor, ArtifactEntryContract, CellBindingMembership, CellBindingRole, CellBindingSource,
    CellDisposition, CellEnvelopeDisposition, ClaimExecutionBinding, EntryDispatchContract, FieldDisposition, InputDisposition,
    LayeredSemanticIdentities, LegacySemanticNode, OutputOrigin, ProvenanceBinding, ProvenanceGraph, ProvenanceNode, RoleBinding,
    SemanticClaim, SemanticFoundationRecord, TypedSemanticBlock, TypedSemanticBorrow, TypedSemanticCall, TypedSemanticCellBinding,
    TypedSemanticConstant, TypedSemanticCreatePattern, TypedSemanticEntry, TypedSemanticField, TypedSemanticInstantiation,
    TypedSemanticLocal, TypedSemanticOperand, TypedSemanticOperation, TypedSemanticOperationDetail, TypedSemanticOwnership,
    TypedSemanticParam, TypedSemanticRecord, TypedSemanticRuntimeError, TypedSemanticType, TypedSemanticVariant,
    TypedSemanticVariantField, ValueProvenance, PROVENANCE_GRAPH_SCHEMA, PROVENANCE_GRAPH_VERSION, SEMANTIC_FOUNDATION_SCHEMA,
    SEMANTIC_FOUNDATION_VERSION, TYPED_SEMANTICS_SCHEMA, TYPED_SEMANTICS_VERSION,
};
use std::collections::{BTreeMap, BTreeSet};

mod policy;

pub(crate) fn build(module: &ir::IrModule, metadata: &CompileMetadata) -> TypedSemanticRecord {
    let mut types = module
        .external_type_defs
        .iter()
        .chain(module.items.iter().filter_map(|item| match item {
            ir::IrItem::TypeDef(definition) => Some(definition),
            _ => None,
        }))
        .map(|definition| {
            let mut fields = definition
                .fields
                .iter()
                .map(|field| TypedSemanticField {
                    name: field.name.clone(),
                    ty: render_type(&field.ty),
                    offset: u32::try_from(field.offset).unwrap_or(u32::MAX),
                    width_bytes: field.fixed_size.and_then(|width| u32::try_from(width).ok()),
                })
                .collect::<Vec<_>>();
            fields.sort_by(|left, right| left.offset.cmp(&right.offset).then(left.name.cmp(&right.name)));
            let encoded_size = definition
                .fields
                .iter()
                .try_fold(0usize, |end, field| Some(end.max(field.offset.checked_add(field.fixed_size?)?)))
                .and_then(|width| u32::try_from(width).ok());
            let kind = match definition.kind {
                ir::IrTypeKind::Resource => "resource",
                ir::IrTypeKind::Shared => "shared",
                ir::IrTypeKind::Receipt => "receipt",
                ir::IrTypeKind::Struct => "struct",
            };
            let mut capabilities =
                definition.capabilities.iter().map(|capability| capability.as_str().to_string()).collect::<Vec<_>>();
            capabilities.sort();
            capabilities.dedup();
            let identity_policy = identity_policy_label(&definition.identity);
            let tag_width_bytes = None;
            let variants = Vec::<TypedSemanticVariant>::new();
            let layout_hash = canonical_hash(
                "cellscript-typed-layout-v2",
                &(kind, encoded_size, &fields, tag_width_bytes, &variants, &capabilities, &identity_policy),
            )
            .expect("typed layout record is serializable");
            TypedSemanticType {
                name: definition.name.clone(),
                kind: kind.to_string(),
                encoded_size,
                fields,
                tag_width_bytes,
                variants,
                capabilities,
                identity_policy,
                layout_hash,
            }
        })
        .collect::<Vec<_>>();
    for layout in module.enum_layouts.values() {
        let mut variants = layout
            .variants
            .iter()
            .map(|variant| TypedSemanticVariant {
                name: variant.name.clone(),
                tag: u32::from(variant.tag),
                payload_width_bytes: u32::try_from(variant.payload_width).unwrap_or(u32::MAX),
                fields: variant
                    .fields
                    .iter()
                    .map(|field| TypedSemanticVariantField {
                        index: u32::try_from(field.index).unwrap_or(u32::MAX),
                        ty: render_type(&field.ty),
                        offset: u32::try_from(field.offset).unwrap_or(u32::MAX),
                        width_bytes: u32::try_from(field.width).unwrap_or(u32::MAX),
                        linear: field.linear,
                    })
                    .collect(),
            })
            .collect::<Vec<_>>();
        variants.sort_by(|left, right| left.tag.cmp(&right.tag).then(left.name.cmp(&right.name)));
        for variant in &mut variants {
            variant.fields.sort_by_key(|field| field.index);
        }
        let encoded_size = u32::try_from(layout.encoded_size).ok();
        let fields = Vec::<TypedSemanticField>::new();
        let tag_width_bytes = u32::try_from(layout.tag_width).ok();
        let capabilities = Vec::<String>::new();
        let identity_policy = "none".to_string();
        let layout_hash = canonical_hash(
            "cellscript-typed-layout-v2",
            &("enum", encoded_size, &fields, tag_width_bytes, &variants, &capabilities, &identity_policy),
        )
        .expect("typed enum layout record is serializable");
        types.push(TypedSemanticType {
            name: layout.name.clone(),
            kind: "enum".to_string(),
            encoded_size,
            fields,
            tag_width_bytes,
            variants,
            capabilities,
            identity_policy,
            layout_hash,
        });
    }

    let signatures = callable_signatures(module);
    let mut entries = module
        .items
        .iter()
        .filter_map(|item| match item {
            ir::IrItem::Action(action) => Some(build_entry(
                "action",
                &action.name,
                &action.params,
                action.return_type.as_ref(),
                &format!("{:?}", action.effect_class),
                &action.body,
                &signatures,
                proof_ids(metadata, "action", &action.name),
            )),
            ir::IrItem::PureFn(function) => Some(build_entry(
                "helper",
                &function.name,
                &function.params,
                function.return_type.as_ref(),
                &format!("{:?}", function.effect_class),
                &function.body,
                &signatures,
                proof_ids(metadata, "helper", &function.name),
            )),
            ir::IrItem::Lock(lock) => Some(build_entry(
                "lock",
                &lock.name,
                &lock.params,
                Some(&IrType::Bool),
                "lock-predicate",
                &lock.body,
                &signatures,
                proof_ids(metadata, "lock", &lock.name),
            )),
            ir::IrItem::TypeDef(_) | ir::IrItem::Invariant(_) => None,
        })
        .collect::<Vec<_>>();
    let instantiations = metadata
        .generic_instantiations
        .iter()
        .map(|item| TypedSemanticInstantiation {
            kind: item.kind.clone(),
            module: item.module.clone(),
            template: item.template.clone(),
            concrete_name: item.concrete_name.clone(),
            identity: item.identity.clone(),
            type_arguments: item.type_arguments.clone(),
            value_ability_registry_version: item.value_ability_registry_version,
            constraints_verified: item.constraints_verified,
            fixed_layout_required: item.fixed_layout_required,
            cell_backed_layout_rejected: item.cell_backed_layout_rejected,
            identity_includes_phantom_arguments: item.identity_includes_phantom_arguments,
        })
        .collect::<Vec<_>>();
    let mut record = TypedSemanticRecord {
        schema: TYPED_SEMANTICS_SCHEMA.to_string(),
        version: TYPED_SEMANTICS_VERSION,
        module: module.name.clone(),
        interface_hash: String::new(),
        failure_semantics: cellscript_artifact_checker::VerifierFailureSemantics::CurrentVmProcessExitV1,
        types: {
            types.sort_by(|left, right| left.name.cmp(&right.name));
            types.dedup_by(|left, right| left.name == right.name);
            types
        },
        entries: {
            entries.sort_by(|left, right| left.id.cmp(&right.id));
            entries
        },
        instantiations,
        trusted_external_verifiers: metadata.runtime.trusted_external_verifiers.clone(),
        foundation: SemanticFoundationRecord::default(),
    };
    record.canonicalize();
    record.foundation = build_semantic_foundation(module, metadata, &record.types, &record.entries);
    record.canonicalize();
    record
}

fn build_semantic_foundation(
    module: &ir::IrModule,
    metadata: &CompileMetadata,
    types: &[TypedSemanticType],
    entries: &[TypedSemanticEntry],
) -> SemanticFoundationRecord {
    let type_layouts = types.iter().map(|ty| (ty.name.as_str(), ty)).collect::<BTreeMap<_, _>>();
    let (mut provenance, condition_nodes) = build_provenance_graph(entries, module);
    let entry_contract =
        policy::build_entry_contract(module, types, entries, &mut provenance).unwrap_or_else(|| build_entry_contract(module));
    let mut roles = Vec::new();
    let mut dispositions = Vec::new();
    let mut legacy_nodes = Vec::new();

    for item in &module.items {
        let (kind, name, params, body, source_dispositions) = match item {
            ir::IrItem::Action(entry) => {
                ("action", entry.name.as_str(), entry.params.as_slice(), &entry.body, entry.source_dispositions.as_slice())
            }
            ir::IrItem::Lock(entry) => {
                ("lock", entry.name.as_str(), entry.params.as_slice(), &entry.body, &[] as &[ir::IrSourceDisposition])
            }
            ir::IrItem::PureFn(entry) => {
                ("helper", entry.name.as_str(), entry.params.as_slice(), &entry.body, &[] as &[ir::IrSourceDisposition])
            }
            ir::IrItem::TypeDef(_) | ir::IrItem::Invariant(_) => continue,
        };
        let entry_id = format!("{kind}:{name}");
        if kind == "helper" {
            continue;
        }
        let typed_entry = entries.iter().find(|entry| entry.id == entry_id).expect("IR callable has a typed entry");
        append_roles(&mut roles, typed_entry, &type_layouts);
        append_dispositions(
            &mut dispositions,
            &mut legacy_nodes,
            &entry_id,
            kind,
            params,
            body,
            source_dispositions,
            &type_layouts,
            &metadata.runtime.proof_plan,
        );
    }
    roles.sort_by(|left, right| left.role_id.cmp(&right.role_id));
    roles.dedup_by(|left, right| left.role_id == right.role_id);
    dispositions.sort_by(|left, right| left.id.cmp(&right.id));
    dispositions.dedup_by(|left, right| left.id == right.id);
    legacy_nodes.sort_by(|left, right| left.id.cmp(&right.id));
    legacy_nodes.dedup_by(|left, right| left.id == right.id);
    let mut claims = build_claims(metadata, module, entries, &condition_nodes);
    claims.sort_by(|left, right| left.id.cmp(&right.id));

    let core_semantic_id = canonical_hash(
        "cellscript-core-semantic-id-v2",
        &(
            cellscript_artifact_checker::VerifierFailureSemantics::CurrentVmProcessExitV1,
            types,
            &roles,
            &dispositions,
            &claims,
            &legacy_nodes,
        ),
    )
    .expect("semantic foundation core projection is serializable");
    let provenance_roots = provenance
        .nodes
        .iter()
        .filter(|node| !matches!(node.provenance, ValueProvenance::Derived { .. }))
        .map(|node| node.id.as_str())
        .collect::<Vec<_>>();
    let entry_contract_id = canonical_hash(
        "cellscript-entry-contract-id-v1",
        &(
            core_semantic_id.as_str(),
            &entry_contract,
            provenance_roots,
            entry_contract.entry_payload_abi.as_str(),
            entry_contract.witness_placement_abi.as_str(),
        ),
    )
    .expect("semantic foundation entry projection is serializable");
    let artifact_contract = ArtifactContractDescriptor {
        target_profile: metadata.target_profile.name.clone(),
        artifact_format: metadata.artifact_format.clone(),
        lowering_record_schema: cellscript_artifact_checker::LOWERING_RECORD_SCHEMA.to_string(),
        typed_semantics_schema: TYPED_SEMANTICS_SCHEMA.to_string(),
    };
    let artifact_contract_id = canonical_hash("cellscript-artifact-contract-id-v1", &(entry_contract_id.as_str(), &artifact_contract))
        .expect("semantic foundation artifact projection is serializable");

    let mut foundation = SemanticFoundationRecord {
        schema: SEMANTIC_FOUNDATION_SCHEMA.to_string(),
        version: SEMANTIC_FOUNDATION_VERSION,
        provenance,
        entry_contract,
        roles,
        dispositions,
        claims,
        artifact_contract,
        identities: LayeredSemanticIdentities { core_semantic_id, entry_contract_id, artifact_contract_id },
        legacy_nodes,
    };
    foundation.canonicalize();
    foundation
}

fn build_entry_contract(module: &ir::IrModule) -> ArtifactEntryContract {
    let (script_role, trigger, exact_entry) = module
        .resolved_entry()
        .map(|entry| (entry.script_role(), entry.trigger(), format!("{}:{}", entry.kind(), entry.name())))
        .unwrap_or(("none", "none", "none".to_string()));
    let semantic_node_id = canonical_hash(
        "cellscript-semantic-node-entry-contract-v1",
        &(
            script_role,
            trigger,
            exact_entry.as_str(),
            "single-entry",
            crate::ENTRY_WITNESS_ABI,
            crate::ENTRY_WITNESS_PLACEMENT_ABI,
            crate::ENTRY_WITNESS_PLACEMENT_FIELD,
            crate::ENTRY_WITNESS_PLACEMENT_SOURCE,
        ),
    )
    .expect("entry contract node is serializable");
    ArtifactEntryContract {
        semantic_node_id,
        script_role: script_role.to_string(),
        trigger: trigger.to_string(),
        exact_entry,
        dispatch: EntryDispatchContract::SingleEntry,
        entry_payload_abi: crate::ENTRY_WITNESS_ABI.to_string(),
        witness_placement_abi: crate::ENTRY_WITNESS_PLACEMENT_ABI.to_string(),
        witness_placement_field: crate::ENTRY_WITNESS_PLACEMENT_FIELD.to_string(),
        witness_placement_source: crate::ENTRY_WITNESS_PLACEMENT_SOURCE.to_string(),
    }
}

fn build_provenance_graph(
    entries: &[TypedSemanticEntry],
    module: &ir::IrModule,
) -> (ProvenanceGraph, BTreeMap<(String, u32), String>) {
    let cell_types = module
        .external_type_defs
        .iter()
        .chain(module.items.iter().filter_map(|item| match item {
            ir::IrItem::TypeDef(definition) => Some(definition),
            _ => None,
        }))
        .filter(|definition| matches!(definition.kind, ir::IrTypeKind::Resource | ir::IrTypeKind::Shared | ir::IrTypeKind::Receipt))
        .map(|definition| definition.name.clone())
        .collect::<BTreeSet<_>>();
    let abi_sources = module
        .items
        .iter()
        .filter_map(|item| {
            let (kind, name, params, body) = match item {
                ir::IrItem::Action(action) => ("action", &action.name, &action.params, &action.body),
                ir::IrItem::Lock(lock) => ("lock", &lock.name, &lock.params, &lock.body),
                ir::IrItem::PureFn(function) => ("helper", &function.name, &function.params, &function.body),
                ir::IrItem::TypeDef(_) | ir::IrItem::Invariant(_) => return None,
            };
            Some((format!("{kind}:{name}"), crate::codegen::entry_param_abi_sources(params, body, &cell_types, &module.enum_layouts)))
        })
        .collect::<BTreeMap<_, _>>();
    let mut nodes = BTreeMap::<String, ProvenanceNode>::new();
    let mut bindings = Vec::new();
    let mut condition_nodes = BTreeMap::new();
    for entry in entries {
        let mut local_nodes = BTreeMap::<u32, String>::new();
        let mut named_nodes = BTreeMap::<String, String>::new();
        for param in &entry.params {
            let provenance = param_provenance(entry, param, &abi_sources[&entry.id], module);
            let node_id = insert_provenance_node(&mut nodes, provenance);
            local_nodes.insert(param.binding_id, node_id.clone());
            named_nodes.insert(param.name.clone(), node_id.clone());
            bindings.push(ProvenanceBinding { entry_id: entry.id.clone(), local_id: param.binding_id, node_id });
        }
        for block in &entry.blocks {
            for operation in &block.operations {
                let mut input_nodes = Vec::with_capacity(operation.operands.len());
                for operand in &operation.operands {
                    if let Some(local) = operand.local {
                        if let Some(node) = local_nodes.get(&local).cloned() {
                            input_nodes.push(node);
                            continue;
                        }
                        if let Some(node) = alias_provenance_node(entry, local, &local_nodes) {
                            local_nodes.insert(local, node.clone());
                            bindings.push(ProvenanceBinding { entry_id: entry.id.clone(), local_id: local, node_id: node.clone() });
                            input_nodes.push(node);
                            continue;
                        }
                    }
                    let declaration = operand
                        .constant
                        .as_ref()
                        .map(|constant| format!("{:?}", constant))
                        .unwrap_or_else(|| format!("typed-local:{}", operand.local.unwrap_or(u32::MAX)));
                    input_nodes.push(insert_provenance_node(&mut nodes, ValueProvenance::Constant { declaration }));
                }
                if operation.opcode == "bounded-cell-load"
                    && let Some(root) = entry
                        .params
                        .iter()
                        .find(|param| param.ty.starts_with("BoundedCellSet<"))
                        .and_then(|param| local_nodes.get(&param.binding_id))
                {
                    input_nodes.insert(0, root.clone());
                }
                if operation.opcode == "load-var"
                    && let TypedSemanticOperationDetail::Binding { name } = &operation.detail
                    && let Some(node_id) = named_nodes.get(name).cloned()
                {
                    bind_operation_destinations(entry, operation, node_id, &mut local_nodes, &mut bindings);
                    continue;
                }
                if operation.opcode == "store-var"
                    && let TypedSemanticOperationDetail::Binding { name } = &operation.detail
                    && let Some(node_id) = input_nodes.first().cloned()
                {
                    named_nodes.insert(name.clone(), node_id);
                    continue;
                }
                if operation.opcode == "branch-condition"
                    && let Some(condition_node) = input_nodes.first()
                {
                    condition_nodes.insert((entry.id.clone(), block.id), condition_node.clone());
                }
                if operation.opcode == "read-ref" {
                    for destination in &operation.destinations {
                        let binding =
                            cell_binding_for_typed_local(entry, *destination).expect("lowered read_ref has a resolved Cell binding");
                        let node_id = insert_provenance_node(&mut nodes, binding.provenance(&entry.id));
                        local_nodes.insert(*destination, node_id.clone());
                        // Generated temporary names are not source bindings.
                        // A user may legitimately name a parameter
                        // `read_ref_Config`; only StoreVar can introduce an
                        // alias into named_nodes without shadowing that value.
                        bindings.push(ProvenanceBinding { entry_id: entry.id.clone(), local_id: *destination, node_id });
                    }
                    continue;
                }
                for (destination_index, destination) in operation.destinations.iter().enumerate() {
                    let provenance = cell_binding_for_typed_local(entry, *destination)
                        .map(|binding| binding.provenance(&entry.id))
                        .unwrap_or_else(|| ValueProvenance::Derived {
                            operation: format!("{}#{}", operation.opcode, destination_index),
                            inputs: input_nodes.clone(),
                        });
                    let node_id = insert_provenance_node(&mut nodes, provenance);
                    local_nodes.insert(*destination, node_id.clone());
                    bindings.push(ProvenanceBinding { entry_id: entry.id.clone(), local_id: *destination, node_id });
                }
            }
        }
    }
    let mut graph = ProvenanceGraph {
        schema: PROVENANCE_GRAPH_SCHEMA.to_string(),
        version: PROVENANCE_GRAPH_VERSION,
        nodes: nodes.into_values().collect(),
        bindings,
    };
    graph.canonicalize();
    (graph, condition_nodes)
}

fn alias_provenance_node(entry: &TypedSemanticEntry, local_id: u32, local_nodes: &BTreeMap<u32, String>) -> Option<String> {
    let source_id = entry.locals.iter().find(|local| local.id == local_id)?.source_id;
    entry.locals.iter().filter(|local| local.source_id == source_id).find_map(|local| local_nodes.get(&local.id).cloned())
}

fn cell_binding_for_typed_local(entry: &TypedSemanticEntry, local_id: u32) -> Option<&TypedSemanticCellBinding> {
    let source_id = entry.locals.iter().find(|local| local.id == local_id)?.source_id;
    entry.cell_bindings.iter().find(|binding| {
        binding.local_id.is_some_and(|root| entry.locals.iter().any(|local| local.id == root && local.source_id == source_id))
    })
}

fn param_provenance(
    entry: &TypedSemanticEntry,
    param: &TypedSemanticParam,
    abi_sources: &[crate::codegen::EntryParamAbiSource],
    module: &ir::IrModule,
) -> ValueProvenance {
    let policy = match &module.entry_selection {
        ir::IrEntrySelection::Artifact(declaration) => Some(declaration),
        _ => None,
    };
    let policy_variant = policy.and_then(|declaration| declaration.action(&entry.name));
    if entry.kind == "helper" || (policy.is_some() && policy_variant.is_none()) {
        return ValueProvenance::Derived { operation: format!("call-parameter:{}", param.name), inputs: Vec::new() };
    }
    if let Some(binding) = cell_binding_for_typed_local(entry, param.binding_id) {
        return binding.provenance(&entry.id);
    }
    if param.ty.starts_with("BoundedCellSet<") {
        return ValueProvenance::GroupInput {
            role: format!("{}:{}", entry.id, param.name),
            ordinal: "all-in-canonical-group-order-up-to-bound".to_string(),
            field_path: "cell".to_string(),
        };
    }
    match &abi_sources[param.index as usize] {
        crate::codegen::EntryParamAbiSource::ScriptArgs { byte_range } => ValueProvenance::ScriptArgs {
            script_role: if entry.kind == "lock" { "lock" } else { "type" }.to_string(),
            byte_range: byte_range
                .map(|(start, end)| format!("{start}..{end}"))
                .unwrap_or_else(|| "unsupported-fail-closed".to_string()),
            codec: "typed-fixed-bytes".to_string(),
        },
        crate::codegen::EntryParamAbiSource::Witness { ordinal } if policy_variant.is_some() => ValueProvenance::EntryWitness {
            placement_abi: crate::artifact::POLICY_WITNESS_PLACEMENT_ABI.to_string(),
            payload_abi: crate::policy_witness::POLICY_WITNESS_ABI.to_string(),
            group_witness_source: crate::artifact::POLICY_WITNESS_PLACEMENT_SOURCE.to_string(),
            field_path: format!("input_type.records[type,current-script-hash].args[{ordinal}].{}", param.name),
        },
        crate::codegen::EntryParamAbiSource::Witness { ordinal } => ValueProvenance::EntryWitness {
            placement_abi: crate::ENTRY_WITNESS_PLACEMENT_ABI.to_string(),
            payload_abi: crate::ENTRY_WITNESS_ABI.to_string(),
            group_witness_source: crate::ENTRY_WITNESS_PLACEMENT_SOURCE.to_string(),
            field_path: format!("args[{ordinal}].{}", param.name),
        },
        crate::codegen::EntryParamAbiSource::Unit => ValueProvenance::Constant { declaration: "Unit".to_string() },
        crate::codegen::EntryParamAbiSource::RuntimeBound => ValueProvenance::Derived {
            operation: format!("unresolved-runtime-bound-entry-parameter:{}", param.name),
            inputs: Vec::new(),
        },
        crate::codegen::EntryParamAbiSource::Unsupported => {
            ValueProvenance::Derived { operation: format!("unsupported-entry-abi:{}", param.name), inputs: Vec::new() }
        }
    }
}

fn insert_provenance_node(nodes: &mut BTreeMap<String, ProvenanceNode>, provenance: ValueProvenance) -> String {
    let id = canonical_hash("cellscript-value-provenance-node-v1", &provenance).expect("value provenance node is serializable");
    nodes.entry(id.clone()).or_insert_with(|| ProvenanceNode { id: id.clone(), provenance });
    id
}

fn bind_operation_destinations(
    entry: &TypedSemanticEntry,
    operation: &TypedSemanticOperation,
    node_id: String,
    local_nodes: &mut BTreeMap<u32, String>,
    bindings: &mut Vec<ProvenanceBinding>,
) {
    for destination in &operation.destinations {
        local_nodes.insert(*destination, node_id.clone());
        bindings.push(ProvenanceBinding { entry_id: entry.id.clone(), local_id: *destination, node_id: node_id.clone() });
    }
}

fn append_roles(roles: &mut Vec<RoleBinding>, entry: &TypedSemanticEntry, types: &BTreeMap<&str, &TypedSemanticType>) {
    let script_role = if entry.kind == "lock" { "lock" } else { "type" };
    for binding in &entry.cell_bindings {
        let direction = binding.direction();
        let role_id = binding.role_id(&entry.id);
        let schema_identity = types
            .get(binding.ty.as_str())
            .map(|layout| layout.layout_hash.clone())
            .unwrap_or_else(|| format!("unresolved:{}", binding.ty));
        let correspondence = if binding.role == CellBindingRole::Output {
            entry
                .cell_bindings
                .iter()
                .find(|input| input.binding == binding.binding && input.role == CellBindingRole::Input)
                .map_or_else(
                    || format!("canonical-output:{}", binding.selector()),
                    |input| format!("successor-of-{}", input.selector()),
                )
        } else {
            "none".to_string()
        };
        roles.push(make_role(
            role_id,
            &entry.id,
            binding.binding.clone(),
            binding.ty.clone(),
            direction,
            binding.source_scope(),
            binding.selector(),
            "exactly-one".to_string(),
            script_role,
            binding.membership_policy(),
            schema_identity,
            correspondence,
        ));
    }
    // Bounded handles have an independently executable scan contract. They
    // must not be projected as a fixed Cell at the parameter signature index.
    for param in &entry.params {
        let Some(element) = bounded_cell_element(&param.ty) else { continue };
        let Some(maximum) = bounded_cell_maximum(&param.ty) else { continue };
        roles.push(make_role(
            format!("role:{}:input:{}", entry.id, param.name),
            &entry.id,
            param.name.clone(),
            param.ty.clone(),
            "input",
            "group-relative",
            "all current Type Script Group cells in canonical group order".to_string(),
            format!("0..={maximum}"),
            script_role,
            "current-type-group",
            types.get(element).map(|layout| layout.layout_hash.clone()).unwrap_or_else(|| format!("unresolved:{element}")),
            "none".to_string(),
        ));
    }
}
#[allow(clippy::too_many_arguments)]
fn make_role(
    role_id: String,
    entry_id: &str,
    binding: String,
    ty: String,
    direction: &str,
    source: &str,
    selector: String,
    cardinality: String,
    lock_or_type_role: &str,
    script_identity_policy: &str,
    schema_identity: String,
    correspondence_policy: String,
) -> RoleBinding {
    let semantic_node_id = canonical_hash(
        "cellscript-semantic-node-role-v1",
        &(
            role_id.as_str(),
            entry_id,
            binding.as_str(),
            ty.as_str(),
            direction,
            source,
            selector.as_str(),
            cardinality.as_str(),
            lock_or_type_role,
            script_identity_policy,
            schema_identity.as_str(),
            correspondence_policy.as_str(),
        ),
    )
    .expect("role binding node is serializable");
    RoleBinding {
        semantic_node_id,
        role_id,
        entry_id: entry_id.to_string(),
        binding,
        ty,
        direction: direction.to_string(),
        locality: "local".to_string(),
        source: source.to_string(),
        selector,
        cardinality,
        lock_or_type_role: lock_or_type_role.to_string(),
        script_identity_policy: script_identity_policy.to_string(),
        schema_identity,
        correspondence_policy,
    }
}

fn append_source_dispositions(
    dispositions: &mut Vec<CellDisposition>,
    entry_id: &str,
    params: &[ir::IrParam],
    body: &ir::IrBody,
    source_dispositions: &[ir::IrSourceDisposition],
    types: &BTreeMap<&str, &TypedSemanticType>,
) {
    for source in source_dispositions {
        let input_role = source.input_binding.as_ref().map(|binding| format!("role:{entry_id}:input:{binding}"));
        let output_role = source.output_binding.as_ref().map(|binding| {
            let ordinal = body
                .cell_binding(ir::IrCellBindingRole::Output, binding)
                .expect("native output has a resolved physical location")
                .ordinal;
            format!("role:{entry_id}:output:{binding}:output[{ordinal}]")
        });
        match &source.kind {
            ir::IrSourceDispositionKind::Successor => {
                let input_binding = source.input_binding.as_deref().expect("validated native successor input");
                let output_binding = source.output_binding.as_deref().expect("validated native successor output");
                let input_ordinal = source_role_ordinal(params, input_binding, crate::ast::ParamSource::Input);
                let output_ordinal = source_role_ordinal(params, output_binding, crate::ast::ParamSource::Output);
                let lock_expression = source.lock_expression.as_deref().expect("validated native successor lock expression");
                dispositions.push(make_disposition(
                    ir::source_disposition_id(entry_id, source),
                    entry_id,
                    input_role.clone(),
                    output_role.clone(),
                    Some(InputDisposition::Successor { output_role: output_role.expect("successor output role") }),
                    Some(OutputOrigin::SuccessorOf { input_role: input_role.expect("successor input role") }),
                    CellEnvelopeDisposition {
                        completeness: "exhaustive".to_string(),
                        data_fields: source
                            .data_fields
                            .iter()
                            .map(|(field, treatment)| FieldDisposition { field: field.clone(), treatment: treatment.clone() })
                            .collect(),
                        logical_identity: "preserve-and-check".to_string(),
                        lock_script: format!("set-and-check-exact-hash:{lock_expression}"),
                        type_script: "preserve-and-check".to_string(),
                        capacity: "builder-set-and-chain-checked".to_string(),
                        cardinality: "one-input-to-one-output".to_string(),
                        correspondence: format!("group-input[{input_ordinal}]->group-output[{output_ordinal}]"),
                    },
                    "checked-runtime",
                ));
            }
            ir::IrSourceDispositionKind::PooledInput { pool_id, accounting_obligation } => {
                dispositions.push(make_disposition(
                    ir::source_disposition_id(entry_id, source),
                    entry_id,
                    input_role,
                    None,
                    Some(InputDisposition::Pooled { pool_id: pool_id.clone(), accounting_obligation: accounting_obligation.clone() }),
                    None,
                    CellEnvelopeDisposition {
                        completeness: "exhaustive".to_string(),
                        data_fields: source
                            .data_fields
                            .iter()
                            .map(|(field, treatment)| FieldDisposition { field: field.clone(), treatment: treatment.clone() })
                            .collect(),
                        logical_identity: format!("pool:{pool_id}"),
                        lock_script: "released-with-consumed-input".to_string(),
                        type_script: "checked-type-group-member".to_string(),
                        capacity: "released-to-transaction-balance".to_string(),
                        cardinality: "declared-pool-input-role".to_string(),
                        correspondence: pool_id.clone(),
                    },
                    "checked-runtime",
                ));
            }
            ir::IrSourceDispositionKind::PoolResult { pool_id, accounting_obligation } => {
                let lock_expression = source.lock_expression.as_deref().expect("validated native pool result lock expression");
                dispositions.push(make_disposition(
                    ir::source_disposition_id(entry_id, source),
                    entry_id,
                    None,
                    output_role,
                    None,
                    Some(OutputOrigin::PoolResult { pool_id: pool_id.clone(), accounting_obligation: accounting_obligation.clone() }),
                    CellEnvelopeDisposition {
                        completeness: "exhaustive".to_string(),
                        data_fields: source
                            .data_fields
                            .iter()
                            .map(|(field, treatment)| FieldDisposition { field: field.clone(), treatment: treatment.clone() })
                            .collect(),
                        logical_identity: format!("pool:{pool_id}"),
                        lock_script: format!("set-and-check-exact-hash:{lock_expression}"),
                        type_script: "checked-type-group-member".to_string(),
                        capacity: "builder-computed-and-chain-checked".to_string(),
                        cardinality: "declared-pool-output-role".to_string(),
                        correspondence: pool_id.clone(),
                    },
                    "checked-runtime",
                ));
            }
            ir::IrSourceDispositionKind::Retired { absence_policy } => {
                let input_binding = source.input_binding.as_deref().expect("validated native retirement input");
                let ty = source_binding_type(params, body, input_binding).unwrap_or_default();
                dispositions.push(make_disposition(
                    ir::source_disposition_id(entry_id, source),
                    entry_id,
                    input_role,
                    None,
                    Some(InputDisposition::Retired { absence_policy: absence_policy.clone() }),
                    None,
                    CellEnvelopeDisposition {
                        completeness: "exhaustive".to_string(),
                        data_fields: type_fields(types, &ty)
                            .into_iter()
                            .map(|field| FieldDisposition {
                                field: field.to_string(),
                                treatment: "decoded-then-discarded".to_string(),
                            })
                            .collect(),
                        logical_identity: format!("retire:{absence_policy}"),
                        lock_script: "no-successor".to_string(),
                        type_script: "absence-checked".to_string(),
                        capacity: "released-with-consumed-input".to_string(),
                        cardinality: "exactly-one".to_string(),
                        correspondence: "absence-policy".to_string(),
                    },
                    "checked-runtime",
                ));
            }
            ir::IrSourceDispositionKind::Fresh { identity_policy } => {
                let output_binding = source.output_binding.as_deref().expect("validated native fresh output");
                let lock_expression = source.lock_expression.as_deref().expect("validated native fresh lock expression");
                let output_ordinal = source_role_ordinal(params, output_binding, crate::ast::ParamSource::Output);
                dispositions.push(make_disposition(
                    ir::source_disposition_id(entry_id, source),
                    entry_id,
                    None,
                    output_role,
                    None,
                    Some(OutputOrigin::Fresh { identity_policy: identity_policy.clone() }),
                    CellEnvelopeDisposition {
                        completeness: "exhaustive".to_string(),
                        data_fields: source
                            .data_fields
                            .iter()
                            .map(|(field, expression)| FieldDisposition {
                                field: field.clone(),
                                treatment: format!("set-from-expression:{expression}"),
                            })
                            .collect(),
                        logical_identity: format!("create:{identity_policy}"),
                        lock_script: format!("set-and-check-exact-hash:{lock_expression}"),
                        type_script: "set-to-declared-resource-type".to_string(),
                        capacity: "builder-computed-and-chain-checked".to_string(),
                        cardinality: "exactly-one".to_string(),
                        correspondence: format!("group-output[{output_ordinal}]"),
                    },
                    "checked-runtime",
                ));
            }
        }
    }
}

fn source_role_ordinal(params: &[ir::IrParam], binding: &str, source: crate::ast::ParamSource) -> usize {
    params
        .iter()
        .filter(|param| param.source == source)
        .position(|param| param.name == binding)
        .expect("validated native role remains in the lowered signature")
}

fn source_binding_type(params: &[ir::IrParam], body: &ir::IrBody, binding: &str) -> Option<String> {
    params
        .iter()
        .find(|param| param.name == binding)
        .map(|param| strip_semantic_reference(&render_type(&param.ty)).to_string())
        .or_else(|| body.create_set.iter().find(|pattern| pattern.binding == binding).map(|pattern| pattern.ty.clone()))
}

// Legacy node meanings name the semantic contract inherited from Edition 2026,
// not the caller's source edition. The outer compatibility profile already
// records the frontend. Keeping these meanings fixed preserves canonical IDs
// for identical legacy operations accepted by the authoring frontend.
fn append_dispositions(
    dispositions: &mut Vec<CellDisposition>,
    legacy_nodes: &mut Vec<LegacySemanticNode>,
    entry_id: &str,
    entry_kind: &str,
    params: &[ir::IrParam],
    body: &ir::IrBody,
    source_dispositions: &[ir::IrSourceDisposition],
    types: &BTreeMap<&str, &TypedSemanticType>,
    proof_plan: &[crate::ProofPlanMetadata],
) {
    if entry_kind == "lock" {
        for param in params.iter().filter(|param| param.source == crate::ast::ParamSource::Protected) {
            let rendered_ty = render_type(&param.ty);
            let ty = strip_semantic_reference(&rendered_ty);
            let input_role = format!("role:{entry_id}:input:{}", param.name);
            dispositions.push(make_disposition(
                format!("disposition:{entry_id}:authorization-only:{}", param.name),
                entry_id,
                Some(input_role),
                None,
                Some(InputDisposition::AuthorizationOnly {
                    disposition_owner: "type-script-or-explicit-transaction-policy".to_string(),
                }),
                None,
                CellEnvelopeDisposition {
                    completeness: "authorization-scope-explicit".to_string(),
                    data_fields: type_fields(types, ty)
                        .into_iter()
                        .map(|field| FieldDisposition {
                            field: field.to_string(),
                            treatment: "not-constrained-by-lock-artifact".to_string(),
                        })
                        .collect(),
                    logical_identity: "not-constrained-by-lock-artifact".to_string(),
                    lock_script: "spend-authorization-checked".to_string(),
                    type_script: "not-constrained-by-lock-artifact".to_string(),
                    capacity: "not-constrained-by-lock-artifact".to_string(),
                    cardinality: "exactly-one-protected-role".to_string(),
                    correspondence: "none-authorized-spend-only".to_string(),
                },
                "checked-runtime",
            ));
        }
        return;
    }
    if !source_dispositions.is_empty() {
        append_source_dispositions(dispositions, entry_id, params, body, source_dispositions, types);
        return;
    }
    let mutated = body.mutate_set.iter().map(|pattern| pattern.binding.as_str()).collect::<BTreeSet<_>>();
    for pattern in &body.mutate_set {
        let input_role = format!("role:{entry_id}:input:{}", pattern.binding);
        let output_role = format!("role:{entry_id}:output:{}:output[{}]", pattern.binding, pattern.output_index);
        let transition_by_field = pattern
            .transitions
            .iter()
            .map(|transition| {
                let operation = match transition.op {
                    ir::MutateTransitionOp::Set => "set",
                    ir::MutateTransitionOp::Add => "add",
                    ir::MutateTransitionOp::Sub => "sub",
                    ir::MutateTransitionOp::Append => "append",
                };
                (transition.field.as_str(), operation)
            })
            .collect::<BTreeMap<_, _>>();
        let fields = type_fields(types, &pattern.ty)
            .into_iter()
            .map(|field| FieldDisposition {
                treatment: if pattern.preserved_fields.iter().any(|preserved| preserved == field) {
                    "preserve".to_string()
                } else if let Some(operation) = transition_by_field.get(field) {
                    format!("{operation}-from-expression")
                } else {
                    "set-from-expression".to_string()
                },
                field: field.to_string(),
            })
            .collect::<Vec<_>>();
        let id = format!("disposition:{entry_id}:successor:{}", pattern.binding);
        dispositions.push(make_disposition(
            id,
            entry_id,
            Some(input_role.clone()),
            Some(output_role.clone()),
            Some(InputDisposition::Successor { output_role }),
            Some(OutputOrigin::SuccessorOf { input_role }),
            CellEnvelopeDisposition {
                completeness: "exhaustive".to_string(),
                data_fields: fields,
                logical_identity: "preserve".to_string(),
                lock_script: if pattern.preserve_lock_hash { "preserve" } else { "set-and-check" }.to_string(),
                type_script: if pattern.preserve_type_hash { "preserve" } else { "set-and-check" }.to_string(),
                capacity: "preserve-or-explicit-runtime-relation".to_string(),
                cardinality: "one-input-to-one-output".to_string(),
                correspondence: format!("input[{}]->output[{}]", pattern.input_index, pattern.output_index),
            },
            "checked-runtime",
        ));
    }
    let successor_pairs = checked_successor_pairs(entry_id, params, body, proof_plan);
    let successor_inputs = successor_pairs.iter().map(|pair| pair.input_binding.as_str()).collect::<BTreeSet<_>>();
    let successor_outputs = successor_pairs.iter().map(|pair| pair.output_binding.as_str()).collect::<BTreeSet<_>>();
    for pair in &successor_pairs {
        let input_role = format!("role:{entry_id}:input:{}", pair.input_binding);
        let output_role = format!("role:{entry_id}:output:{}:output[{}]", pair.output_binding, pair.output_index);
        let fields = type_fields(types, &pair.ty)
            .into_iter()
            .map(|field| FieldDisposition { field: field.to_string(), treatment: "checked-successor-relation".to_string() })
            .collect::<Vec<_>>();
        dispositions.push(make_disposition(
            format!("disposition:{entry_id}:successor:{}->{}", pair.input_binding, pair.output_binding),
            entry_id,
            Some(input_role.clone()),
            Some(output_role.clone()),
            Some(InputDisposition::Successor { output_role }),
            Some(OutputOrigin::SuccessorOf { input_role }),
            CellEnvelopeDisposition {
                completeness: "exhaustive".to_string(),
                data_fields: fields,
                logical_identity: "preserve-and-check".to_string(),
                lock_script: pair
                    .lock_expression
                    .as_ref()
                    .map_or_else(|| "preserve-and-check".to_string(), |expression| format!("set-and-check-exact-hash:{expression}")),
                type_script: "preserve-and-check".to_string(),
                capacity: "builder-set-and-chain-checked".to_string(),
                cardinality: "one-input-to-one-output".to_string(),
                correspondence: format!("input[{}]->output[{}]", pair.input_index, pair.output_index),
            },
            "checked-runtime",
        ));
    }
    for pattern in &body.consume_set {
        if mutated.contains(pattern.binding.as_str()) || successor_inputs.contains(pattern.binding.as_str()) {
            continue;
        }
        let input_role = format!("role:{entry_id}:input:{}", pattern.binding);
        let (input, identity, completeness, migration) = if pattern.operation == "destroy" {
            (
                InputDisposition::Retired { absence_policy: "legacy-destruction-policy".to_string() },
                "retire-under-declared-policy",
                "legacy-policy-bound",
                "review the legacy destruction policy and spell Retired(absence_policy) explicitly",
            )
        } else {
            (
                InputDisposition::LegacyConsumed {
                    operation: pattern.operation.clone(),
                    migration: "explicit-successor-pooled-or-retired-required".to_string(),
                },
                "legacy-unspecified",
                "legacy-ambiguous",
                "choose Successor, Pooled, or Retired; migration is intentionally non-mechanical",
            )
        };
        let id = format!("disposition:{entry_id}:input:{}", pattern.binding);
        let disposition = make_disposition(
            id.clone(),
            entry_id,
            Some(input_role),
            None,
            Some(input),
            None,
            CellEnvelopeDisposition {
                completeness: completeness.to_string(),
                data_fields: pattern
                    .fields
                    .iter()
                    .map(|(field, _)| FieldDisposition {
                        field: field.clone(),
                        treatment: "decoded-before-legacy-discharge".to_string(),
                    })
                    .collect(),
                logical_identity: identity.to_string(),
                lock_script: "no-successor-envelope".to_string(),
                type_script: "no-successor-envelope".to_string(),
                capacity: "ledger-input-consumed".to_string(),
                cardinality: "exactly-one".to_string(),
                correspondence: "none".to_string(),
            },
            "checked-runtime",
        );
        legacy_nodes.push(make_legacy_node(
            format!("legacy:{id}"),
            "input-disposition",
            format!(
                "Edition 2026 operation '{}' terminates linear ownership without a complete next-edition disposition",
                pattern.operation
            ),
            migration,
        ));
        dispositions.push(disposition);
    }
    for (ordinal, pattern) in body.create_set.iter().enumerate() {
        if successor_outputs.contains(pattern.binding.as_str()) {
            continue;
        }
        let output_role = if pattern.operation == "bounded-create" {
            format!("role:{entry_id}:output:{}", pattern.binding)
        } else {
            format!("role:{entry_id}:output:{}:output[{ordinal}]", pattern.binding)
        };
        let id = format!("disposition:{entry_id}:output:{}:output[{ordinal}]", pattern.binding);
        let declared_fields = type_fields(types, &pattern.ty);
        let provided = pattern.fields.iter().map(|(field, _)| field.as_str()).collect::<BTreeSet<_>>();
        let exhaustive = !declared_fields.is_empty() && declared_fields.iter().all(|field| provided.contains(field));
        dispositions.push(make_disposition(
            id,
            entry_id,
            None,
            Some(output_role),
            None,
            Some(OutputOrigin::Fresh { identity_policy: identity_policy_label(&pattern.identity) }),
            CellEnvelopeDisposition {
                completeness: if exhaustive && pattern.lock.is_some() { "exhaustive" } else { "legacy-partial" }.to_string(),
                data_fields: declared_fields
                    .into_iter()
                    .map(|field| FieldDisposition {
                        treatment: if provided.contains(field) { "set-from-expression" } else { "missing-in-legacy-source" }
                            .to_string(),
                        field: field.to_string(),
                    })
                    .collect(),
                logical_identity: format!("create:{}", identity_policy_label(&pattern.identity)),
                lock_script: if pattern.lock.is_some() { "set-and-check" } else { "legacy-unspecified" }.to_string(),
                type_script: "set-to-declared-resource-type".to_string(),
                capacity: if pattern.operation == "bounded-create" {
                    "at-least-declared-floor-checked-runtime"
                } else {
                    "builder-computed-and-chain-checked"
                }
                .to_string(),
                cardinality: if pattern.operation == "bounded-create" { "bounded-plan-cardinality" } else { "exactly-one" }
                    .to_string(),
                correspondence: if pattern.operation == "bounded-create" {
                    "canonical-plan-relative-group-output"
                } else {
                    "canonical-create-order"
                }
                .to_string(),
            },
            if pattern.operation == "bounded-create" { "checked-runtime" } else { "builder-evidence-required" },
        ));
    }
    for operation in &body.bounded_collection_ops {
        if operation.operation != "consume_each" {
            continue;
        }
        let input_role = format!("role:{entry_id}:input:{}", operation.collection_binding);
        let id = format!("disposition:{entry_id}:bounded-input:{}", operation.collection_binding);
        dispositions.push(make_disposition(
            id.clone(),
            entry_id,
            Some(input_role),
            None,
            Some(InputDisposition::LegacyConsumed {
                operation: "consume_each".to_string(),
                migration: "per-element-successor-pooled-or-retired-required".to_string(),
            }),
            None,
            CellEnvelopeDisposition {
                completeness: "legacy-ambiguous".to_string(),
                data_fields: type_fields(types, &operation.element_type)
                    .into_iter()
                    .map(|field| FieldDisposition { field: field.to_string(), treatment: "decoded-and-predicate-checked".to_string() })
                    .collect(),
                logical_identity: "legacy-unspecified-per-element".to_string(),
                lock_script: "no-successor-envelope".to_string(),
                type_script: "current-type-group".to_string(),
                capacity: "ledger-input-consumed".to_string(),
                cardinality: format!("0..={}", operation.max_elements),
                correspondence: "none".to_string(),
            },
            operation.runtime_contract.as_deref().map_or("runtime-helper-required", |_| "checked-runtime"),
        ));
        legacy_nodes.push(make_legacy_node(
            format!("legacy:{id}"),
            "bounded-input-disposition",
            format!(
                "Edition 2026 consume_each checks up to {} Type Script Group inputs but does not classify their business disposition",
                operation.max_elements
            ),
            "select a per-element Successor, Pooled, or Retired disposition",
        ));
    }
}

struct CheckedSuccessorPair {
    input_binding: String,
    output_binding: String,
    ty: String,
    input_index: usize,
    output_index: usize,
    lock_expression: Option<String>,
}

fn checked_successor_pairs(
    entry_id: &str,
    params: &[ir::IrParam],
    body: &ir::IrBody,
    proof_plan: &[crate::ProofPlanMetadata],
) -> Vec<CheckedSuccessorPair> {
    let mut pairs = Vec::new();
    let type_names = params
        .iter()
        .filter(|param| body.consume_set.iter().any(|pattern| pattern.binding == param.name))
        .map(|param| strip_semantic_reference(&render_type(&param.ty)).to_string())
        .collect::<BTreeSet<_>>();
    for ty in type_names {
        let inputs = body
            .consume_set
            .iter()
            .enumerate()
            .filter(|(_, pattern)| {
                params.iter().any(|param| param.name == pattern.binding && strip_semantic_reference(&render_type(&param.ty)) == ty)
            })
            .collect::<Vec<_>>();
        let outputs = body.create_set.iter().enumerate().filter(|(_, pattern)| pattern.ty == ty).collect::<Vec<_>>();
        let checked = proof_plan.iter().any(|record| {
            record.origin == entry_id
                && record.feature == format!("resource-conservation:{ty}")
                && record.evidence_tier == crate::proof_plan::EvidenceTier::CheckedRuntime
                && record.on_chain_checked
        });
        if checked && inputs.len() == 1 && outputs.len() == 1 {
            pairs.push(CheckedSuccessorPair {
                input_binding: inputs[0].1.binding.clone(),
                output_binding: outputs[0].1.binding.clone(),
                ty,
                input_index: inputs[0].0,
                output_index: outputs[0].0,
                lock_expression: outputs[0].1.lock.as_ref().map(render_ir_operand_semantic),
            });
        }
    }
    pairs
}

fn render_ir_operand_semantic(operand: &ir::IrOperand) -> String {
    match operand {
        ir::IrOperand::Var(variable) => variable.name.clone(),
        ir::IrOperand::Const(constant) => format!("{constant:?}"),
    }
}

fn make_disposition(
    id: String,
    entry_id: &str,
    input_role: Option<String>,
    output_role: Option<String>,
    input: Option<InputDisposition>,
    output: Option<OutputOrigin>,
    mut envelope: CellEnvelopeDisposition,
    enforcement: &str,
) -> CellDisposition {
    envelope.data_fields.sort_by(|left, right| left.field.cmp(&right.field));
    let semantic_node_id = canonical_hash(
        "cellscript-semantic-node-disposition-v1",
        &(id.as_str(), entry_id, input_role.as_deref(), output_role.as_deref(), &input, &output, &envelope, enforcement),
    )
    .expect("Cell disposition node is serializable");
    CellDisposition {
        semantic_node_id,
        id,
        entry_id: entry_id.to_string(),
        input_role,
        output_role,
        input,
        output,
        envelope,
        enforcement: enforcement.to_string(),
    }
}

fn make_legacy_node(id: String, kind: &str, meaning: String, migration: &str) -> LegacySemanticNode {
    let semantic_node_id = canonical_hash("cellscript-semantic-node-legacy-v1", &(id.as_str(), kind, meaning.as_str(), migration))
        .expect("legacy semantic node is serializable");
    LegacySemanticNode { semantic_node_id, id, kind: kind.to_string(), meaning, migration: migration.to_string() }
}

fn build_claims(
    metadata: &CompileMetadata,
    module: &ir::IrModule,
    entries: &[TypedSemanticEntry],
    condition_nodes: &BTreeMap<(String, u32), String>,
) -> Vec<SemanticClaim> {
    let plans = metadata
        .actions
        .iter()
        .flat_map(|entry| entry.proof_plan.iter().map(move |plan| (format!("action:{}", entry.name), plan)))
        .chain(metadata.locks.iter().flat_map(|entry| entry.proof_plan.iter().map(move |plan| (format!("lock:{}", entry.name), plan))))
        .chain(
            metadata
                .functions
                .iter()
                .flat_map(|entry| entry.proof_plan.iter().map(move |plan| (format!("helper:{}", entry.name), plan))),
        );
    let mut claims = plans
        .enumerate()
        .map(|(index, (entry_id, plan))| {
            let id = format!("claim:{entry_id}:{index:05}:{}", plan.name);
            let statement = format!("{}: {}", plan.feature, plan.detail);
            let enforcement = plan.evidence_tier.as_str().to_string();
            make_claim(
                id,
                entry_id,
                plan.category.clone(),
                statement,
                enforcement,
                plan.on_chain_checked,
                format!("proof-plan:{}", plan.name),
                None,
            )
        })
        .collect::<Vec<_>>();

    for item in &module.items {
        let (kind, name, body, audit_claims) = match item {
            ir::IrItem::Action(entry) => ("action", entry.name.as_str(), &entry.body, entry.audit_claims.as_slice()),
            ir::IrItem::Lock(entry) => ("lock", entry.name.as_str(), &entry.body, entry.audit_claims.as_slice()),
            ir::IrItem::PureFn(entry) => ("helper", entry.name.as_str(), &entry.body, &[] as &[ir::IrAuditClaim]),
            ir::IrItem::TypeDef(_) | ir::IrItem::Invariant(_) => continue,
        };
        let entry_id = format!("{kind}:{name}");
        let typed_entry = entries.iter().find(|entry| entry.id == entry_id).expect("IR entry has typed semantic entry");
        for (ordinal, claim) in body.enforced_claims.iter().enumerate() {
            let condition_block = u32::try_from(claim.condition_block.0).unwrap_or(u32::MAX);
            let success_block = u32::try_from(claim.success_block.0).unwrap_or(u32::MAX);
            let failure_block = u32::try_from(claim.failure_block.0).unwrap_or(u32::MAX);
            let condition_node_id = condition_nodes
                .get(&(entry_id.clone(), condition_block))
                .cloned()
                .expect("lowered require branch has canonical condition provenance");
            let failure_error_code = typed_entry
                .blocks
                .iter()
                .find(|block| block.id == failure_block)
                .and_then(|block| block.runtime_error.as_ref())
                .map(|error| error.code)
                .expect("lowered require failure block has a typed runtime error");
            let id = format!("claim:{entry_id}:enforced:{ordinal:05}");
            let evidence_reference = format!("typed-entry:{entry_id}:block:{condition_block}:branch-condition");
            claims.push(make_claim(
                id,
                entry_id.clone(),
                "entry-condition".to_string(),
                format!("require {}", claim.statement),
                "checked-runtime".to_string(),
                true,
                evidence_reference,
                Some(ClaimExecutionBinding { condition_block, condition_node_id, success_block, failure_block, failure_error_code }),
            ));
        }
        for audit in audit_claims {
            claims.push(make_claim(
                format!("claim:{entry_id}:audit:{}", audit.name),
                entry_id.clone(),
                "audit".to_string(),
                format!("expected external policy evidence for {}", audit.subject),
                "metadata-only".to_string(),
                false,
                format!("audit:{}", audit.evidence),
                None,
            ));
        }
    }
    claims
}

#[allow(clippy::too_many_arguments)]
fn make_claim(
    id: String,
    entry_id: String,
    category: String,
    statement: String,
    enforcement: String,
    on_chain_checked: bool,
    evidence_reference: String,
    execution: Option<ClaimExecutionBinding>,
) -> SemanticClaim {
    let semantic_node_id = canonical_hash(
        "cellscript-semantic-node-claim-v1",
        &(
            id.as_str(),
            entry_id.as_str(),
            category.as_str(),
            statement.as_str(),
            enforcement.as_str(),
            on_chain_checked,
            evidence_reference.as_str(),
            &execution,
        ),
    )
    .expect("semantic claim node is serializable");
    SemanticClaim { semantic_node_id, id, entry_id, category, statement, enforcement, on_chain_checked, evidence_reference, execution }
}

fn type_fields<'a>(types: &BTreeMap<&str, &'a TypedSemanticType>, ty: &str) -> Vec<&'a str> {
    types.get(ty).map_or_else(Vec::new, |layout| layout.fields.iter().map(|field| field.name.as_str()).collect())
}

fn strip_semantic_reference(ty: &str) -> &str {
    ty.strip_prefix("&mut ").or_else(|| ty.strip_prefix('&')).unwrap_or(ty)
}

fn bounded_cell_element(ty: &str) -> Option<&str> {
    ty.strip_prefix("BoundedCellSet<")
        .and_then(|value| value.strip_suffix('>'))
        .and_then(|value| value.rsplit_once(','))
        .map(|(element, _)| element.trim())
}

fn bounded_cell_maximum(ty: &str) -> Option<usize> {
    ty.strip_prefix("BoundedCellSet<")
        .and_then(|value| value.strip_suffix('>'))
        .and_then(|value| value.rsplit_once(','))
        .and_then(|(_, maximum)| maximum.trim().parse().ok())
}

#[derive(Clone)]
struct CallableSignature {
    params: Vec<String>,
    return_type: String,
    effect: String,
    contract: String,
}

fn callable_signatures(module: &ir::IrModule) -> BTreeMap<String, CallableSignature> {
    let mut signatures = BTreeMap::new();
    for item in &module.items {
        match item {
            ir::IrItem::Action(action) => {
                signatures.insert(
                    action.name.clone(),
                    CallableSignature {
                        params: action.params.iter().map(|param| render_type(&param.ty)).collect(),
                        return_type: action.return_type.as_ref().map(render_type).unwrap_or_else(|| "unit".to_string()),
                        effect: format!("{:?}", action.effect_class),
                        contract: "typed-local".to_string(),
                    },
                );
            }
            ir::IrItem::PureFn(function) => {
                signatures.insert(
                    function.name.clone(),
                    CallableSignature {
                        params: function.params.iter().map(|param| render_type(&param.ty)).collect(),
                        return_type: function.return_type.as_ref().map(render_type).unwrap_or_else(|| "unit".to_string()),
                        effect: format!("{:?}", function.effect_class),
                        contract: "typed-local".to_string(),
                    },
                );
            }
            ir::IrItem::Lock(lock) => {
                signatures.insert(
                    lock.name.clone(),
                    CallableSignature {
                        params: lock.params.iter().map(|param| render_type(&param.ty)).collect(),
                        return_type: "bool".to_string(),
                        effect: "lock-predicate".to_string(),
                        contract: "typed-local".to_string(),
                    },
                );
            }
            ir::IrItem::TypeDef(_) | ir::IrItem::Invariant(_) => {}
        }
    }
    signatures
}

fn build_entry(
    kind: &str,
    name: &str,
    params: &[ir::IrParam],
    return_type: Option<&IrType>,
    effect: &str,
    body: &ir::IrBody,
    signatures: &BTreeMap<String, CallableSignature>,
    obligations: Vec<String>,
) -> TypedSemanticEntry {
    let mut locals = LocalTable::default();
    for param in params {
        insert_var(&mut locals, &param.binding);
    }
    let mut blocks = body
        .blocks
        .iter()
        .map(|block| {
            let mut operations =
                block.instructions.iter().map(|instruction| operation(instruction, &mut locals, signatures)).collect::<Vec<_>>();
            if let Some(error) = block.runtime_error {
                operations.push(TypedSemanticOperation {
                    index: 0,
                    opcode: "verifier-failure".to_string(),
                    destinations: Vec::new(),
                    operands: vec![typed_operand(&ir::IrOperand::Const(ir::IrConst::U64(error.code())), &mut locals)],
                    detail: TypedSemanticOperationDetail::None,
                    call: None,
                });
            } else if let IrTerminator::Return(operand) = &block.terminator {
                operations.push(TypedSemanticOperation {
                    index: 0,
                    opcode: "return".to_string(),
                    destinations: Vec::new(),
                    operands: operand.iter().map(|operand| typed_operand(operand, &mut locals)).collect(),
                    detail: TypedSemanticOperationDetail::None,
                    call: None,
                });
            }
            if let IrTerminator::Branch { cond, .. } = &block.terminator {
                operations.push(TypedSemanticOperation {
                    index: 0,
                    opcode: "branch-condition".to_string(),
                    destinations: Vec::new(),
                    operands: vec![typed_operand(cond, &mut locals)],
                    detail: TypedSemanticOperationDetail::None,
                    call: None,
                });
            }
            for (index, operation) in operations.iter_mut().enumerate() {
                operation.index = u32::try_from(index).unwrap_or(u32::MAX);
            }
            let (terminator, successors) = match &block.terminator {
                _ if block.runtime_error.is_some() => ("verifier-failure", Vec::new()),
                IrTerminator::Return(_) => ("return", Vec::new()),
                IrTerminator::Jump(target) => ("jump", vec![u32::try_from(target.0).unwrap_or(u32::MAX)]),
                IrTerminator::Branch { then_block, else_block, .. } => {
                    ("branch", vec![u32::try_from(then_block.0).unwrap_or(u32::MAX), u32::try_from(else_block.0).unwrap_or(u32::MAX)])
                }
            };
            TypedSemanticBlock {
                id: u32::try_from(block.id.0).unwrap_or(u32::MAX),
                operations,
                successors,
                terminator: terminator.to_string(),
                runtime_error: block
                    .runtime_error
                    .map(|error| TypedSemanticRuntimeError { code: error.code(), name: error.name().to_string() }),
            }
        })
        .collect::<Vec<_>>();
    blocks.sort_by_key(|block| block.id);
    let param_types = params.iter().map(|param| (param.name.as_str(), render_type(&param.ty))).collect::<BTreeMap<_, _>>();
    let mut ownership = Vec::new();
    for pattern in &body.consume_set {
        let operation = pattern.operation.as_str();
        let final_state = match operation {
            "destroy" => "destroyed",
            "transfer" => "transferred",
            "replace_unique" => "replaced",
            "claim" => "claimed",
            "settle" => "settled",
            _ => "consumed",
        };
        ownership.push(TypedSemanticOwnership {
            binding: pattern.binding.clone(),
            ty: param_types.get(pattern.binding.as_str()).cloned().unwrap_or_else(|| "cell".to_string()),
            operation: operation.to_string(),
            initial_state: "available".to_string(),
            final_state: final_state.to_string(),
        });
    }
    for pattern in &body.read_refs {
        ownership.push(TypedSemanticOwnership {
            binding: pattern.binding.clone(),
            ty: param_types.get(pattern.binding.as_str()).cloned().unwrap_or_else(|| "cell".to_string()),
            operation: "read_ref".to_string(),
            initial_state: "available".to_string(),
            final_state: "available".to_string(),
        });
    }
    for pattern in &body.mutate_set {
        ownership.push(TypedSemanticOwnership {
            binding: pattern.binding.clone(),
            ty: pattern.ty.clone(),
            operation: "mutate".to_string(),
            initial_state: "available".to_string(),
            final_state: "available".to_string(),
        });
    }
    for pattern in &body.create_set {
        ownership.push(TypedSemanticOwnership {
            binding: pattern.binding.clone(),
            ty: pattern.ty.clone(),
            operation: pattern.operation.clone(),
            initial_state: "unbound".to_string(),
            final_state: "available".to_string(),
        });
    }
    let mut typed_params = params
        .iter()
        .enumerate()
        .map(|(index, param)| TypedSemanticParam {
            index: u32::try_from(index).unwrap_or(u32::MAX),
            binding_id: locals.id_for(&param.binding),
            name: param.name.clone(),
            ty: render_type(&param.ty),
            source: format!("{:?}", param.source).to_ascii_lowercase(),
            mutable: param.is_mut,
            reference: param.is_ref || param.is_read_ref,
        })
        .collect::<Vec<_>>();
    let mut typed_locals = locals.into_values();
    refine_collection_local_types(&mut typed_locals, &mut typed_params, &mut blocks);
    let cell_bindings = body
        .cell_bindings
        .iter()
        .map(|binding| TypedSemanticCellBinding {
            binding: binding.binding.clone(),
            role: match binding.role {
                ir::IrCellBindingRole::Input => CellBindingRole::Input,
                ir::IrCellBindingRole::Output => CellBindingRole::Output,
                ir::IrCellBindingRole::ReadOnly => CellBindingRole::ReadOnly,
            },
            local_id: binding
                .local_id
                .and_then(|source_id| typed_locals.iter().find(|local| local.source_id == source_id as u64).map(|local| local.id)),
            ty: binding.ty.clone(),
            source: match binding.source {
                ir::IrCellSource::Input => CellBindingSource::Input,
                ir::IrCellSource::Output => CellBindingSource::Output,
                ir::IrCellSource::GroupInput => CellBindingSource::GroupInput,
                ir::IrCellSource::GroupOutput => CellBindingSource::GroupOutput,
                ir::IrCellSource::CellDep => CellBindingSource::CellDep,
            },
            ordinal: u32::try_from(binding.ordinal).unwrap_or(u32::MAX),
            membership: match binding.membership {
                ir::IrCellMembership::Unproven => CellBindingMembership::Unproven,
                ir::IrCellMembership::CurrentTypeGroup => CellBindingMembership::CurrentTypeGroup,
                ir::IrCellMembership::CurrentLockGroup => CellBindingMembership::CurrentLockGroup,
            },
        })
        .collect();
    TypedSemanticEntry {
        id: format!("{kind}:{name}"),
        kind: kind.to_string(),
        name: name.to_string(),
        params: typed_params,
        cell_bindings,
        return_type: return_type.map(render_type).unwrap_or_else(|| "unit".to_string()),
        effect: effect.to_string(),
        entry_block: body.blocks.first().and_then(|block| u32::try_from(block.id.0).ok()).unwrap_or(0),
        locals: typed_locals,
        blocks,
        borrows: body
            .borrow_regions
            .iter()
            .map(|borrow| TypedSemanticBorrow {
                root: borrow.root.clone(),
                path: borrow.path.clone(),
                binding: borrow.binding.clone(),
                root_type: borrow.root_type.clone(),
                view_type: if borrow.view_type.starts_with('&') { borrow.view_type.clone() } else { format!("&{}", borrow.view_type) },
                start_block: u32::try_from(borrow.start_block.0).unwrap_or(u32::MAX),
                start_operation: u32::try_from(borrow.start_instruction).unwrap_or(u32::MAX),
                end_block: borrow.end_block.and_then(|block| u32::try_from(block.0).ok()),
                end_operation: borrow.end_instruction.and_then(|instruction| u32::try_from(instruction).ok()),
                escapes: false,
            })
            .collect(),
        ownership,
        obligations,
    }
}

fn refine_collection_local_types(
    locals: &mut Vec<TypedSemanticLocal>,
    params: &mut [TypedSemanticParam],
    blocks: &mut [TypedSemanticBlock],
) {
    let mut candidates = BTreeMap::<u64, BTreeSet<String>>::new();
    for local in locals.iter().filter(|local| local.ty.starts_with("Vec<") && local.ty.ends_with('>')) {
        candidates.entry(local.source_id).or_default().insert(local.ty.clone());
    }
    let refinements = candidates
        .into_iter()
        .filter_map(|(source_id, types)| (types.len() == 1).then(|| (source_id, types.into_iter().next().unwrap())))
        .collect::<BTreeMap<_, _>>();
    for local in locals.iter_mut() {
        if local.ty == "Vec"
            && let Some(refined) = refinements.get(&local.source_id)
        {
            local.ty.clone_from(refined);
        }
    }
    let mut canonical_ids = BTreeMap::<(u64, String, String), u32>::new();
    let mut remapped_ids = BTreeMap::<u32, u32>::new();
    for local in locals.iter() {
        let key = (local.source_id, local.name.clone(), local.ty.clone());
        let canonical = *canonical_ids.entry(key).or_insert(local.id);
        remapped_ids.insert(local.id, canonical);
    }
    locals.retain(|local| remapped_ids.get(&local.id) == Some(&local.id));
    for param in params {
        param.binding_id = remapped_ids.get(&param.binding_id).copied().unwrap_or(param.binding_id);
    }
    let local_types = locals.iter().map(|local| (local.id, local.ty.clone())).collect::<BTreeMap<_, _>>();
    for operation in blocks.iter_mut().flat_map(|block| &mut block.operations) {
        for destination in &mut operation.destinations {
            *destination = remapped_ids.get(destination).copied().unwrap_or(*destination);
        }
        for operand in &mut operation.operands {
            if let Some(id) = operand.local {
                operand.local = Some(remapped_ids.get(&id).copied().unwrap_or(id));
            }
            if let Some(local) = operand.local.and_then(|id| local_types.get(&id)) {
                operand.ty.clone_from(local);
            }
        }
    }
}

fn operation(
    instruction: &IrInstruction,
    locals: &mut LocalTable,
    signatures: &BTreeMap<String, CallableSignature>,
) -> TypedSemanticOperation {
    let (opcode, destinations, operands, detail, call) = match instruction {
        IrInstruction::LoadConst { dest, value } => {
            let value = typed_constant(value);
            ("load-const", vec![dest], vec![], TypedSemanticOperationDetail::Constant { value }, None)
        }
        IrInstruction::LoadVar { dest, name } => {
            ("load-var", vec![dest], vec![], TypedSemanticOperationDetail::Binding { name: name.clone() }, None)
        }
        IrInstruction::StoreVar { name, src } => {
            ("store-var", vec![], vec![src], TypedSemanticOperationDetail::Binding { name: name.clone() }, None)
        }
        IrInstruction::Binary { dest, op, left, right } => (
            "binary",
            vec![dest],
            vec![left, right],
            TypedSemanticOperationDetail::BinaryOperator { operator: binary_operator_label(*op).to_string() },
            None,
        ),
        IrInstruction::Unary { dest, op, operand } => (
            "unary",
            vec![dest],
            vec![operand],
            TypedSemanticOperationDetail::UnaryOperator { operator: unary_operator_label(*op).to_string() },
            None,
        ),
        IrInstruction::FieldAccess { dest, obj, field } => {
            ("field-access", vec![dest], vec![obj], TypedSemanticOperationDetail::Field { name: field.clone() }, None)
        }
        IrInstruction::Index { dest, arr, idx } => ("index", vec![dest], vec![arr, idx], TypedSemanticOperationDetail::None, None),
        IrInstruction::Length { dest, operand } => ("length", vec![dest], vec![operand], TypedSemanticOperationDetail::None, None),
        IrInstruction::TypeHash { dest, operand } => {
            ("type-hash", vec![dest], vec![operand], TypedSemanticOperationDetail::None, None)
        }
        IrInstruction::CollectionNew { dest, ty, capacity } => (
            "collection-new",
            vec![dest],
            capacity.iter().collect(),
            TypedSemanticOperationDetail::Collection { declared_type: ty.clone() },
            None,
        ),
        IrInstruction::CollectionCapacity { dest, collection } => {
            ("collection-capacity", vec![dest], vec![collection], TypedSemanticOperationDetail::None, None)
        }
        IrInstruction::CollectionPush { collection, value } => {
            ("collection-push", vec![], vec![collection, value], TypedSemanticOperationDetail::None, None)
        }
        IrInstruction::CollectionExtend { collection, slice } => {
            ("collection-extend", vec![], vec![collection, slice], TypedSemanticOperationDetail::None, None)
        }
        IrInstruction::CollectionClear { collection } => {
            ("collection-clear", vec![], vec![collection], TypedSemanticOperationDetail::None, None)
        }
        IrInstruction::CollectionContains { dest, collection, value } => {
            ("collection-contains", vec![dest], vec![collection, value], TypedSemanticOperationDetail::None, None)
        }
        IrInstruction::CollectionRemove { dest, collection, index } => {
            ("collection-remove", vec![dest], vec![collection, index], TypedSemanticOperationDetail::None, None)
        }
        IrInstruction::CollectionInsert { collection, index, value } => {
            ("collection-insert", vec![], vec![collection, index, value], TypedSemanticOperationDetail::None, None)
        }
        IrInstruction::CollectionSet { collection, index, value } => {
            ("collection-set", vec![], vec![collection, index, value], TypedSemanticOperationDetail::None, None)
        }
        IrInstruction::CollectionPop { dest, collection } => {
            ("collection-pop", vec![dest], vec![collection], TypedSemanticOperationDetail::None, None)
        }
        IrInstruction::CollectionReverse { collection } => {
            ("collection-reverse", vec![], vec![collection], TypedSemanticOperationDetail::None, None)
        }
        IrInstruction::CollectionTruncate { collection, len } => {
            ("collection-truncate", vec![], vec![collection, len], TypedSemanticOperationDetail::None, None)
        }
        IrInstruction::CollectionSwap { collection, left, right } => {
            ("collection-swap", vec![], vec![collection, left, right], TypedSemanticOperationDetail::None, None)
        }
        IrInstruction::BoundedCellLoad { dest, found, index, element_type, max_elements, .. } => (
            "bounded-cell-load",
            vec![dest, found],
            vec![index],
            TypedSemanticOperationDetail::Collection { declared_type: format!("BoundedCellSet<{}, {}>", element_type, max_elements) },
            None,
        ),
        IrInstruction::BoundedPlanLoad { dest, found, plan, index, element_type, max_elements, .. } => (
            "bounded-plan-load",
            vec![dest, found],
            vec![plan, index],
            TypedSemanticOperationDetail::Collection { declared_type: format!("BoundedList<{}, {}>", element_type, max_elements) },
            None,
        ),
        IrInstruction::BoundedOutputVerify { index, pattern, .. } => {
            let mut operands = vec![index];
            operands.extend(create_pattern_operands(pattern));
            (
                "bounded-output-verify",
                vec![],
                operands,
                TypedSemanticOperationDetail::Create { pattern: typed_create_pattern(pattern) },
                None,
            )
        }
        IrInstruction::BoundedOutputEnd { index } => {
            ("bounded-output-end", vec![], vec![index], TypedSemanticOperationDetail::None, None)
        }
        IrInstruction::Call { dest, func, args } => {
            let signature = signatures.get(func).cloned().unwrap_or_else(|| CallableSignature {
                params: args.iter().map(operand_type).collect(),
                return_type: dest.as_ref().map(|dest| render_type(&dest.ty)).unwrap_or_else(|| "unit".to_string()),
                effect: crate::ir::IrDeferredRuntimeFeature::from_helper(func)
                    .map_or_else(|| "runtime-contract".to_string(), |deferred| deferred.effect()),
                contract: "versioned-runtime-helper".to_string(),
            });
            (
                "call",
                dest.iter().collect(),
                args.iter().collect(),
                TypedSemanticOperationDetail::None,
                Some(TypedSemanticCall {
                    target: func.clone(),
                    params: signature.params,
                    return_type: signature.return_type,
                    effect: signature.effect,
                    contract: signature.contract,
                }),
            )
        }
        IrInstruction::ReadRef { dest, ty } => {
            ("read-ref", vec![dest], vec![], TypedSemanticOperationDetail::Reference { declared_type: ty.clone() }, None)
        }
        IrInstruction::Move { dest, src } => ("move", vec![dest], vec![src], TypedSemanticOperationDetail::None, None),
        IrInstruction::Tuple { dest, fields } => {
            ("tuple", vec![dest], fields.iter().collect(), TypedSemanticOperationDetail::None, None)
        }
        IrInstruction::EnumConstruct { dest, enum_name, variant, fields } => (
            "enum-construct",
            vec![dest],
            fields.iter().collect(),
            TypedSemanticOperationDetail::EnumConstruct { enum_name: enum_name.clone(), variant: variant.clone() },
            None,
        ),
        IrInstruction::EnumTag { dest, operand, enum_name } => {
            ("enum-tag", vec![dest], vec![operand], TypedSemanticOperationDetail::EnumTag { enum_name: enum_name.clone() }, None)
        }
        IrInstruction::EnumPayload { dest, operand, enum_name, variant, field_index } => (
            "enum-payload",
            vec![dest],
            vec![operand],
            TypedSemanticOperationDetail::EnumPayload {
                enum_name: enum_name.clone(),
                variant: variant.clone(),
                field_index: u32::try_from(*field_index).unwrap_or(u32::MAX),
            },
            None,
        ),
        IrInstruction::Consume { operand } => ("consume", vec![], vec![operand], TypedSemanticOperationDetail::None, None),
        IrInstruction::Create { dest, pattern } => (
            "create",
            vec![dest],
            create_pattern_operands(pattern),
            TypedSemanticOperationDetail::Create { pattern: typed_create_pattern(pattern) },
            None,
        ),
        IrInstruction::Transfer { dest, operand, to } => {
            ("transfer", vec![dest], vec![operand, to], TypedSemanticOperationDetail::None, None)
        }
        IrInstruction::Destroy { operand, policy } => (
            "destroy",
            vec![],
            vec![operand],
            TypedSemanticOperationDetail::Destroy { policy: destruction_policy_label(policy) },
            None,
        ),
        IrInstruction::Claim { dest, receipt } => ("claim", vec![dest], vec![receipt], TypedSemanticOperationDetail::None, None),
        IrInstruction::Settle { dest, operand } => ("settle", vec![dest], vec![operand], TypedSemanticOperationDetail::None, None),
        IrInstruction::CreateUnique { dest, pattern, identity } => (
            "create-unique",
            vec![dest],
            create_pattern_operands(pattern),
            TypedSemanticOperationDetail::CreateUnique {
                pattern: typed_create_pattern(pattern),
                identity: identity_policy_label(identity),
            },
            None,
        ),
        IrInstruction::ReplaceUnique { dest, operand, pattern, identity } => {
            let mut operands = vec![operand];
            operands.extend(create_pattern_operands(pattern));
            (
                "replace-unique",
                vec![dest],
                operands,
                TypedSemanticOperationDetail::ReplaceUnique {
                    pattern: typed_create_pattern(pattern),
                    identity: identity_policy_label(identity),
                },
                None,
            )
        }
        IrInstruction::CellMetadataEquality { left, right, field } => (
            "cell-metadata-equality",
            vec![],
            vec![left, right],
            TypedSemanticOperationDetail::CellMetadata {
                field: match field {
                    ir::CellMetadataField::LockHash => "lock-hash",
                    ir::CellMetadataField::Capacity => "capacity",
                }
                .to_string(),
            },
            None,
        ),
    };
    for destination in &destinations {
        insert_var(locals, destination);
    }
    TypedSemanticOperation {
        index: 0,
        opcode: opcode.to_string(),
        destinations: destinations.iter().map(|var| locals.id_for(var)).collect(),
        operands: operands.into_iter().map(|operand| typed_operand(operand, locals)).collect(),
        detail,
        call,
    }
}

fn binary_operator_label(operator: crate::ast::BinaryOp) -> &'static str {
    match operator {
        crate::ast::BinaryOp::Add => "add",
        crate::ast::BinaryOp::Sub => "sub",
        crate::ast::BinaryOp::Mul => "mul",
        crate::ast::BinaryOp::Div => "div",
        crate::ast::BinaryOp::Mod => "mod",
        crate::ast::BinaryOp::Eq => "eq",
        crate::ast::BinaryOp::Ne => "ne",
        crate::ast::BinaryOp::Lt => "lt",
        crate::ast::BinaryOp::Le => "le",
        crate::ast::BinaryOp::Gt => "gt",
        crate::ast::BinaryOp::Ge => "ge",
        crate::ast::BinaryOp::And => "and",
        crate::ast::BinaryOp::Or => "or",
        crate::ast::BinaryOp::BitAnd => "bit-and",
        crate::ast::BinaryOp::BitOr => "bit-or",
        crate::ast::BinaryOp::BitXor => "bit-xor",
        crate::ast::BinaryOp::Shl => "shl",
        crate::ast::BinaryOp::Shr => "shr",
    }
}

fn unary_operator_label(operator: crate::ast::UnaryOp) -> &'static str {
    match operator {
        crate::ast::UnaryOp::Neg => "neg",
        crate::ast::UnaryOp::Not => "not",
        crate::ast::UnaryOp::Ref => "ref",
        crate::ast::UnaryOp::Deref => "deref",
    }
}

fn create_pattern_operands(pattern: &ir::CreatePattern) -> Vec<&IrOperand> {
    pattern.fields.iter().map(|(_, operand)| operand).chain(pattern.lock.iter()).collect()
}

fn typed_create_pattern(pattern: &ir::CreatePattern) -> TypedSemanticCreatePattern {
    TypedSemanticCreatePattern {
        operation: pattern.operation.clone(),
        ty: pattern.ty.clone(),
        binding: pattern.binding.clone(),
        field_names: pattern.fields.iter().map(|(name, _)| name.clone()).collect(),
        has_lock: pattern.lock.is_some(),
        identity: identity_policy_label(&pattern.identity),
    }
}

fn identity_policy_label(identity: &ir::IrIdentityPolicy) -> String {
    match identity {
        ir::IrIdentityPolicy::None => "none".to_string(),
        ir::IrIdentityPolicy::CkbTypeId => "ckb-type-id".to_string(),
        ir::IrIdentityPolicy::Field(path) => format!("field:{path}"),
        ir::IrIdentityPolicy::ScriptArgs => "script-args".to_string(),
        ir::IrIdentityPolicy::SingletonType => "singleton-type".to_string(),
    }
}

fn destruction_policy_label(policy: &ir::IrDestructionPolicy) -> String {
    match policy {
        ir::IrDestructionPolicy::Default => "default".to_string(),
        ir::IrDestructionPolicy::SingletonType => "singleton-type".to_string(),
        ir::IrDestructionPolicy::Unique { identity } => format!("unique:{identity}"),
        ir::IrDestructionPolicy::Instance { identity_field } => format!("instance:{identity_field}"),
        ir::IrDestructionPolicy::BurnAmount { field } => format!("burn-amount:{field}"),
    }
}

fn typed_operand(operand: &IrOperand, locals: &mut LocalTable) -> TypedSemanticOperand {
    match operand {
        IrOperand::Var(var) => TypedSemanticOperand { local: Some(locals.id_for(var)), ty: render_type(&var.ty), constant: None },
        IrOperand::Const(value) => {
            TypedSemanticOperand { local: None, ty: render_type(&const_type(value)), constant: Some(typed_constant(value)) }
        }
    }
}

fn typed_constant(value: &ir::IrConst) -> TypedSemanticConstant {
    match value {
        ir::IrConst::Unit => TypedSemanticConstant::Unit,
        ir::IrConst::U8(value) => TypedSemanticConstant::U8(value.to_string()),
        ir::IrConst::U16(value) => TypedSemanticConstant::U16(value.to_string()),
        ir::IrConst::U32(value) => TypedSemanticConstant::U32(value.to_string()),
        ir::IrConst::U64(value) => TypedSemanticConstant::U64(value.to_string()),
        ir::IrConst::U128(value) => TypedSemanticConstant::U128(value.to_string()),
        ir::IrConst::Bool(value) => TypedSemanticConstant::Bool(*value),
        ir::IrConst::Address(value) => TypedSemanticConstant::Address(hex::encode(value)),
        ir::IrConst::Hash(value) => TypedSemanticConstant::Hash(hex::encode(value)),
        ir::IrConst::Array(values) => TypedSemanticConstant::Array(values.iter().map(typed_constant).collect()),
    }
}

fn operand_type(operand: &IrOperand) -> String {
    match operand {
        IrOperand::Var(var) => render_type(&var.ty),
        IrOperand::Const(value) => render_type(&const_type(value)),
    }
}

fn const_type(value: &ir::IrConst) -> IrType {
    match value {
        ir::IrConst::Unit => IrType::Unit,
        ir::IrConst::U8(_) => IrType::U8,
        ir::IrConst::U16(_) => IrType::U16,
        ir::IrConst::U32(_) => IrType::U32,
        ir::IrConst::U64(_) => IrType::U64,
        ir::IrConst::U128(_) => IrType::U128,
        ir::IrConst::Bool(_) => IrType::Bool,
        ir::IrConst::Address(_) => IrType::Address,
        ir::IrConst::Hash(_) => IrType::Hash,
        ir::IrConst::Array(items) => IrType::Array(Box::new(items.first().map(const_type).unwrap_or(IrType::Unit)), items.len()),
    }
}

#[derive(Default)]
struct LocalTable {
    values: BTreeMap<u32, TypedSemanticLocal>,
    identities: BTreeMap<(usize, String, String), u32>,
    next_synthetic: u32,
}

impl LocalTable {
    fn id_for(&mut self, var: &IrVar) -> u32 {
        let ty = render_type(&var.ty);
        let identity = (var.id, var.name.clone(), ty.clone());
        if let Some(id) = self.identities.get(&identity) {
            return *id;
        }
        let preferred = u32::try_from(var.id).unwrap_or(u32::MAX);
        let id = if self.values.contains_key(&preferred) { self.next_available_synthetic() } else { preferred };
        self.values
            .insert(id, TypedSemanticLocal { id, source_id: u64::try_from(var.id).unwrap_or(u64::MAX), name: var.name.clone(), ty });
        self.identities.insert(identity, id);
        id
    }

    fn next_available_synthetic(&mut self) -> u32 {
        loop {
            let candidate = 0x8000_0000_u32.saturating_add(self.next_synthetic);
            self.next_synthetic = self.next_synthetic.saturating_add(1);
            if !self.values.contains_key(&candidate) {
                return candidate;
            }
        }
    }

    fn into_values(self) -> Vec<TypedSemanticLocal> {
        self.values.into_values().collect()
    }
}

fn insert_var(locals: &mut LocalTable, var: &IrVar) {
    locals.id_for(var);
}

pub(crate) fn render_type(ty: &IrType) -> String {
    match ty {
        IrType::U8 => "u8".to_string(),
        IrType::U16 => "u16".to_string(),
        IrType::U32 => "u32".to_string(),
        IrType::I32 => "i32".to_string(),
        IrType::U64 => "u64".to_string(),
        IrType::U128 => "u128".to_string(),
        IrType::Bool => "bool".to_string(),
        IrType::Unit => "unit".to_string(),
        IrType::Address => "address".to_string(),
        IrType::Hash => "hash".to_string(),
        IrType::Array(inner, size) => format!("[{}; {}]", render_type(inner), size),
        IrType::Tuple(items) => format!("({})", items.iter().map(render_type).collect::<Vec<_>>().join(", ")),
        IrType::Named(name) => name.clone(),
        IrType::Ref(inner) => format!("&{}", render_type(inner)),
        IrType::MutRef(inner) => format!("&mut {}", render_type(inner)),
    }
}

fn proof_ids(metadata: &CompileMetadata, kind: &str, name: &str) -> Vec<String> {
    let count = match kind {
        "action" => metadata.actions.iter().find(|item| item.name == name).map(|item| item.proof_plan.len()),
        "lock" => metadata.locks.iter().find(|item| item.name == name).map(|item| item.proof_plan.len()),
        "helper" => metadata.functions.iter().find(|item| item.name == name).map(|item| item.proof_plan.len()),
        _ => None,
    }
    .unwrap_or(0);
    (0..count).map(|index| format!("proof:{kind}:{name}:{index:05}")).collect()
}
