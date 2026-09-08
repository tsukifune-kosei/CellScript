//! Parser-free checks for the bounded, single-resource policy dispatch record.
//!
//! These checks bind the selector, exports, fixed Cell roles and common-check
//! declarations to the typed record. The bundle checker separately decodes the
//! bounded policy wrapper and adapters to bind those records to machine dispatch.

use crate::schema::*;
use crate::{canonical_hash, CheckerError, CheckerRejectionCode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const POLICY_DISPATCH_SCHEMA: &str = "cellscript-policy-dispatch-v1";
pub const POLICY_DISPATCH_VERSION: u32 = 1;
pub const POLICY_PAYLOAD_ABI: &str = "cellscript-policy-witness-v1";
pub const POLICY_PLACEMENT_ABI: &str = "cellscript-policy-witnessargs-input-type-v1";
pub const POLICY_WITNESS_SOURCE: &str = "group-input[0]-or-output[0]-if-no-inputs";
pub const POLICY_SELECTOR_FIELD: &str = "input_type.records[type,current-script-hash].tag";

const MAX_COMMON_CALL_DEPTH: usize = 256;
const MAX_COMMON_CALLEE_BLOCKS: usize = 262_144;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyWitnessContract {
    pub schema: String,
    pub version: u32,
    pub artifact_name: String,
    pub resource: String,
    pub resource_layout_hash: String,
    pub selector_node_id: String,
    pub variants: Vec<PolicyWitnessVariant>,
    /// Evaluation order is significant; this list must not be sorted.
    pub common_checks: Vec<String>,
    pub max_records: u32,
    pub max_witness_bytes: u32,
    pub unknown_selector: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyWitnessVariant {
    /// Numeric ordering is canonical. All u32 tags, including zero, are valid.
    pub tag: u32,
    pub entry_id: String,
    pub payload_schema_hash: String,
    pub input_count: u32,
    pub output_count: u32,
}

fn invalid(message: impl Into<String>) -> CheckerError {
    CheckerError::new(CheckerRejectionCode::V2419TypedSemanticsInvalid, message)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 256 && !name.chars().any(|character| character.is_control() || character.is_whitespace())
}

/// Check the bounded policy declaration, fixed-Cell/source projections, and
/// builder-visible parameter encodings without requiring an ELF or source map.
///
/// This validates policy metadata consistency, not the whole typed program or
/// executable semantics. Success does not produce machine evidence, establish
/// dispatch/common-check dominance, or prove transaction acceptance. Policy
/// metadata and typed policy dispatch must either both be present or both be
/// absent. Outer JSON/hash agreement alone does not establish these relations.
pub fn validate_policy_metadata(metadata: &serde_json::Value, typed: &TypedSemanticRecord) -> Result<(), CheckerError> {
    let actual = metadata.get("runtime").and_then(|runtime| runtime.get("policy_artifact"));
    let EntryDispatchContract::PolicyWitnessV1(contract) = &typed.foundation.entry_contract.dispatch else {
        return if actual.is_none() {
            Ok(())
        } else {
            Err(CheckerError::new(
                CheckerRejectionCode::V2410MetadataBindingMismatch,
                "compile metadata declares a policy artifact without policy dispatch",
            ))
        };
    };
    validate_policy_contract(contract, typed)?;
    let expected = policy_metadata_projection(contract, typed)?;
    if actual != Some(&expected) {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2410MetadataBindingMismatch,
            "compile metadata runtime.policy_artifact does not exactly match the checked policy declaration, ABI and limits",
        ));
    }
    validate_builder_parameters(metadata, contract, typed)?;
    Ok(())
}

fn metadata_error(message: impl Into<String>) -> CheckerError {
    CheckerError::new(CheckerRejectionCode::V2410MetadataBindingMismatch, message)
}

fn validate_builder_parameters(
    metadata: &serde_json::Value,
    contract: &PolicyWitnessContract,
    typed: &TypedSemanticRecord,
) -> Result<(), CheckerError> {
    let actions = metadata
        .get("actions")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| metadata_error("policy builder metadata has no action array"))?;
    for variant in &contract.variants {
        let entry = action_entry(typed, &variant.entry_id)?;
        let mut candidates =
            actions.iter().filter(|action| action.get("name").and_then(serde_json::Value::as_str) == Some(&entry.name));
        let action = candidates.next().ok_or_else(|| metadata_error(format!("policy builder action '{}' is missing", entry.name)))?;
        if candidates.next().is_some() {
            return Err(metadata_error(format!("policy builder action '{}' is ambiguous", entry.name)));
        }
        let params = action
            .get("params")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| metadata_error(format!("policy builder action '{}' has no parameter array", entry.name)))?;
        if params.len() != entry.params.len() {
            return Err(metadata_error(format!("policy builder action '{}' parameter count differs from typed IR", entry.name)));
        }
        for (actual, param) in params.iter().zip(&entry.params) {
            let actual_type = actual
                .get("ty")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| metadata_error(format!("policy builder parameter '{}::{}' has no type", entry.name, param.name)))?;
            if policy_abi_type(actual_type, 0)? != policy_abi_type(&param.ty, 0)? {
                return Err(metadata_error(format!(
                    "policy builder parameter '{}::{}' changes its typed ABI type",
                    entry.name, param.name
                )));
            }
            let mut expected = builder_parameter_projection(param, entry, typed)?;
            // Public metadata uses Address/Hash/() while the typed record uses
            // address/hash/unit. The independently parsed type must agree;
            // spelling normalization must not alter any encoding flags.
            expected["ty"] = actual_type.into();
            if actual != &expected {
                return Err(metadata_error(format!(
                    "policy builder parameter '{}::{}' source, order, reference or encoding flags differ from typed IR",
                    entry.name, param.name
                )));
            }
        }
    }
    Ok(())
}

pub(crate) fn builder_parameter_projection(
    param: &TypedSemanticParam,
    entry: &TypedSemanticEntry,
    typed: &TypedSemanticRecord,
) -> Result<serde_json::Value, CheckerError> {
    let shape = policy_abi_type(&param.ty, 0)?;
    let schema =
        shape.named().and_then(|name| typed.types.iter().find(|schema| crate::checker::canonical_abi_type(&schema.name) == name));
    let physical = entry.cell_bindings.iter().find(|binding| binding.local_id == Some(param.binding_id));
    let explicit_read = param.reference && physical.is_some_and(|binding| binding.source == CellBindingSource::CellDep);
    let source = if explicit_read {
        "read"
    } else {
        match param.source.as_str() {
            "default" => "default",
            "input" => "input",
            "output" => "output",
            "protected" => "protected",
            "witness" => "witness",
            "lockargs" => "lock_args",
            _ => return Err(metadata_error(format!("policy parameter '{}' has an unknown typed source", param.name))),
        }
    };
    let reference = param.reference && !explicit_read;
    let enum_fixed = schema
        .filter(|schema| schema.kind == "enum" && schema.variants.iter().any(|variant| !variant.fields.is_empty()))
        .and_then(|schema| schema.encoded_size)
        .map(u64::from);
    let schema_pointer = shape.named().is_some() && enum_fixed.is_none();
    let fixed_byte_len = enum_fixed.or_else(|| shape.fixed_byte_width().filter(|width| *width > 8)).or_else(|| {
        matches!(shape, PolicyAbiType::Array(_, _) | PolicyAbiType::Tuple(_))
            .then(|| shape.static_width())
            .flatten()
            .filter(|width| *width > 8)
    });
    let cell_bound = physical.is_some()
        || reference
        || schema.is_some_and(|schema| matches!(schema.kind.as_str(), "resource" | "shared" | "receipt"));
    let source_id = entry.locals.iter().find(|local| local.id == param.binding_id).map(|local| local.source_id);
    let type_hash = schema_pointer
        && source_id.is_some_and(|source_id| {
            entry.blocks.iter().flat_map(|block| &block.operations).any(|operation| {
                operation.opcode == "type-hash"
                    && operation
                        .operands
                        .iter()
                        .filter_map(|operand| operand.local)
                        .any(|id| entry.locals.iter().any(|local| local.id == id && local.source_id == source_id))
            })
        });
    let mut result = serde_json::json!({
        "name": param.name,
        "ty": param.ty,
        "is_mut": param.mutable,
        "is_ref": reference,
        "cell_bound_abi": cell_bound,
        "schema_pointer_abi": schema_pointer,
        "schema_length_abi": schema_pointer,
        "fixed_byte_pointer_abi": fixed_byte_len.is_some(),
        "fixed_byte_length_abi": fixed_byte_len.is_some(),
        "fixed_byte_len": fixed_byte_len,
        "type_hash_pointer_abi": type_hash,
        "type_hash_length_abi": type_hash,
        "type_hash_len": type_hash.then_some(32u32),
    });
    if source != "default" {
        result["source"] = source.into();
    }
    for (field, enabled) in [
        ("protected_spend_surface", param.source == "protected"),
        ("witness_data_source", param.source == "witness"),
        ("lock_args_data_source", param.source == "lockargs"),
    ] {
        if enabled {
            result[field] = true.into();
        }
    }
    Ok(result)
}

/// The serialized ABI type grammar is deliberately independent of the source
/// parser. Named/generic schema views stay opaque; only fixed arrays, tuples,
/// references and builtin scalars contribute a statically encoded width.
#[derive(Debug, PartialEq, Eq)]
enum PolicyAbiType {
    Scalar { name: String, width: u64 },
    Named(String),
    Ref { mutable: bool, inner: Box<Self> },
    Array(Box<Self>, u64),
    Tuple(Vec<Self>),
}

impl PolicyAbiType {
    fn named(&self) -> Option<&str> {
        match self {
            Self::Named(name) => Some(name),
            Self::Ref { inner, .. } => inner.named(),
            _ => None,
        }
    }

    fn static_width(&self) -> Option<u64> {
        match self {
            Self::Scalar { width, .. } => Some(*width),
            Self::Ref { inner, .. } => inner.static_width(),
            Self::Array(inner, length) => inner.static_width()?.checked_mul(*length),
            Self::Tuple(items) => items.iter().try_fold(0u64, |total, item| total.checked_add(item.static_width()?)),
            Self::Named(_) => None,
        }
    }

    fn fixed_byte_width(&self) -> Option<u64> {
        match self {
            Self::Scalar { name, width } if name != "unit" => Some(*width),
            Self::Array(inner, length) if matches!(inner.as_ref(), Self::Scalar { name, .. } if name == "u8") => Some(*length),
            Self::Ref { inner, .. } => inner.fixed_byte_width(),
            _ => None,
        }
    }
}

fn policy_abi_type(input: &str, depth: usize) -> Result<PolicyAbiType, CheckerError> {
    if depth > 128 {
        return Err(metadata_error("policy ABI type exceeds the bounded nesting budget"));
    }
    let input = input.trim();
    if input.is_empty() {
        return Err(metadata_error("policy ABI type is empty"));
    }
    if let Some(inner) = input.strip_prefix('&') {
        let inner = inner.trim_start();
        let (mutable, inner) = if let Some(inner) = inner.strip_prefix("mut ") { (true, inner) } else { (false, inner) };
        return Ok(PolicyAbiType::Ref { mutable, inner: Box::new(policy_abi_type(inner, depth + 1)?) });
    }
    let canonical = crate::checker::canonical_abi_type(input);
    let width = match canonical.as_str() {
        "unit" => Some(0),
        "bool" | "u8" => Some(1),
        "u16" => Some(2),
        "u32" | "i32" => Some(4),
        "u64" => Some(8),
        "u128" => Some(16),
        "address" | "hash" => Some(32),
        _ => None,
    };
    if let Some(width) = width {
        return Ok(PolicyAbiType::Scalar { name: canonical, width });
    }
    if let Some(body) = input.strip_prefix('[').and_then(|body| body.strip_suffix(']')) {
        let parts = split_abi_fields(body, ';')?;
        if parts.len() != 2 {
            return Err(metadata_error("policy fixed array type requires one width separator"));
        }
        let length = parts[1].trim().parse::<u64>().map_err(|_| metadata_error("policy fixed array length is invalid"))?;
        return Ok(PolicyAbiType::Array(Box::new(policy_abi_type(parts[0], depth + 1)?), length));
    }
    if let Some(body) = input.strip_prefix('(').and_then(|body| body.strip_suffix(')')) {
        let items = split_abi_fields(body, ',')?.iter().map(|field| policy_abi_type(field, depth + 1)).collect::<Result<_, _>>()?;
        return Ok(PolicyAbiType::Tuple(items));
    }
    // Validate delimiter balance even for an opaque Vec/Option/named schema;
    // it must not be confused with a partially parsed fixed aggregate.
    split_abi_fields(input, '\0')?;
    Ok(PolicyAbiType::Named(canonical))
}

fn split_abi_fields(input: &str, separator: char) -> Result<Vec<&str>, CheckerError> {
    let mut delimiters = Vec::new();
    let mut fields = Vec::new();
    let mut start = 0;
    for (index, character) in input.char_indices() {
        match character {
            '(' => delimiters.push(')'),
            '[' => delimiters.push(']'),
            '<' => delimiters.push('>'),
            ')' | ']' | '>' if delimiters.pop() != Some(character) => {
                return Err(metadata_error("policy ABI type has unbalanced delimiters"));
            }
            character if character == separator && delimiters.is_empty() => {
                fields.push(&input[start..index]);
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    if !delimiters.is_empty() {
        return Err(metadata_error("policy ABI type has unbalanced delimiters"));
    }
    fields.push(&input[start..]);
    Ok(fields)
}

fn policy_metadata_projection(
    contract: &PolicyWitnessContract,
    typed: &TypedSemanticRecord,
) -> Result<serde_json::Value, CheckerError> {
    let mut actions = Vec::new();
    for variant in &contract.variants {
        let entry = action_entry(typed, &variant.entry_id)?;
        actions.push(serde_json::json!({ "tag": variant.tag, "action": entry.name }));
    }
    let mut common_checks = Vec::new();
    for id in &contract.common_checks {
        common_checks.push(action_entry(typed, id)?.name.as_str());
    }
    let mut declaration = serde_json::json!({
        "name": contract.artifact_name,
        "context": { "kind": "type-group", "resource": contract.resource },
        "dispatch": "policy-witness-v1",
        "actions": actions,
    });
    // ArtifactDeclaration deliberately omits an empty common-check list.
    if !common_checks.is_empty() {
        declaration["common_checks"] = serde_json::json!(common_checks);
    }
    Ok(serde_json::json!({
        "schema": "cellscript-policy-artifact-v1",
        "declaration": declaration,
        "max_records": contract.max_records,
        "max_witness_bytes": contract.max_witness_bytes,
        "payload_abi": POLICY_PAYLOAD_ABI,
        "placement_abi": POLICY_PLACEMENT_ABI,
        "placement_field": "input_type",
        "placement_source": POLICY_WITNESS_SOURCE,
    }))
}

pub(crate) fn validate_policy_contract(contract: &PolicyWitnessContract, typed: &TypedSemanticRecord) -> Result<(), CheckerError> {
    if contract.schema != POLICY_DISPATCH_SCHEMA
        || contract.version != POLICY_DISPATCH_VERSION
        || !valid_name(&contract.artifact_name)
        || !valid_name(&contract.resource)
        || contract.variants.is_empty()
        || contract.variants.len() > 64
        || contract.common_checks.len() > 16
        || contract.max_records != 8
        || contract.max_witness_bytes != 4096
        || contract.unknown_selector != "reject"
    {
        return Err(invalid("policy dispatch uses an unsupported or incomplete bounded contract"));
    }
    if contract.variants.windows(2).any(|pair| pair[0].tag >= pair[1].tag) {
        return Err(invalid("policy dispatch tags must be unique and numerically sorted"));
    }
    let mut schemas = typed.types.iter().filter(|schema| schema.name == contract.resource);
    let schema = schemas.next().ok_or_else(|| invalid("policy resource has no exact typed schema"))?;
    if schemas.next().is_some() || !matches!(schema.kind.as_str(), "resource" | "shared" | "receipt") {
        return Err(invalid("policy resource must identify exactly one concrete Cell-backed schema"));
    }
    let expected_layout = canonical_hash(
        "cellscript-typed-layout-v2",
        &(
            schema.kind.as_str(),
            schema.encoded_size,
            &schema.fields,
            schema.tag_width_bytes,
            &schema.variants,
            &schema.capabilities,
            &schema.identity_policy,
        ),
    )?;
    if schema.layout_hash != expected_layout || contract.resource_layout_hash != expected_layout {
        return Err(invalid("policy resource does not bind its exact canonical typed layout"));
    }
    let selector = ValueProvenance::EntryWitness {
        placement_abi: POLICY_PLACEMENT_ABI.to_string(),
        payload_abi: POLICY_PAYLOAD_ABI.to_string(),
        group_witness_source: POLICY_WITNESS_SOURCE.to_string(),
        field_path: POLICY_SELECTOR_FIELD.to_string(),
    };
    let selector_id = canonical_hash("cellscript-value-provenance-node-v1", &selector)?;
    let mut selector_nodes = typed.foundation.provenance.nodes.iter().filter(|node| node.id == contract.selector_node_id);
    if contract.selector_node_id != selector_id
        || selector_nodes.next().is_none_or(|node| node.provenance != selector)
        || selector_nodes.next().is_some()
    {
        return Err(invalid(
            "policy selector must be the canonical policy EntryWitness root, not an arbitrary label or derived value",
        ));
    }
    // Reuse the parser-free binding/provenance projection checks. The policy
    // restrictions below additionally reject absolute, bounded and aliased
    // group roles that ordinary single-entry compilation may legitimately use.
    crate::bindings::validate(typed)?;
    let mut exports = BTreeSet::new();
    for variant in &contract.variants {
        if !exports.insert(variant.entry_id.as_str()) {
            return Err(invalid("policy dispatch exports an action more than once"));
        }
        let entry = action_entry(typed, &variant.entry_id)?;
        if variant.payload_schema_hash != canonical_hash("cellscript-policy-variant-payload-v1", &entry.params)? {
            return Err(invalid(format!("policy export '{}' payload schema does not match its exact typed parameters", entry.id)));
        }
        if entry.return_type != "unit" {
            return Err(invalid(format!("policy export '{}' must use the Unit action status contract", entry.id)));
        }
        let (inputs, outputs) = validate_export_bindings(entry, contract, typed)?;
        if inputs != variant.input_count || outputs != variant.output_count || (inputs == 0 && outputs == 0) {
            return Err(invalid(format!("policy export '{}' group counts do not match its fixed roles", entry.id)));
        }
    }
    let mut common_checks = BTreeSet::new();
    for id in &contract.common_checks {
        if exports.contains(id.as_str()) || !common_checks.insert(id.as_str()) {
            return Err(invalid("policy common checks must be unique and must not also be selectable exports"));
        }
        validate_common_check(action_entry(typed, id)?, typed)?;
    }
    Ok(())
}

fn action_entry<'a>(typed: &'a TypedSemanticRecord, id: &str) -> Result<&'a TypedSemanticEntry, CheckerError> {
    let mut entries = typed.entries.iter().filter(|entry| entry.id == id);
    let entry = entries.next().ok_or_else(|| invalid(format!("policy entry '{id}' is missing")))?;
    if entries.next().is_some() || entry.kind != "action" || !valid_name(&entry.name) || entry.id != format!("action:{}", entry.name) {
        return Err(invalid(format!("policy entry '{id}' must identify exactly one typed action")));
    }
    Ok(entry)
}

fn validate_export_bindings(
    entry: &TypedSemanticEntry,
    contract: &PolicyWitnessContract,
    typed: &TypedSemanticRecord,
) -> Result<(u32, u32), CheckerError> {
    for param in &entry.params {
        if param.source != "lockargs"
            && (param.reference || matches!(policy_abi_type(&param.ty, 0)?, PolicyAbiType::Ref { .. }))
            && !entry.cell_bindings.iter().any(|binding| binding.local_id == Some(param.binding_id))
        {
            return Err(invalid(format!(
                "policy export '{}' reference parameter '{}' has no physical Cell source",
                entry.id, param.name
            )));
        }
    }
    let mut inputs = BTreeSet::new();
    let mut outputs = BTreeSet::new();
    let mut local_locations = BTreeMap::new();
    for binding in &entry.cell_bindings {
        if let Some(local) = binding.local_id {
            let location = (binding.source, binding.ordinal);
            if local_locations.insert(local, location).is_some_and(|previous| previous != location) {
                return Err(invalid(format!("policy export '{}' reuses one local for distinct physical Cells", entry.id)));
            }
        }
        if binding.source == CellBindingSource::CellDep {
            if binding.role != CellBindingRole::ReadOnly || binding.membership != CellBindingMembership::Unproven {
                return Err(invalid(format!("policy export '{}' implicitly authenticates a CellDep", entry.id)));
            }
            continue;
        }
        let slots = match (binding.source, binding.role) {
            (CellBindingSource::GroupInput, CellBindingRole::Input | CellBindingRole::ReadOnly) => &mut inputs,
            (CellBindingSource::GroupOutput, CellBindingRole::Output) => &mut outputs,
            _ => return Err(invalid(format!("policy export '{}' has a non-group or inconsistent Cell role", entry.id))),
        };
        if binding.ty != contract.resource
            || binding.membership != CellBindingMembership::CurrentTypeGroup
            || !slots.insert(binding.ordinal)
        {
            return Err(invalid(format!(
                "policy export '{}' has a foreign schema, unproven membership, or aliased group role",
                entry.id
            )));
        }
    }
    for slots in [&inputs, &outputs] {
        if slots.iter().copied().ne(0..slots.len() as u32) {
            return Err(invalid(format!("policy export '{}' group roles are not dense from ordinal zero", entry.id)));
        }
    }
    for role in typed.foundation.roles.iter().filter(|role| role.entry_id == entry.id) {
        if role.direction == "read-only-dependency" {
            continue;
        }
        if role.ty != contract.resource
            || role.schema_identity != contract.resource_layout_hash
            || role.source != "group-relative"
            || role.script_identity_policy != "current-type-group"
            || role.lock_or_type_role != "type"
            || role.cardinality != "exactly-one"
        {
            return Err(invalid(format!("policy export '{}' has a non-fixed or foreign projected role", entry.id)));
        }
    }
    if entry.blocks.iter().flat_map(|block| &block.operations).any(|operation| operation.opcode.starts_with("bounded-")) {
        return Err(invalid(format!("policy export '{}' mixes fixed and bounded Cell roles", entry.id)));
    }
    Ok((inputs.len() as u32, outputs.len() as u32))
}

fn validate_common_check(entry: &TypedSemanticEntry, typed: &TypedSemanticRecord) -> Result<(), CheckerError> {
    if entry.blocks.len() > MAX_COMMON_CALLEE_BLOCKS {
        return Err(invalid("policy common check has excessive blocks"));
    }
    let invalid_body = entry.blocks.iter().flat_map(|block| &block.operations).any(|operation| {
        operation.opcode.starts_with("bounded-")
            || matches!(
                operation.opcode.as_str(),
                "consume" | "create" | "create-unique" | "replace-unique" | "destroy" | "transfer" | "claim" | "settle"
            )
    });
    if !entry.params.is_empty()
        || entry.return_type != "unit"
        || entry.cell_bindings.iter().any(|binding| {
            binding.source != CellBindingSource::CellDep
                || binding.role != CellBindingRole::ReadOnly
                || binding.membership != CellBindingMembership::Unproven
        })
        || typed.foundation.roles.iter().any(|role| role.entry_id == entry.id && role.direction != "read-only-dependency")
        || typed.foundation.dispositions.iter().any(|disposition| disposition.entry_id == entry.id)
        || entry.ownership.iter().any(|ownership| ownership.operation != "read_ref")
        || invalid_body
    {
        return Err(invalid(format!(
            "policy common check '{}' must be a zero-parameter Unit action with only CellDep roles and no lifecycle",
            entry.id
        )));
    }
    let names = typed.entries.iter().map(|entry| (entry.name.as_str(), entry)).collect::<BTreeMap<_, _>>();
    if names.len() != typed.entries.len() {
        return Err(invalid("policy common calls require unique retained callable names"));
    }
    validate_common_calls(entry, typed, &names, &mut BTreeSet::new(), &mut BTreeMap::new())?;
    Ok(())
}

fn scalar_call_type(ty: &str) -> bool {
    matches!(ty, "u8" | "u16" | "u32" | "i32" | "u64" | "bool")
}

fn bounded_call_type(ty: &str, typed: &TypedSemanticRecord) -> bool {
    scalar_call_type(ty)
        || matches!(ty, "unit" | "()")
        || ty.strip_prefix('&').is_some_and(|name| typed.types.iter().any(|schema| schema.name == name))
}

fn validate_common_calls<'a>(
    entry: &'a TypedSemanticEntry,
    typed: &TypedSemanticRecord,
    names: &BTreeMap<&str, &'a TypedSemanticEntry>,
    active: &mut BTreeSet<&'a str>,
    suffix_depths: &mut BTreeMap<&'a str, usize>,
) -> Result<usize, CheckerError> {
    if active.contains(entry.name.as_str()) {
        return Err(invalid("policy common call graph is recursive"));
    }
    // A shared suffix still contributes its full depth to every caller path.
    // Memoize only completed subgraphs, and combine that depth with the live
    // prefix before returning it. A visited bit alone is order-dependent.
    if let Some(depth) = suffix_depths.get(entry.name.as_str()).copied() {
        if active.len() + depth > MAX_COMMON_CALL_DEPTH {
            return Err(invalid("policy common call graph exceeds the call-depth bound"));
        }
        return Ok(depth);
    }
    if active.len() >= MAX_COMMON_CALL_DEPTH {
        return Err(invalid("policy common call graph exceeds the call-depth bound"));
    }
    active.insert(entry.name.as_str());
    let mut longest_suffix = 1;
    for operation in entry.blocks.iter().flat_map(|block| &block.operations) {
        if operation.opcode != "call" && operation.call.is_none() {
            continue;
        }
        let call = operation
            .call
            .as_ref()
            .filter(|_| operation.opcode == "call")
            .ok_or_else(|| invalid("policy common call has a missing or hidden callable contract"))?;
        let callee = names
            .get(call.target.as_str())
            .copied()
            .ok_or_else(|| invalid("policy common call requires a retained scalar/Unit callable body"))?;
        if !matches!(callee.kind.as_str(), "action" | "helper")
            || call.contract != "typed-local"
            || call.params != callee.params.iter().map(|param| param.ty.clone()).collect::<Vec<_>>()
            || call.return_type != callee.return_type
            || call.effect != callee.effect
            || callee.params.iter().any(|param| param.mutable || !bounded_call_type(&param.ty, typed))
            || !bounded_call_type(&callee.return_type, typed)
            || callee.return_type.starts_with('&')
            || !callee.cell_bindings.is_empty()
            || !callee.ownership.is_empty()
            || typed.foundation.roles.iter().any(|role| role.entry_id == callee.id)
            || typed.foundation.dispositions.iter().any(|disposition| disposition.entry_id == callee.id)
        {
            return Err(invalid(format!("policy common callee '{}' exceeds its bounded caller-value contract", callee.id)));
        }
        if !suffix_depths.contains_key(callee.name.as_str()) {
            validate_common_callee_body(callee, typed)?;
        }
        let callee_depth = validate_common_calls(callee, typed, names, active, suffix_depths)?;
        longest_suffix = longest_suffix.max(1 + callee_depth);
    }
    active.remove(entry.name.as_str());
    suffix_depths.insert(entry.name.as_str(), longest_suffix);
    Ok(longest_suffix)
}

fn validate_common_callee_body(entry: &TypedSemanticEntry, typed: &TypedSemanticRecord) -> Result<(), CheckerError> {
    if entry.blocks.len() > MAX_COMMON_CALLEE_BLOCKS {
        return Err(invalid("policy common callee has excessive blocks"));
    }
    let locals = entry.locals.iter().map(|local| (local.id, local.ty.as_str())).collect::<BTreeMap<_, _>>();
    let blocks = entry.blocks.iter().map(|block| (block.id, block)).collect::<BTreeMap<_, _>>();
    if blocks.len() != entry.blocks.len() {
        return Err(invalid("policy common callee has duplicated blocks"));
    }
    let mut incoming = blocks.keys().map(|id| (*id, 0usize)).collect::<BTreeMap<_, _>>();
    for block in &entry.blocks {
        for successor in &block.successors {
            *incoming.get_mut(successor).ok_or_else(|| invalid("policy common callee has an unknown CFG successor"))? += 1;
        }
        if block
            .runtime_error
            .as_ref()
            .is_some_and(|error| !matches!(error.code, 5 | 20 | 65) || block.terminator != "verifier-failure")
        {
            return Err(invalid("policy common callee has a failure outside the scalar terminal contract"));
        }
        for operation in &block.operations {
            let scalar = operation.opcode == "binary";
            let bounded = |ty: &str| if scalar { scalar_call_type(ty) } else { bounded_call_type(ty, typed) };
            let empty_tuple = operation.opcode == "tuple"
                && operation.operands.is_empty()
                && operation.destinations.len() == 1
                && locals.get(&operation.destinations[0]).is_some_and(|ty| matches!(*ty, "unit" | "()"));
            if (!empty_tuple
                && !matches!(
                    operation.opcode.as_str(),
                    "load-const"
                        | "load-var"
                        | "store-var"
                        | "move"
                        | "binary"
                        | "unary"
                        | "call"
                        | "return"
                        | "branch-condition"
                        | "verifier-failure"
                ))
                || operation.destinations.iter().any(|id| locals.get(id).is_none_or(|ty| !bounded(ty)))
                || operation.operands.iter().any(|operand| !bounded(&operand.ty))
                || (operation.opcode == "unary"
                    && !matches!(&operation.detail, TypedSemanticOperationDetail::UnaryOperator { operator } if operator == "not"))
            {
                return Err(invalid(format!("policy common callee '{}' contains an unsupported operation", entry.id)));
            }
        }
    }
    let mut ready = incoming.iter().filter_map(|(id, count)| (*count == 0).then_some(*id)).collect::<Vec<_>>();
    let mut visited = 0;
    while let Some(id) = ready.pop() {
        visited += 1;
        for successor in &blocks[&id].successors {
            let remaining = incoming.get_mut(successor).expect("checked CFG successor");
            *remaining -= 1;
            if *remaining == 0 {
                ready.push(*successor);
            }
        }
    }
    if visited != blocks.len() {
        return Err(invalid("policy common callee must have an acyclic bounded CFG"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema(name: &str) -> TypedSemanticType {
        let mut schema = TypedSemanticType {
            name: name.to_string(),
            kind: "resource".to_string(),
            encoded_size: Some(8),
            fields: vec![TypedSemanticField { name: "amount".to_string(), ty: "u64".to_string(), offset: 0, width_bytes: Some(8) }],
            identity_policy: "none".to_string(),
            ..Default::default()
        };
        schema.layout_hash = canonical_hash(
            "cellscript-typed-layout-v2",
            &(
                schema.kind.as_str(),
                schema.encoded_size,
                &schema.fields,
                schema.tag_width_bytes,
                &schema.variants,
                &schema.capabilities,
                &schema.identity_policy,
            ),
        )
        .unwrap();
        schema
    }

    fn role_projection(entry: &TypedSemanticEntry, binding: &TypedSemanticCellBinding, schema: &TypedSemanticType) -> RoleBinding {
        RoleBinding {
            semantic_node_id: String::new(),
            role_id: binding.role_id(&entry.id),
            entry_id: entry.id.clone(),
            binding: binding.binding.clone(),
            ty: binding.ty.clone(),
            direction: binding.direction().to_string(),
            locality: "local".to_string(),
            source: binding.source_scope().to_string(),
            selector: binding.selector(),
            cardinality: "exactly-one".to_string(),
            lock_or_type_role: "type".to_string(),
            script_identity_policy: binding.membership_policy().to_string(),
            schema_identity: schema.layout_hash.clone(),
            correspondence_policy: "independent-fixed-role".to_string(),
        }
    }

    fn fixture() -> (PolicyWitnessContract, TypedSemanticRecord) {
        let resource = schema("Token");
        let selector = ValueProvenance::EntryWitness {
            placement_abi: POLICY_PLACEMENT_ABI.to_string(),
            payload_abi: POLICY_PAYLOAD_ABI.to_string(),
            group_witness_source: POLICY_WITNESS_SOURCE.to_string(),
            field_path: POLICY_SELECTOR_FIELD.to_string(),
        };
        let selector_node_id = canonical_hash("cellscript-value-provenance-node-v1", &selector).unwrap();
        let mut typed = TypedSemanticRecord { types: vec![resource.clone(), schema("Config")], ..Default::default() };
        typed.foundation.provenance.nodes.push(ProvenanceNode { id: selector_node_id.clone(), provenance: selector });
        let mut variants = Vec::new();
        for (tag, name, input_count, output_count) in
            [(0, "mint", 0, 1), (2, "transfer", 1, 1), (10, "merge", 2, 1), (u32::MAX, "burn", 1, 0)]
        {
            let mut entry = TypedSemanticEntry {
                id: format!("action:{name}"),
                kind: "action".to_string(),
                name: name.to_string(),
                return_type: "unit".to_string(),
                ..Default::default()
            };
            for (source, count, prefix, role) in [
                (CellBindingSource::GroupInput, input_count, "before", CellBindingRole::Input),
                (CellBindingSource::GroupOutput, output_count, "after", CellBindingRole::Output),
            ] {
                for ordinal in 0..count {
                    let binding = TypedSemanticCellBinding {
                        binding: format!("{prefix}{ordinal}"),
                        role,
                        local_id: None,
                        ty: "Token".to_string(),
                        source,
                        ordinal,
                        membership: CellBindingMembership::CurrentTypeGroup,
                    };
                    typed.foundation.roles.push(role_projection(&entry, &binding, &resource));
                    entry.cell_bindings.push(binding);
                }
            }
            variants.push(PolicyWitnessVariant {
                tag,
                entry_id: entry.id.clone(),
                payload_schema_hash: canonical_hash("cellscript-policy-variant-payload-v1", &entry.params).unwrap(),
                input_count,
                output_count,
            });
            typed.entries.push(entry);
        }
        typed.canonicalize();
        (
            PolicyWitnessContract {
                schema: POLICY_DISPATCH_SCHEMA.to_string(),
                version: POLICY_DISPATCH_VERSION,
                artifact_name: "token_policy".to_string(),
                resource: "Token".to_string(),
                resource_layout_hash: resource.layout_hash,
                selector_node_id,
                variants,
                common_checks: Vec::new(),
                max_records: 8,
                max_witness_bytes: 4096,
                unknown_selector: "reject".to_string(),
            },
            typed,
        )
    }

    fn entry_mut<'a>(typed: &'a mut TypedSemanticRecord, name: &str) -> &'a mut TypedSemanticEntry {
        typed.entries.iter_mut().find(|entry| entry.name == name).unwrap()
    }

    fn attach_builder_actions(metadata: &mut serde_json::Value, typed: &TypedSemanticRecord) {
        metadata["actions"] = serde_json::json!(typed.entries.iter().filter(|entry| entry.kind == "action").map(|entry| {
            serde_json::json!({
                "name": entry.name,
                "params": entry.params.iter().map(|param| builder_parameter_projection(param, entry, typed).unwrap()).collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>());
    }

    fn refresh_role_projections(typed: &mut TypedSemanticRecord) {
        typed.foundation.roles = typed
            .entries
            .iter()
            .flat_map(|entry| {
                entry.cell_bindings.iter().map(|binding| {
                    let schema = typed.types.iter().find(|schema| schema.name == binding.ty).unwrap();
                    role_projection(entry, binding, schema)
                })
            })
            .collect();
        typed.canonicalize();
    }

    fn add_common(typed: &mut TypedSemanticRecord, contract: &mut PolicyWitnessContract, name: &str) {
        let mut entry = TypedSemanticEntry {
            id: format!("action:{name}"),
            kind: "action".to_string(),
            name: name.to_string(),
            return_type: "unit".to_string(),
            ..Default::default()
        };
        let binding = TypedSemanticCellBinding {
            binding: "config".to_string(),
            role: CellBindingRole::ReadOnly,
            local_id: None,
            ty: "Config".to_string(),
            source: CellBindingSource::CellDep,
            ordinal: 0,
            membership: CellBindingMembership::Unproven,
        };
        typed.foundation.roles.push(role_projection(
            &entry,
            &binding,
            typed.types.iter().find(|schema| schema.name == "Config").unwrap(),
        ));
        entry.cell_bindings.push(binding);
        contract.common_checks.push(entry.id.clone());
        typed.entries.push(entry);
        typed.canonicalize();
    }

    #[test]
    fn numeric_tags_and_fixed_mint_transfer_merge_burn_roles_are_supported() {
        let (contract, typed) = fixture();
        validate_policy_contract(&contract, &typed).unwrap();
        let serialized = serde_json::to_value(&contract).unwrap();
        assert_eq!(serialized["variants"][0]["tag"], 0);
        assert_eq!(serialized["variants"][3]["tag"], u32::MAX);
        assert_eq!(serde_json::from_value::<PolicyWitnessContract>(serialized).unwrap(), contract);
    }

    #[test]
    fn selector_requires_exact_root_contents_and_canonical_identity() {
        for mutation in ["label", "derived", "placement", "payload", "source", "field", "duplicate"] {
            let (mut contract, mut typed) = fixture();
            let node = &mut typed.foundation.provenance.nodes[0];
            match mutation {
                "label" => node.id = "chosen-selector".to_string(),
                "derived" => {
                    node.provenance = ValueProvenance::Derived { operation: "identity".to_string(), inputs: vec![node.id.clone()] }
                }
                "duplicate" => {}
                field => {
                    let ValueProvenance::EntryWitness { placement_abi, payload_abi, group_witness_source, field_path } =
                        &mut node.provenance
                    else {
                        unreachable!()
                    };
                    *match field {
                        "placement" => placement_abi,
                        "payload" => payload_abi,
                        "source" => group_witness_source,
                        "field" => field_path,
                        _ => unreachable!(),
                    } = "different".to_string();
                }
            }
            if mutation != "label" {
                node.id = canonical_hash("cellscript-value-provenance-node-v1", &node.provenance).unwrap();
            }
            contract.selector_node_id = node.id.clone();
            if mutation == "duplicate" {
                typed.foundation.provenance.nodes.push(typed.foundation.provenance.nodes[0].clone());
            }
            assert!(validate_policy_contract(&contract, &typed).is_err(), "{mutation}");
        }
    }

    #[test]
    fn declaration_mutations_cannot_weaken_the_bounded_dispatch_contract() {
        for mutation in [
            "schema",
            "version",
            "records",
            "bytes",
            "unknown",
            "duplicate-tag",
            "lexical-order",
            "duplicate-export",
            "missing-export",
            "payload",
            "layout",
            "count",
            "empty",
            "too-many",
        ] {
            let (mut contract, typed) = fixture();
            match mutation {
                "schema" => contract.schema.push_str("-future"),
                "version" => contract.version += 1,
                "records" => contract.max_records += 1,
                "bytes" => contract.max_witness_bytes += 1,
                "unknown" => contract.unknown_selector = "accept".to_string(),
                "duplicate-tag" => contract.variants[1].tag = 0,
                "lexical-order" => contract.variants.swap(1, 2),
                "duplicate-export" => contract.variants[1].entry_id = contract.variants[0].entry_id.clone(),
                "missing-export" => contract.variants[1].entry_id = "action:absent".to_string(),
                "payload" => contract.variants[1].payload_schema_hash = "other".to_string(),
                "layout" => contract.resource_layout_hash = "label".to_string(),
                "count" => contract.variants[1].input_count += 1,
                "empty" => contract.variants.clear(),
                "too-many" => contract.variants.resize(65, contract.variants[0].clone()),
                _ => unreachable!(),
            }
            assert!(validate_policy_contract(&contract, &typed).is_err(), "{mutation}");
        }
    }

    #[test]
    fn physical_roles_cannot_be_absolute_sparse_aliased_foreign_or_unauthenticated() {
        for mutation in ["absolute", "sparse", "alias", "foreign", "membership", "role-layout", "bounded"] {
            let (contract, mut typed) = fixture();
            let entry = entry_mut(&mut typed, "transfer");
            match mutation {
                "absolute" => {
                    entry.cell_bindings[0].source = CellBindingSource::Output;
                    entry.cell_bindings[0].membership = CellBindingMembership::Unproven;
                }
                "sparse" => entry.cell_bindings[0].ordinal = 1,
                "alias" => {
                    let mut alias = entry.cell_bindings[0].clone();
                    alias.binding = "alias".to_string();
                    entry.cell_bindings.push(alias);
                }
                "foreign" => entry.cell_bindings[0].ty = "Config".to_string(),
                "membership" => entry.cell_bindings[0].membership = CellBindingMembership::Unproven,
                "role-layout" => {
                    typed.foundation.roles.iter_mut().find(|role| role.entry_id == "action:transfer").unwrap().schema_identity =
                        "other".to_string()
                }
                "bounded" => entry.blocks.push(TypedSemanticBlock {
                    operations: vec![TypedSemanticOperation { opcode: "bounded-cell-load".to_string(), ..Default::default() }],
                    ..Default::default()
                }),
                _ => unreachable!(),
            }
            if mutation != "role-layout" {
                // The policy boundary must reject coherent projections too,
                // not only mutations already caught by ordinary role binding.
                refresh_role_projections(&mut typed);
            }
            assert!(validate_policy_contract(&contract, &typed).is_err(), "{mutation}");
        }
    }

    #[test]
    fn one_local_cannot_claim_both_input_and_output_despite_complete_provenance() {
        let (contract, mut typed) = fixture();
        let entry = entry_mut(&mut typed, "transfer");
        entry.locals.push(TypedSemanticLocal { id: 0, source_id: 0, name: "shared".to_string(), ty: "Token".to_string() });
        let mut nodes = Vec::new();
        let mut bindings = Vec::new();
        for binding in &mut entry.cell_bindings {
            binding.local_id = Some(0);
            let provenance = binding.provenance(&entry.id);
            let id = canonical_hash("cellscript-value-provenance-node-v1", &provenance).unwrap();
            bindings.push(ProvenanceBinding { entry_id: entry.id.clone(), local_id: 0, node_id: id.clone() });
            nodes.push(ProvenanceNode { id, provenance });
        }
        typed.foundation.provenance.nodes.extend(nodes);
        typed.foundation.provenance.bindings.extend(bindings);
        refresh_role_projections(&mut typed);
        crate::bindings::validate(&typed).unwrap();
        assert!(validate_policy_contract(&contract, &typed).unwrap_err().message.contains("distinct physical Cells"));
    }

    #[test]
    fn payload_identity_tracks_exact_typed_parameter_shape() {
        let (mut contract, mut typed) = fixture();
        let entry = entry_mut(&mut typed, "transfer");
        entry.params.push(TypedSemanticParam {
            index: 0,
            binding_id: 7,
            name: "amount".to_string(),
            ty: "u64".to_string(),
            source: "witness".to_string(),
            mutable: false,
            reference: false,
        });
        assert!(validate_policy_contract(&contract, &typed).unwrap_err().message.contains("payload schema"));
        let entry = entry_mut(&mut typed, "transfer");
        contract.variants[1].payload_schema_hash = canonical_hash("cellscript-policy-variant-payload-v1", &entry.params).unwrap();
        validate_policy_contract(&contract, &typed).unwrap();
        entry_mut(&mut typed, "transfer").params[0].ty = "u128".to_string();
        assert!(validate_policy_contract(&contract, &typed).unwrap_err().message.contains("payload schema"));
    }

    #[test]
    fn entry_reference_parameters_cannot_be_unsourced_caller_views() {
        let (mut contract, mut typed) = fixture();
        let entry = entry_mut(&mut typed, "mint");
        entry.params.push(TypedSemanticParam {
            name: "view".to_string(),
            ty: "&u64".to_string(),
            source: "default".to_string(),
            ..Default::default()
        });
        contract.variants[0].payload_schema_hash = canonical_hash("cellscript-policy-variant-payload-v1", &entry.params).unwrap();
        assert!(validate_policy_contract(&contract, &typed).unwrap_err().message.contains("no physical Cell source"));
    }

    #[test]
    fn common_checks_preserve_order_and_allow_only_zero_param_unit_dep_actions() {
        let (mut contract, mut typed) = fixture();
        add_common(&mut typed, &mut contract, "z_first");
        add_common(&mut typed, &mut contract, "a_second");
        validate_policy_contract(&contract, &typed).unwrap();
        assert_eq!(contract.common_checks, ["action:z_first", "action:a_second"]);
        for mutation in ["duplicate", "overlap", "too-many", "helper", "bool", "param", "cell", "call", "hidden-call", "lifecycle"] {
            let mut contract = contract.clone();
            let mut typed = typed.clone();
            match mutation {
                "duplicate" => contract.common_checks.push(contract.common_checks[0].clone()),
                "overlap" => contract.common_checks.push("action:mint".to_string()),
                "too-many" => contract.common_checks.resize(17, "action:z_first".to_string()),
                mutation => {
                    let entry = entry_mut(&mut typed, "z_first");
                    match mutation {
                        "helper" => entry.kind = "helper".to_string(),
                        "bool" => entry.return_type = "bool".to_string(),
                        "param" => entry.params.push(TypedSemanticParam::default()),
                        "cell" => entry.cell_bindings[0].source = CellBindingSource::GroupInput,
                        "call" | "hidden-call" | "lifecycle" => entry.blocks.push(TypedSemanticBlock {
                            operations: vec![TypedSemanticOperation {
                                opcode: if mutation == "lifecycle" {
                                    "consume"
                                } else if mutation == "hidden-call" {
                                    "move"
                                } else {
                                    "call"
                                }
                                .to_string(),
                                call: (mutation == "hidden-call").then(TypedSemanticCall::default),
                                ..Default::default()
                            }],
                            ..Default::default()
                        }),
                        _ => unreachable!(),
                    }
                }
            }
            assert!(validate_policy_contract(&contract, &typed).is_err(), "{mutation}");
        }
    }

    fn unit_call(target: &str, index: u32) -> TypedSemanticOperation {
        TypedSemanticOperation {
            index,
            opcode: "call".to_string(),
            call: Some(TypedSemanticCall {
                target: target.to_string(),
                return_type: "unit".to_string(),
                contract: "typed-local".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn add_unit_chain(typed: &mut TypedSemanticRecord, prefix: &str, length: usize, tail: Option<&str>) -> String {
        for index in 1..=length {
            let name = format!("{prefix}{index}");
            let next = if index < length { Some(format!("{prefix}{}", index + 1)) } else { tail.map(str::to_string) };
            typed.entries.push(TypedSemanticEntry {
                id: format!("helper:{name}"),
                name,
                kind: "helper".to_string(),
                return_type: "unit".to_string(),
                blocks: vec![TypedSemanticBlock {
                    operations: next.map(|next| vec![unit_call(&next, 0)]).unwrap_or_default(),
                    terminator: "return".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            });
        }
        format!("{prefix}1")
    }

    #[test]
    fn common_call_depth_counts_shared_suffix_on_every_path_in_either_order() {
        for head_length in [200, 55, 56] {
            for tail_first in [true, false] {
                let (mut contract, mut typed) = fixture();
                add_common(&mut typed, &mut contract, "common");
                let tail = add_unit_chain(&mut typed, "tail", 200, None);
                let head = add_unit_chain(&mut typed, "head", head_length, Some(&tail));
                let calls = if tail_first { [&tail, &head] } else { [&head, &tail] };
                entry_mut(&mut typed, "common").blocks.push(TypedSemanticBlock {
                    operations: calls.iter().enumerate().map(|(index, name)| unit_call(name, index as u32)).collect(),
                    terminator: "return".to_string(),
                    ..Default::default()
                });
                let actual_path = 1 + head_length + 200;
                let result = validate_policy_contract(&contract, &typed);
                if actual_path <= 256 {
                    result.unwrap();
                } else {
                    assert!(result.is_err(), "accepted actual path {actual_path} with tail_first={tail_first}");
                    assert!(result.unwrap_err().message.contains("call-depth bound"));
                }
            }
        }
    }

    #[test]
    fn common_call_depth_accepts_exact_limit_and_rejects_cycles() {
        for helper_count in [0, 255, 256] {
            let (mut contract, mut typed) = fixture();
            add_common(&mut typed, &mut contract, "common");
            if helper_count > 0 {
                let head = add_unit_chain(&mut typed, "chain", helper_count, None);
                entry_mut(&mut typed, "common")
                    .blocks
                    .push(TypedSemanticBlock { operations: vec![unit_call(&head, 0)], ..Default::default() });
            }
            assert_eq!(validate_policy_contract(&contract, &typed).is_ok(), helper_count < 256, "{helper_count} helpers");
        }
        let (mut contract, mut typed) = fixture();
        add_common(&mut typed, &mut contract, "common");
        let head = add_unit_chain(&mut typed, "cycle", 2, Some("cycle1"));
        entry_mut(&mut typed, "common")
            .blocks
            .push(TypedSemanticBlock { operations: vec![unit_call(&head, 0)], ..Default::default() });
        assert!(validate_policy_contract(&contract, &typed).unwrap_err().message.contains("recursive"));
    }

    #[test]
    fn unknown_contract_and_variant_fields_are_rejected() {
        let (contract, _) = fixture();
        let mut json = serde_json::to_value(&contract).unwrap();
        json["extra"] = true.into();
        assert!(serde_json::from_value::<PolicyWitnessContract>(json).is_err());
        let mut json = serde_json::to_value(&contract).unwrap();
        json["variants"][0]["extra"] = true.into();
        assert!(serde_json::from_value::<PolicyWitnessContract>(json).is_err());
    }

    #[test]
    fn builder_tag_map_and_ordered_common_checks_must_equal_the_checked_contract() {
        let (mut contract, mut typed) = fixture();
        add_common(&mut typed, &mut contract, "z_first");
        add_common(&mut typed, &mut contract, "a_second");
        let mut metadata = serde_json::json!({ "runtime": { "policy_artifact": {
            "schema": "cellscript-policy-artifact-v1",
            "declaration": {
                "name": "token_policy",
                "context": { "kind": "type-group", "resource": "Token" },
                "dispatch": "policy-witness-v1",
                "actions": [
                    { "tag": 0, "action": "mint" },
                    { "tag": 2, "action": "transfer" },
                    { "tag": 10, "action": "merge" },
                    { "tag": u32::MAX, "action": "burn" },
                ],
                "common_checks": ["z_first", "a_second"],
            },
            "max_records": 8,
            "max_witness_bytes": 4096,
            "payload_abi": "cellscript-policy-witness-v1",
            "placement_abi": "cellscript-policy-witnessargs-input-type-v1",
            "placement_field": "input_type",
            "placement_source": "group-input[0]-or-output[0]-if-no-inputs",
        } } });
        typed.foundation.entry_contract.dispatch = EntryDispatchContract::PolicyWitnessV1(contract);
        attach_builder_actions(&mut metadata, &typed);
        validate_policy_metadata(&metadata, &typed).unwrap();
        for mutation in [
            "tag",
            "action",
            "name",
            "resource",
            "dispatch",
            "common-order",
            "schema",
            "payload",
            "placement",
            "field",
            "source",
            "records",
            "bytes",
            "extra",
            "missing",
        ] {
            let mut metadata = metadata.clone();
            let policy = &mut metadata["runtime"]["policy_artifact"];
            match mutation {
                "tag" => policy["declaration"]["actions"][0]["tag"] = 1.into(),
                "action" => policy["declaration"]["actions"][0]["action"] = "transfer".into(),
                "name" => policy["declaration"]["name"] = "other".into(),
                "resource" => policy["declaration"]["context"]["resource"] = "Config".into(),
                "dispatch" => policy["declaration"]["dispatch"] = "single-entry".into(),
                "common-order" => policy["declaration"]["common_checks"].as_array_mut().unwrap().swap(0, 1),
                "schema" => policy["schema"] = "future".into(),
                "payload" => policy["payload_abi"] = "raw".into(),
                "placement" => policy["placement_abi"] = "raw".into(),
                "field" => policy["placement_field"] = "lock".into(),
                "source" => policy["placement_source"] = "absolute-input[0]".into(),
                "records" => policy["max_records"] = 9.into(),
                "bytes" => policy["max_witness_bytes"] = 4097.into(),
                "extra" => policy["accept_unknown"] = true.into(),
                "missing" => {
                    metadata["runtime"].as_object_mut().unwrap().remove("policy_artifact");
                }
                _ => unreachable!(),
            }
            assert_eq!(
                validate_policy_metadata(&metadata, &typed).unwrap_err().code,
                CheckerRejectionCode::V2410MetadataBindingMismatch,
                "{mutation}"
            );
        }
    }

    #[test]
    fn policy_metadata_presence_is_canonical_for_single_entry_and_empty_common_checks() {
        let (contract, mut typed) = fixture();
        validate_policy_metadata(&serde_json::json!({ "runtime": {} }), &typed).unwrap();
        for policy in [serde_json::Value::Null, serde_json::json!({})] {
            assert!(validate_policy_metadata(&serde_json::json!({ "runtime": { "policy_artifact": policy } }), &typed).is_err());
        }
        let mut metadata =
            serde_json::json!({ "runtime": { "policy_artifact": policy_metadata_projection(&contract, &typed).unwrap() } });
        typed.foundation.entry_contract.dispatch = EntryDispatchContract::PolicyWitnessV1(contract);
        attach_builder_actions(&mut metadata, &typed);
        validate_policy_metadata(&metadata, &typed).unwrap();
        metadata["runtime"]["policy_artifact"]["declaration"]["common_checks"] = serde_json::json!([]);
        assert!(validate_policy_metadata(&metadata, &typed).is_err());
    }

    #[test]
    fn builder_parameter_encodings_are_derived_from_exact_typed_values_and_cells() {
        let (mut contract, mut typed) = fixture();
        let entry = entry_mut(&mut typed, "transfer");
        entry.params = [("before0", "Token", "input"), ("amount", "u64", "witness"), ("data", "(address, [u16; 5])", "witness")]
            .into_iter()
            .enumerate()
            .map(|(index, (name, ty, source))| TypedSemanticParam {
                index: index as u32,
                binding_id: index as u32,
                name: name.to_string(),
                ty: ty.to_string(),
                source: source.to_string(),
                mutable: false,
                reference: false,
            })
            .collect();
        entry.locals = entry
            .params
            .iter()
            .map(|param| TypedSemanticLocal {
                id: param.binding_id,
                source_id: u64::from(param.binding_id),
                name: param.name.clone(),
                ty: param.ty.clone(),
            })
            .collect();
        let input = entry.cell_bindings.iter_mut().find(|binding| binding.role == CellBindingRole::Input).unwrap();
        input.local_id = Some(0);
        let provenance = input.provenance(&entry.id);
        let id = canonical_hash("cellscript-value-provenance-node-v1", &provenance).unwrap();
        let provenance_binding = ProvenanceBinding { entry_id: entry.id.clone(), local_id: 0, node_id: id.clone() };
        entry.blocks.push(TypedSemanticBlock {
            operations: vec![TypedSemanticOperation {
                opcode: "type-hash".to_string(),
                operands: vec![TypedSemanticOperand { local: Some(0), ty: "Token".to_string(), ..Default::default() }],
                ..Default::default()
            }],
            ..Default::default()
        });
        contract.variants[1].payload_schema_hash = canonical_hash("cellscript-policy-variant-payload-v1", &entry.params).unwrap();
        typed.foundation.provenance.nodes.push(ProvenanceNode { id, provenance });
        typed.foundation.provenance.bindings.push(provenance_binding);
        typed.canonicalize();
        let mut metadata =
            serde_json::json!({ "runtime": { "policy_artifact": policy_metadata_projection(&contract, &typed).unwrap() } });
        typed.foundation.entry_contract.dispatch = EntryDispatchContract::PolicyWitnessV1(contract);
        attach_builder_actions(&mut metadata, &typed);
        let action_index = metadata["actions"].as_array().unwrap().iter().position(|action| action["name"] == "transfer").unwrap();
        // Public metadata's builtin spelling differs without changing its ABI.
        metadata["actions"][action_index]["params"][2]["ty"] = "(Address, [u16; 5])".into();
        validate_policy_metadata(&metadata, &typed).unwrap();
        let params = &metadata["actions"][action_index]["params"];
        assert_eq!(params[0]["cell_bound_abi"], true);
        assert_eq!(params[0]["type_hash_len"], 32);
        assert_eq!(params[1]["fixed_byte_len"], serde_json::Value::Null);
        assert_eq!(params[2]["fixed_byte_len"], 42);
        for mutation in [
            "name",
            "order",
            "type",
            "source",
            "mut",
            "ref",
            "cell-skip",
            "scalar-skip",
            "witness",
            "lock-args",
            "schema",
            "fixed-width",
            "fixed-flag",
            "hash-width",
            "hash-flag",
            "bounded",
            "duplicate-action",
            "missing-action",
        ] {
            let mut metadata = metadata.clone();
            let params = &mut metadata["actions"][action_index]["params"];
            match mutation {
                "name" => params[1]["name"] = "other".into(),
                "order" => params.as_array_mut().unwrap().swap(0, 1),
                "type" => params[1]["ty"] = "u128".into(),
                "source" => params[1]["source"] = "input".into(),
                "mut" => params[1]["is_mut"] = true.into(),
                "ref" => params[1]["is_ref"] = true.into(),
                "cell-skip" => params[0]["cell_bound_abi"] = false.into(),
                "scalar-skip" => params[1]["cell_bound_abi"] = true.into(),
                "witness" => params[1]["witness_data_source"] = false.into(),
                "lock-args" => params[1]["lock_args_data_source"] = true.into(),
                "schema" => params[1]["schema_pointer_abi"] = true.into(),
                "fixed-width" => params[2]["fixed_byte_len"] = 41.into(),
                "fixed-flag" => params[2]["fixed_byte_length_abi"] = false.into(),
                "hash-width" => params[0]["type_hash_len"] = 31.into(),
                "hash-flag" => params[0]["type_hash_pointer_abi"] = false.into(),
                "bounded" => params[0]["bounded_runtime_contract"] = "type-group-inputs-v1".into(),
                "duplicate-action" => {
                    let duplicate = metadata["actions"][action_index].clone();
                    metadata["actions"].as_array_mut().unwrap().push(duplicate);
                }
                "missing-action" => {
                    metadata["actions"].as_array_mut().unwrap().remove(action_index);
                }
                _ => unreachable!(),
            }
            assert_eq!(
                validate_policy_metadata(&metadata, &typed).unwrap_err().code,
                CheckerRejectionCode::V2410MetadataBindingMismatch,
                "{mutation}"
            );
        }
    }

    #[test]
    fn independent_builder_layout_covers_nested_aggregates_views_units_and_payload_enums() {
        let mut typed = TypedSemanticRecord::default();
        typed.types.push(TypedSemanticType {
            name: "Choice".to_string(),
            kind: "enum".to_string(),
            encoded_size: Some(9),
            variants: vec![TypedSemanticVariant {
                fields: vec![TypedSemanticVariantField { ty: "u64".to_string(), width_bytes: 8, ..Default::default() }],
                ..Default::default()
            }],
            ..Default::default()
        });
        for (ty, fixed, schema) in [
            ("unit", None, false),
            ("()", None, false),
            ("u64", None, false),
            ("u128", Some(16), false),
            ("address", Some(32), false),
            ("Hash", Some(32), false),
            ("[u8; 8]", None, false),
            ("[u16; 5]", Some(10), false),
            ("[[u64; 2]; 3]", Some(48), false),
            ("(u64, [Address; 2], ())", Some(72), false),
            ("Choice", Some(9), false),
            ("&Choice", Some(9), false),
            ("&mut [u8; 16]", Some(16), false),
            ("&[u16; 5]", None, false),
            ("Vec<u64>", None, true),
            ("Vec<(Hash, [u8; 8])>", None, true),
            ("String", None, true),
            ("Payload", None, true),
            ("&Payload", None, true),
        ] {
            let param = TypedSemanticParam {
                name: "value".to_string(),
                ty: ty.to_string(),
                source: "default".to_string(),
                ..Default::default()
            };
            let entry = TypedSemanticEntry::default();
            let projection = builder_parameter_projection(&param, &entry, &typed).unwrap();
            assert_eq!(projection["fixed_byte_len"], serde_json::json!(fixed), "{ty}");
            assert_eq!(projection["schema_pointer_abi"], schema, "{ty}");
            assert_eq!(projection["schema_length_abi"], schema, "{ty}");
        }
        assert_ne!(policy_abi_type("&mut Token", 0).unwrap(), policy_abi_type("&mutToken", 0).unwrap());
        assert!(policy_abi_type("[u8; 4)", 0).is_err());
        assert!(policy_abi_type("Vec<(u64]>", 0).is_err());
    }

    #[test]
    fn read_dependencies_and_script_args_have_exact_source_and_skip_flags() {
        let mut typed = TypedSemanticRecord::default();
        let mut payload = schema("Payload");
        payload.kind = "struct".to_string();
        typed.types.push(payload);
        let mut entry = TypedSemanticEntry::default();
        entry.cell_bindings.push(TypedSemanticCellBinding {
            binding: "config".to_string(),
            role: CellBindingRole::ReadOnly,
            local_id: Some(2),
            ty: "Payload".to_string(),
            source: CellBindingSource::CellDep,
            ordinal: 0,
            membership: CellBindingMembership::Unproven,
        });
        let read = TypedSemanticParam {
            binding_id: 2,
            name: "config".to_string(),
            ty: "&Payload".to_string(),
            source: "default".to_string(),
            reference: true,
            ..Default::default()
        };
        let projection = builder_parameter_projection(&read, &entry, &typed).unwrap();
        assert_eq!(projection["source"], "read");
        assert_eq!(projection["is_ref"], false);
        assert_eq!(projection["cell_bound_abi"], true);
        assert_eq!(projection["schema_pointer_abi"], true);
        let args = TypedSemanticParam {
            name: "owner".to_string(),
            ty: "address".to_string(),
            source: "lockargs".to_string(),
            ..Default::default()
        };
        let projection = builder_parameter_projection(&args, &entry, &typed).unwrap();
        assert_eq!(projection["source"], "lock_args");
        assert_eq!(projection["lock_args_data_source"], true);
        assert_eq!(projection["cell_bound_abi"], false);
        assert_eq!(projection["fixed_byte_len"], 32);
    }
}
