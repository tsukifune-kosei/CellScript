use crate::ast::*;
use crate::error::{CompileError, Result, Span};
use crate::resolve::{FunctionDef, ModuleResolver, TypeDef};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallableKind {
    Action,
    Function,
    Invariant,
    Lock,
}

#[derive(Debug, Clone)]
struct FunctionSignature {
    params: Vec<Type>,
    return_type: Option<Type>,
    kind: CallableKind,
    effect: EffectClass,
}

#[derive(Debug, Clone)]
struct MatchPayloadBindings {
    bindings: Vec<(String, Type)>,
}

#[derive(Debug, Clone)]
struct MatchPatternAnalysis {
    bindings: Vec<(String, Type)>,
    covered_variants: Vec<String>,
    irrefutable: bool,
}

#[derive(Debug, Clone)]
struct MatchConstructor {
    name: String,
    fields: Vec<(Option<String>, Type)>,
}

const MATCH_EXHAUSTIVENESS_BUDGET: usize = 4096;

#[derive(Debug, Clone)]
struct FlowSpec {
    type_name: String,
    field_name: String,
    field_enum_type: Option<String>,
    states: Vec<String>,
    transitions: Vec<StateTransition>,
}

#[derive(Debug, Clone)]
struct ActionOutputBinding {
    type_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CellTypeKind {
    Resource,
    Shared,
    Receipt,
}

pub struct TypeEnv {
    vars: HashMap<String, Type>,
    mutability: HashMap<String, bool>,
    linear_states: HashMap<String, LinearState>,
    parent: Option<Box<TypeEnv>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinearState {
    Available,
    Consumed,
    Transferred,
    Destroyed,
}

impl Default for TypeEnv {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeEnv {
    pub fn new() -> Self {
        Self { vars: HashMap::new(), mutability: HashMap::new(), linear_states: HashMap::new(), parent: None }
    }

    pub fn child(&self) -> Self {
        Self { vars: HashMap::new(), mutability: HashMap::new(), linear_states: HashMap::new(), parent: Some(Box::new(self.clone())) }
    }

    pub fn lookup(&self, name: &str) -> Option<&Type> {
        self.vars.get(name).or_else(|| self.parent.as_ref().and_then(|p| p.lookup(name)))
    }

    pub fn is_mutable(&self, name: &str) -> bool {
        self.mutability.get(name).copied().or_else(|| self.parent.as_ref().map(|p| p.is_mutable(name))).unwrap_or(false)
    }

    pub fn insert(&mut self, name: String, ty: Type, is_linear: bool, is_mut: bool) {
        self.vars.insert(name.clone(), ty);
        self.mutability.insert(name.clone(), is_mut);
        if is_linear {
            self.linear_states.insert(name, LinearState::Available);
        } else {
            self.linear_states.remove(&name);
        }
    }

    fn bind_new(&mut self, name: String, ty: Type, is_linear: bool, is_mut: bool, span: Span) -> Result<()> {
        if self.lookup(&name).is_some() {
            return Err(CompileError::new(format!("binding '{}' already exists in this scope or an outer scope", name), span));
        }
        self.insert(name, ty, is_linear, is_mut);
        Ok(())
    }

    fn update_type(&mut self, name: &str, ty: Type) -> bool {
        if self.vars.contains_key(name) {
            self.vars.insert(name.to_string(), ty);
            true
        } else {
            self.parent.as_mut().map(|parent| parent.update_type(name, ty)).unwrap_or(false)
        }
    }

    fn merge_existing_type_refinements_from(&mut self, other: &TypeEnv) {
        let names = self.vars.keys().cloned().collect::<Vec<_>>();
        for name in names {
            if let Some(ty) = other.lookup(&name).cloned() {
                self.vars.insert(name, ty);
            }
        }
        if let Some(parent) = self.parent.as_mut() {
            parent.merge_existing_type_refinements_from(other);
        }
    }

    fn merge_existing_linear_states_from(&mut self, other: &TypeEnv) {
        for name in self.linear_names() {
            if let Some(state) = other.linear_state(&name) {
                self.set_existing_linear_state(&name, state);
            }
        }
    }

    pub fn consume(&mut self, name: &str) -> Result<()> {
        self.set_linear_state(name, LinearState::Consumed)
    }

    pub fn transfer(&mut self, name: &str) -> Result<()> {
        self.set_linear_state(name, LinearState::Transferred)
    }

    pub fn destroy(&mut self, name: &str) -> Result<()> {
        self.set_linear_state(name, LinearState::Destroyed)
    }

    fn set_linear_state(&mut self, name: &str, next: LinearState) -> Result<()> {
        match self.linear_states.get_mut(name) {
            Some(state) => {
                if *state != LinearState::Available {
                    return Err(CompileError::new(format!("resource '{}' already {:?}", name, state), Span::default()));
                }
                *state = next;
                Ok(())
            }
            None => {
                if let Some(ref mut parent) = self.parent {
                    parent.set_linear_state(name, next)
                } else {
                    Err(CompileError::new(format!("unknown resource '{}'", name), Span::default()))
                }
            }
        }
    }

    fn linear_state(&self, name: &str) -> Option<LinearState> {
        self.linear_states.get(name).copied().or_else(|| self.parent.as_ref().and_then(|parent| parent.linear_state(name)))
    }

    fn linear_names(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut names = Vec::new();
        self.collect_linear_names(&mut seen, &mut names);
        names
    }

    fn collect_linear_names(&self, seen: &mut HashSet<String>, names: &mut Vec<String>) {
        if let Some(parent) = &self.parent {
            parent.collect_linear_names(seen, names);
        }
        for name in self.linear_states.keys() {
            if seen.insert(name.clone()) {
                names.push(name.clone());
            }
        }
    }

    fn set_existing_linear_state(&mut self, name: &str, next: LinearState) {
        if let Some(state) = self.linear_states.get_mut(name) {
            *state = next;
        } else if let Some(parent) = self.parent.as_mut() {
            parent.set_existing_linear_state(name, next);
        }
    }

    fn merge_branch_linear_states(
        &mut self,
        then_env: &TypeEnv,
        then_returns: bool,
        else_env: Option<&TypeEnv>,
        else_returns: bool,
        span: Span,
    ) -> Result<()> {
        for name in self.linear_names() {
            let before = self.linear_state(&name).unwrap_or(LinearState::Available);
            let then_state = then_env.linear_state(&name).unwrap_or(before);
            let else_state = else_env.and_then(|env| env.linear_state(&name)).unwrap_or(before);

            let merged = match (then_returns, else_env.is_some(), else_returns) {
                (true, _, true) if then_state == else_state => then_state,
                (true, true, false) => else_state,
                (false, true, true) => then_state,
                (false, true, false) if then_state == else_state => then_state,
                (false, false, _) if then_state == before => before,
                _ => {
                    return Err(CompileError::new(
                        format!("linear resource '{}' has inconsistent ownership state across if branches", name),
                        span,
                    ));
                }
            };

            self.set_existing_linear_state(&name, merged);
        }
        Ok(())
    }

    fn merge_match_linear_states(&mut self, arm_envs: &[TypeEnv], span: Span) -> Result<()> {
        let Some(first_env) = arm_envs.first() else {
            return Ok(());
        };

        for name in self.linear_names() {
            let before = self.linear_state(&name).unwrap_or(LinearState::Available);
            let first_state = first_env.linear_state(&name).unwrap_or(before);
            if arm_envs.iter().skip(1).any(|env| env.linear_state(&name).unwrap_or(before) != first_state) {
                return Err(CompileError::new(
                    format!("linear resource '{}' has inconsistent ownership state across match arms", name),
                    span,
                ));
            }
            self.set_existing_linear_state(&name, first_state);
        }
        Ok(())
    }

    fn reject_loop_linear_state_changes(&self, loop_env: &TypeEnv, span: Span) -> Result<()> {
        for name in self.linear_names() {
            let before = self.linear_state(&name).unwrap_or(LinearState::Available);
            let after = loop_env.linear_state(&name).unwrap_or(before);
            if after != before {
                return Err(CompileError::new(
                    format!("linear resource '{}' cannot change ownership state inside a loop body", name),
                    span,
                ));
            }
        }
        Ok(())
    }

    pub fn check_linear_complete(&self) -> Result<()> {
        for (name, state) in &self.linear_states {
            if *state == LinearState::Available {
                return Err(CompileError::new(
                    format!("linear resource '{}' was not consumed, transferred, or destroyed", name),
                    Span::default(),
                ));
            }
        }
        Ok(())
    }
}

impl Clone for TypeEnv {
    fn clone(&self) -> Self {
        Self {
            vars: self.vars.clone(),
            mutability: self.mutability.clone(),
            linear_states: self.linear_states.clone(),
            parent: self.parent.as_ref().map(|p| Box::new((**p).clone())),
        }
    }
}

pub struct TypeChecker<'a> {
    env: TypeEnv,
    type_fields: HashMap<String, HashMap<String, Type>>,
    enum_variants: HashMap<String, Vec<String>>,
    enum_payload_variants: HashMap<String, HashSet<String>>,
    enum_variant_fields: HashMap<String, HashMap<String, Vec<Type>>>,
    functions: HashMap<String, FunctionSignature>,
    linear_types: HashSet<String>,
    cell_type_kinds: HashMap<String, CellTypeKind>,
    type_capabilities: HashMap<String, HashSet<Capability>>,
    type_identities: HashMap<String, IdentityPolicy>,
    receipt_claim_outputs: HashMap<String, Option<Type>>,
    flow_states: HashMap<String, Vec<String>>,
    flow_state_fields: HashMap<String, String>,
    flows: HashMap<String, FlowSpec>,
    constants: HashMap<String, ConstDef>,
    resolver: Option<&'a ModuleResolver>,
    current_module: Option<String>,
    current_callable: Option<CallableKind>,
    current_return_type: Option<Option<Type>>,
    current_validity: bool,
    active_borrows: Vec<ActiveBorrow>,
    loop_labels: Vec<Option<String>>,
}

#[derive(Debug, Clone)]
struct ActiveBorrow {
    root: String,
    binding: String,
    root_ty: Type,
}

#[derive(Debug, Clone, Default)]
struct SpawnIpcFdState {
    aliases: HashMap<String, String>,
    closed: HashSet<String>,
    pipe_tuples: HashMap<String, (String, String)>,
}

fn function_def_kind(function: &FunctionDef) -> CallableKind {
    match function {
        FunctionDef::Action(_) => CallableKind::Action,
        FunctionDef::Function(_) => CallableKind::Function,
        FunctionDef::Lock(_) => CallableKind::Lock,
    }
}

fn function_def_param_types(function: &FunctionDef) -> Vec<Type> {
    match function {
        FunctionDef::Action(action) => action.params.iter().map(|param| param.ty.clone()).collect(),
        FunctionDef::Function(function) => function.params.iter().map(|param| param.ty.clone()).collect(),
        FunctionDef::Lock(lock) => lock.params.iter().map(|param| param.ty.clone()).collect(),
    }
}

fn function_def_effect(function: &FunctionDef) -> EffectClass {
    match function {
        FunctionDef::Action(action) => action.effect,
        FunctionDef::Function(function) => function.effect,
        FunctionDef::Lock(_) => EffectClass::ReadOnly,
    }
}

fn type_repr(ty: &Type) -> String {
    match ty {
        Type::U8 => "u8".to_string(),
        Type::U16 => "u16".to_string(),
        Type::U32 => "u32".to_string(),
        Type::I32 => "i32".to_string(),
        Type::U64 => "u64".to_string(),
        Type::U128 => "u128".to_string(),
        Type::Bool => "bool".to_string(),
        Type::Unit => "()".to_string(),
        Type::Address => "Address".to_string(),
        Type::Hash => "Hash".to_string(),
        Type::Array(inner, size) => format!("[{}; {}]", type_repr(inner), size),
        Type::Tuple(items) => format!("({})", items.iter().map(type_repr).collect::<Vec<_>>().join(", ")),
        Type::Named(name) => name.clone(),
        Type::Ref(inner) => format!("&{}", type_repr(inner)),
        Type::MutRef(inner) => format!("&mut {}", type_repr(inner)),
    }
}

const CKB_LOCK_SCRIPT_REF_TYPE: &str = "__ckb_lock_script_ref";
const CKB_TYPE_SCRIPT_REF_TYPE: &str = "__ckb_type_script_ref";
const CKB_SCRIPT_ARGS_TYPE: &str = "ScriptArgs";
const CKB_SCRIPT_VALUE_TYPE: &str = "Script";
const CKB_INPUT_VIEW_TYPE: &str = "InputView";
const CKB_OUTPUT_VIEW_TYPE: &str = "OutputView";
const CKB_CELL_DEP_VIEW_TYPE: &str = "CellDepView";
const CKB_HEADER_DEP_VIEW_TYPE: &str = "HeaderDepView";
const CKB_WITNESS_ARGS_VIEW_TYPE: &str = "WitnessArgsView";
const CKB_OUT_POINT_TYPE: &str = "OutPoint";
const CKB_SCRIPT_VIEW_TYPE: &str = "ScriptView";
const CKB_SCRIPT_HASH_TYPE: &str = "ScriptHash";
const CKB_EPOCH_NUMBER_TYPE: &str = "EpochNumber";
const CKB_BLOCK_NUMBER_TYPE: &str = "BlockNumber";
const CKB_EPOCH_LENGTH_TYPE: &str = "EpochLength";
const CKB_ENCODED_SINCE_TYPE: &str = "EncodedSince";
const CKB_ABSOLUTE_EPOCH_SINCE_TYPE: &str = "AbsoluteEpochSince";
const CKB_RELATIVE_EPOCH_SINCE_TYPE: &str = "RelativeEpochSince";

fn param_source_repr(source: ParamSource) -> &'static str {
    match source {
        ParamSource::Default => "default",
        ParamSource::Input => "input",
        ParamSource::Output => "output",
        ParamSource::Protected => "protected",
        ParamSource::Witness => "witness",
        ParamSource::LockArgs => "lock_args",
    }
}

fn type_def_type_id(type_def: &TypeDef) -> Option<&TypeIdentity> {
    match type_def {
        TypeDef::Resource(resource) => resource.type_id.as_ref(),
        TypeDef::Shared(shared) => shared.type_id.as_ref(),
        TypeDef::Receipt(receipt) => receipt.type_id.as_ref(),
        TypeDef::Struct(struct_def) => struct_def.type_id.as_ref(),
        TypeDef::Enum(_) => None,
    }
}

fn register_type_id_value(seen: &mut HashMap<String, Span>, type_name: &str, value: &str, span: Span) -> Result<()> {
    if seen.insert(value.to_string(), span).is_some() {
        return Err(CompileError::new(format!("duplicate type_id '{}' on type '{}'", value, type_name), span));
    }
    Ok(())
}

fn register_type_id(seen: &mut HashMap<String, Span>, type_name: &str, type_id: Option<&TypeIdentity>) -> Result<()> {
    let Some(type_id) = type_id else {
        return Ok(());
    };
    register_type_id_value(seen, type_name, &type_id.value, type_id.span)
}

impl Default for TypeChecker<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> TypeChecker<'a> {
    pub fn new() -> Self {
        Self {
            env: TypeEnv::new(),
            type_fields: HashMap::new(),
            enum_variants: HashMap::new(),
            enum_payload_variants: HashMap::new(),
            enum_variant_fields: HashMap::new(),
            functions: HashMap::new(),
            linear_types: HashSet::new(),
            cell_type_kinds: HashMap::new(),
            type_capabilities: HashMap::new(),
            type_identities: HashMap::new(),
            receipt_claim_outputs: HashMap::new(),
            flow_states: HashMap::new(),
            flow_state_fields: HashMap::new(),
            flows: HashMap::new(),
            constants: HashMap::new(),
            resolver: None,
            current_module: None,
            current_callable: None,
            current_return_type: None,
            current_validity: false,
            active_borrows: Vec::new(),
            loop_labels: Vec::new(),
        }
    }

    pub fn with_resolver(resolver: &'a ModuleResolver, current_module: impl Into<String>) -> Self {
        let mut checker = Self::new();
        checker.resolver = Some(resolver);
        checker.current_module = Some(current_module.into());
        checker
    }

    pub fn check_module(&mut self, module: &Module) -> Result<()> {
        let diagnostics = self.check_module_diagnostics(module);
        match diagnostics.into_iter().next() {
            Some(error) => Err(error),
            _ => Ok(()),
        }
    }

    pub fn check_module_diagnostics(&mut self, module: &Module) -> Vec<CompileError> {
        let mut diagnostics = Vec::new();
        if self.current_module.is_none() {
            self.current_module = Some(module.name.clone());
        }
        let mut seen_symbols = HashSet::new();
        let mut seen_type_ids = HashMap::new();
        for item in &module.items {
            if let Some((symbol, span)) = item_symbol_name_and_span(item)
                && !seen_symbols.insert(symbol.to_string())
            {
                diagnostics.push(CompileError::new(format!("duplicate symbol '{}'", symbol), span));
            }
            match item {
                Item::Const(const_def) => {
                    if let Err(error) = self.validate_type(&const_def.ty) {
                        diagnostics.push(error);
                    }
                    self.env.insert(const_def.name.clone(), const_def.ty.clone(), false, false);
                    self.constants.insert(const_def.name.clone(), const_def.clone());
                }
                Item::Resource(resource) => {
                    if let Err(error) = register_type_id(&mut seen_type_ids, &resource.name, resource.type_id.as_ref()) {
                        diagnostics.push(error);
                    }
                    self.linear_types.insert(resource.name.clone());
                    self.cell_type_kinds.insert(resource.name.clone(), CellTypeKind::Resource);
                    self.type_capabilities.insert(resource.name.clone(), resource.capabilities.iter().copied().collect());
                    self.type_identities.insert(resource.name.clone(), resource.identity.clone());
                    self.type_fields.insert(
                        resource.name.clone(),
                        resource.fields.iter().map(|field| (field.name.clone(), field.ty.clone())).collect(),
                    );
                }
                Item::Shared(shared) => {
                    if let Err(error) = register_type_id(&mut seen_type_ids, &shared.name, shared.type_id.as_ref()) {
                        diagnostics.push(error);
                    }
                    self.linear_types.insert(shared.name.clone());
                    self.cell_type_kinds.insert(shared.name.clone(), CellTypeKind::Shared);
                    self.type_capabilities.insert(shared.name.clone(), shared.capabilities.iter().copied().collect());
                    self.type_identities.insert(shared.name.clone(), shared.identity.clone());
                    self.type_fields.insert(
                        shared.name.clone(),
                        shared.fields.iter().map(|field| (field.name.clone(), field.ty.clone())).collect(),
                    );
                }
                Item::Receipt(receipt) => {
                    if let Err(error) = register_type_id(&mut seen_type_ids, &receipt.name, receipt.type_id.as_ref()) {
                        diagnostics.push(error);
                    }
                    self.linear_types.insert(receipt.name.clone());
                    self.cell_type_kinds.insert(receipt.name.clone(), CellTypeKind::Receipt);
                    self.type_capabilities.insert(receipt.name.clone(), receipt.capabilities.iter().copied().collect());
                    self.type_identities.insert(receipt.name.clone(), receipt.identity.clone());
                    self.receipt_claim_outputs.insert(receipt.name.clone(), receipt.claim_output.clone());
                    self.type_fields.insert(
                        receipt.name.clone(),
                        receipt.fields.iter().map(|field| (field.name.clone(), field.ty.clone())).collect(),
                    );
                }
                Item::Struct(struct_def) => {
                    if let Err(error) = register_type_id(&mut seen_type_ids, &struct_def.name, struct_def.type_id.as_ref()) {
                        diagnostics.push(error);
                    }
                    self.type_fields.insert(
                        struct_def.name.clone(),
                        struct_def.fields.iter().map(|field| (field.name.clone(), field.ty.clone())).collect(),
                    );
                }
                Item::Invariant(_) => {}
                Item::Enum(enum_def) => {
                    self.enum_variants
                        .insert(enum_def.name.clone(), enum_def.variants.iter().map(|variant| variant.name.clone()).collect());
                    self.enum_payload_variants.insert(
                        enum_def.name.clone(),
                        enum_def
                            .variants
                            .iter()
                            .filter(|variant| !variant.fields.is_empty())
                            .map(|variant| variant.name.clone())
                            .collect(),
                    );
                    self.enum_variant_fields.insert(
                        enum_def.name.clone(),
                        enum_def.variants.iter().map(|variant| (variant.name.clone(), variant.fields.clone())).collect(),
                    );
                }
                Item::Action(action) => {
                    self.functions.insert(
                        action.name.clone(),
                        FunctionSignature {
                            params: action.params.iter().map(|param| param.ty.clone()).collect(),
                            return_type: action.return_type.clone(),
                            kind: CallableKind::Action,
                            effect: action.effect,
                        },
                    );
                }
                Item::Function(function) => {
                    self.functions.insert(
                        function.name.clone(),
                        FunctionSignature {
                            params: function.params.iter().map(|param| param.ty.clone()).collect(),
                            return_type: function.return_type.clone(),
                            kind: CallableKind::Function,
                            effect: function.effect,
                        },
                    );
                }
                Item::Lock(lock) => {
                    self.functions.insert(
                        lock.name.clone(),
                        FunctionSignature {
                            params: lock.params.iter().map(|param| param.ty.clone()).collect(),
                            return_type: Some(Type::Bool),
                            kind: CallableKind::Lock,
                            effect: EffectClass::ReadOnly,
                        },
                    );
                }
                Item::Flow(_) => {}
                Item::Use(_) => {}
            }
        }

        if let Err(error) = self.register_imported_type_ids(&mut seen_type_ids) {
            diagnostics.push(error);
        }
        if let Err(error) = self.register_flows(module) {
            diagnostics.push(error);
        }
        if let Err(error) = self.validate_flow_action_edges(module) {
            diagnostics.push(error);
        }

        for item in &module.items {
            diagnostics.extend(self.check_item_diagnostics(item));
        }
        diagnostics
    }

    fn register_imported_type_ids(&self, seen_type_ids: &mut HashMap<String, Span>) -> Result<()> {
        let (Some(resolver), Some(module_name)) = (self.resolver, self.current_module.as_deref()) else {
            return Ok(());
        };

        for import in resolver.imports_for_module(module_name) {
            let local_name = import.alias.as_deref().unwrap_or(&import.name);
            let Some(type_def) = resolver.resolve_type(module_name, local_name) else {
                continue;
            };
            if let Some(type_id) = type_def_type_id(&type_def) {
                register_type_id_value(seen_type_ids, local_name, &type_id.value, import.span)?;
            }
        }

        Ok(())
    }

    fn register_flows(&mut self, module: &Module) -> Result<()> {
        let mut seen_targets = HashSet::new();
        for item in &module.items {
            let Item::Flow(machine) = item else {
                continue;
            };
            if machine.transitions.is_empty() {
                return Err(CompileError::new("flow must declare at least one transition", machine.span));
            }
            let type_name = machine.target.base.clone();
            let field_name = machine.target.field.clone();
            let target_key = format!("{}.{}", type_name, field_name);
            if !seen_targets.insert(target_key.clone()) {
                return Err(CompileError::new(format!("duplicate flow for '{}'", target_key), machine.target.span));
            }
            if self.flow_states.contains_key(&type_name) {
                return Err(CompileError::new(
                    format!(
                        "type '{}' already has flow policy; this release supports one flow-backed state field per Cell type",
                        type_name
                    ),
                    machine.target.span,
                ));
            }
            if self.resolve_cell_type_kind(&type_name).is_none() {
                return Err(CompileError::new(
                    format!("flow target type '{}' must be a resource, shared, or receipt Cell type", type_name),
                    machine.target.span,
                ));
            }

            let fields = self
                .resolve_named_type_fields(&type_name)
                .ok_or_else(|| CompileError::new(format!("flow target type '{}' is not defined", type_name), machine.target.span))?;
            let field_ty = fields.get(&field_name).ok_or_else(|| {
                CompileError::new(format!("flow target field '{}.{}' is not defined", type_name, field_name), machine.target.span)
            })?;

            let (states, field_enum_type) = self.flow_states_for_decl(machine, field_ty)?;
            let has_terminal_contract = !machine.initial_states.is_empty() || !machine.terminal_states.is_empty();
            let (_initial_state, terminal_states) = if has_terminal_contract {
                if machine.initial_states.len() != 1 {
                    return Err(CompileError::new(
                        format!(
                            "flow '{}.{}' must declare exactly one initial state; found {}",
                            type_name,
                            field_name,
                            machine.initial_states.len()
                        ),
                        machine.span,
                    ));
                }
                if machine.terminal_states.is_empty() {
                    return Err(CompileError::new(
                        format!("flow '{}.{}' must declare at least one terminal state", type_name, field_name),
                        machine.span,
                    ));
                }
                let initial = self.canonical_state_name_for_flow(
                    &type_name,
                    field_enum_type.as_deref(),
                    &states,
                    &machine.initial_states[0],
                    machine.span,
                )?;
                let mut terminals = Vec::new();
                for raw_terminal in &machine.terminal_states {
                    let terminal = self.canonical_state_name_for_flow(
                        &type_name,
                        field_enum_type.as_deref(),
                        &states,
                        raw_terminal,
                        machine.span,
                    )?;
                    if !terminals.iter().any(|existing| existing == &terminal) {
                        terminals.push(terminal);
                    } else {
                        return Err(CompileError::new(format!("duplicate terminal state '{}'", terminal), machine.span));
                    }
                }
                if terminals.iter().any(|terminal| terminal == &initial) {
                    return Err(CompileError::new(
                        format!("flow state '{}' cannot be both initial and terminal", initial),
                        machine.span,
                    ));
                }
                (Some(initial), terminals)
            } else {
                (None, Vec::new())
            };
            let mut seen_transitions = HashSet::new();
            let mut normalized_transitions = Vec::new();
            for transition in &machine.transitions {
                let from = self.canonical_state_name_for_flow(
                    &type_name,
                    field_enum_type.as_deref(),
                    &states,
                    &transition.from,
                    transition.span,
                )?;
                let to = self.canonical_state_name_for_flow(
                    &type_name,
                    field_enum_type.as_deref(),
                    &states,
                    &transition.to,
                    transition.span,
                )?;
                if !seen_transitions.insert((from.clone(), to.clone())) {
                    return Err(CompileError::new(format!("duplicate state transition '{} -> {}'", from, to), transition.span));
                }
                if terminal_states.iter().any(|terminal| terminal == &from) {
                    return Err(CompileError::new(
                        format!("terminal state '{}' cannot have an outgoing transition", from),
                        transition.span,
                    ));
                }
                if let Some(action) = &transition.action {
                    match self.functions.get(action) {
                        Some(signature) if signature.kind == CallableKind::Action => {}
                        Some(_) => {
                            return Err(CompileError::new(
                                format!("state transition action '{}' is not an action", action),
                                transition.span,
                            ))
                        }
                        None => {
                            return Err(CompileError::new(
                                format!("state transition action '{}' is not defined", action),
                                transition.span,
                            ))
                        }
                    }
                }
                normalized_transitions.push(StateTransition { from, to, action: transition.action.clone(), span: transition.span });
            }

            self.flow_states.insert(type_name.clone(), states.clone());
            self.flow_state_fields.insert(type_name.clone(), field_name.clone());
            self.flows.insert(
                type_name.clone(),
                FlowSpec { type_name, field_name, field_enum_type, states, transitions: normalized_transitions },
            );
        }

        Ok(())
    }

    fn validate_flow_action_edges(&self, module: &Module) -> Result<()> {
        let actions = module
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Action(action) => Some((action.name.as_str(), action)),
                _ => None,
            })
            .collect::<HashMap<_, _>>();

        for spec in self.flows.values() {
            for transition in &spec.transitions {
                let Some(action_name) = &transition.action else {
                    continue;
                };
                let Some(action) = actions.get(action_name.as_str()).copied() else {
                    continue;
                };
                let has_exact_move = action.state_edges.iter().any(|state_edge| {
                    let from_path = &state_edge.path;
                    let to_path = &state_edge.to_path;
                    from_path.field == spec.field_name
                        && to_path.field == spec.field_name
                        && action_param_owned_named_type(action, &from_path.base).is_some_and(|ty| ty == spec.type_name)
                        && action_param_output_named_type(action, &to_path.base).is_some_and(|ty| ty == spec.type_name)
                        && self
                            .canonical_state_name_for_flow(
                                &spec.type_name,
                                spec.field_enum_type.as_deref(),
                                &spec.states,
                                &state_edge.from,
                                state_edge.span,
                            )
                            .ok()
                            .is_some_and(|from| from == transition.from)
                        && self
                            .canonical_state_name_for_flow(
                                &spec.type_name,
                                spec.field_enum_type.as_deref(),
                                &spec.states,
                                &state_edge.to,
                                state_edge.span,
                            )
                            .ok()
                            .is_some_and(|to| to == transition.to)
                });
                if !has_exact_move {
                    return Err(CompileError::new(
                        format!(
                            "state transition action '{}' is bound to '{}.{} {} -> {}' and must declare the exact field-to-field transition",
                            action.name, spec.type_name, spec.field_name, transition.from, transition.to
                        ),
                        transition.span,
                    ));
                }
            }
        }

        Ok(())
    }

    fn flow_states_for_decl(&self, machine: &FlowDef, field_ty: &Type) -> Result<(Vec<String>, Option<String>)> {
        if let Type::Named(enum_name) = field_ty
            && let Some(variants) = self.resolve_enum_variants(enum_name)
        {
            if variants.iter().any(|variant| self.enum_variant_has_payload(enum_name, variant)) {
                return Err(CompileError::new(
                    format!(
                        "flow field '{}.{}' enum '{}' must not have payload variants",
                        machine.target.base, machine.target.field, enum_name
                    ),
                    machine.target.span,
                ));
            }
            for transition in &machine.transitions {
                self.canonical_state_name_for_flow(
                    &machine.target.base,
                    Some(enum_name),
                    &variants,
                    &transition.from,
                    transition.span,
                )?;
                self.canonical_state_name_for_flow(&machine.target.base, Some(enum_name), &variants, &transition.to, transition.span)?;
            }
            return Ok((variants, Some(enum_name.clone())));
        }

        if !is_state_storage_type(field_ty) {
            return Err(CompileError::new(
                format!(
                    "flow field '{}.{}' must be an unsigned integer or no-payload enum",
                    machine.target.base, machine.target.field
                ),
                machine.target.span,
            ));
        }

        let mut states = Vec::new();
        for transition in &machine.transitions {
            for raw in [&transition.from, &transition.to] {
                let state = raw.rsplit_once("::").map_or(raw.as_str(), |(_, state)| state).to_string();
                if !states.iter().any(|existing| existing == &state) {
                    states.push(state);
                }
            }
        }
        if states.len() < 2 {
            return Err(CompileError::new("flow must mention at least two states", machine.span));
        }
        Ok((states, None))
    }

    fn canonical_state_name_for_flow(
        &self,
        type_name: &str,
        enum_name: Option<&str>,
        states: &[String],
        raw: &str,
        span: Span,
    ) -> Result<String> {
        let state = if let Some((qualifier, state)) = raw.rsplit_once("::") {
            if qualifier != type_name && Some(qualifier) != enum_name {
                return Err(CompileError::new(format!("state '{}' does not belong to '{}'", raw, type_name), span));
            }
            state
        } else {
            raw
        };
        if states.iter().any(|candidate| candidate == state) {
            Ok(state.to_string())
        } else {
            Err(CompileError::new(format!("unknown state '{}::{}'", type_name, state), span))
        }
    }

    fn check_item(&mut self, item: &Item) -> Result<()> {
        match item {
            Item::Resource(r) => self.check_resource(r),
            Item::Shared(s) => self.check_shared(s),
            Item::Receipt(r) => self.check_receipt(r),
            Item::Struct(s) => self.check_struct(s),
            Item::Flow(_) => Ok(()),
            Item::Invariant(i) => self.check_invariant(i),
            Item::Const(c) => self.check_const(c),
            Item::Enum(e) => self.check_enum(e),
            Item::Action(a) => self.check_action(a),
            Item::Function(f) => self.check_function(f),
            Item::Lock(l) => self.check_lock(l),
            Item::Use(_) => Ok(()),
        }
    }

    fn check_item_diagnostics(&mut self, item: &Item) -> Vec<CompileError> {
        match item {
            Item::Action(action) => self.check_action_diagnostics(action),
            Item::Function(function) => self.check_function_diagnostics(function),
            Item::Lock(lock) => self.check_lock_diagnostics(lock),
            _ => self.check_item(item).err().into_iter().collect(),
        }
    }

    fn check_resource(&mut self, resource: &ResourceDef) -> Result<()> {
        self.validate_capability_set(&resource.name, &resource.capabilities, resource.span)?;
        self.validate_schema_fields(&resource.fields, "resource", &resource.name)?;
        self.check_type_validity(&resource.name, &resource.fields, resource.validity.as_ref())
    }

    fn check_shared(&mut self, shared: &SharedDef) -> Result<()> {
        self.validate_capability_set(&shared.name, &shared.capabilities, shared.span)?;
        self.validate_schema_fields(&shared.fields, "shared", &shared.name)?;
        self.check_type_validity(&shared.name, &shared.fields, shared.validity.as_ref())
    }

    fn check_receipt(&mut self, receipt: &ReceiptDef) -> Result<()> {
        self.validate_capability_set(&receipt.name, &receipt.capabilities, receipt.span)?;
        self.validate_schema_fields(&receipt.fields, "receipt", &receipt.name)?;
        if let Some(output) = &receipt.claim_output {
            self.validate_type(output)?;
            self.validate_receipt_claim_output(output, receipt.span)?;
        }
        self.check_type_validity(&receipt.name, &receipt.fields, receipt.validity.as_ref())
    }

    fn validate_capability_set(&self, type_name: &str, capabilities: &[Capability], span: Span) -> Result<()> {
        let mut seen = HashSet::new();
        for capability in capabilities {
            if !seen.insert(*capability) {
                return Err(CompileError::new(
                    format!(
                        "type '{}' repeats canonical capability '{}' (capability-set version {})",
                        type_name,
                        capability.as_str(),
                        Capability::REGISTRY_VERSION
                    ),
                    span,
                ));
            }
        }
        Ok(())
    }

    fn check_struct(&mut self, struct_def: &StructDef) -> Result<()> {
        self.validate_schema_fields(&struct_def.fields, "struct", &struct_def.name)?;
        self.check_type_validity(&struct_def.name, &struct_def.fields, struct_def.validity.as_ref())
    }

    fn check_type_validity(&mut self, type_name: &str, fields: &[Field], validity: Option<&ValidityBlock>) -> Result<()> {
        let Some(validity) = validity else {
            return Ok(());
        };
        let mut env = self.env.child();
        for field in fields {
            env.insert(field.name.clone(), field.ty.clone(), false, false);
        }
        let previous_callable = self.current_callable.replace(CallableKind::Invariant);
        let previous_validity = std::mem::replace(&mut self.current_validity, true);
        let result = (|| {
            for predicate in &validity.predicates {
                let Expr::Require(require) = predicate else {
                    return Err(CompileError::new(
                        format!("validity block for '{}' contains non-require syntax", type_name),
                        predicate.span(),
                    ));
                };
                Self::validate_require_condition_is_pure(&require.condition, "validity predicate")?;
                Self::validate_validity_surface(&require.condition)?;
                let ty = self.infer_expr(&mut env, &require.condition)?;
                if !self.is_bool_type(&ty) {
                    return Err(CompileError::new(format!("validity predicate for '{}' must be boolean", type_name), require.span));
                }
                if let Some(message) = &require.message
                    && !matches!(message.as_ref(), Expr::String(_))
                {
                    return Err(CompileError::new("validity require message must be a string literal", expr_span(message)));
                }
            }
            Ok(())
        })();
        self.current_callable = previous_callable;
        self.current_validity = previous_validity;
        result
    }

    fn validate_validity_surface(expr: &Expr) -> Result<()> {
        match expr {
            Expr::Call(call) => {
                if let Expr::Identifier(name) = call.func.as_ref() {
                    if name == "env::block_number" {
                        if !call.args.is_empty() {
                            return Err(CompileError::new("env::block_number expects 0 arguments", call.span));
                        }
                    } else if name.starts_with("env::") {
                        return Err(CompileError::new(
                            format!("unknown validity environment read '{}'; only env::block_number() is approved", name),
                            call.span,
                        ));
                    } else if ["source::", "ckb::", "witness::", "dao::", "xudt::"].iter().any(|prefix| name.starts_with(prefix)) {
                        return Err(CompileError::new(
                            format!("validity predicate cannot read transaction view '{}'; use the approved env::block_number evidence contract or an action invariant", name),
                            call.span,
                        ));
                    }
                }
                Self::validate_validity_surface(&call.func)?;
                for arg in &call.args {
                    Self::validate_validity_surface(arg)?;
                }
            }
            Expr::Binary(binary) => {
                Self::validate_validity_surface(&binary.left)?;
                Self::validate_validity_surface(&binary.right)?;
            }
            Expr::Unary(unary) => Self::validate_validity_surface(&unary.expr)?,
            Expr::FieldAccess(field) => Self::validate_validity_surface(&field.expr)?,
            Expr::Index(index) => {
                Self::validate_validity_surface(&index.expr)?;
                Self::validate_validity_surface(&index.index)?;
            }
            Expr::Tuple(items) | Expr::Array(items) => {
                for item in items {
                    Self::validate_validity_surface(item)?;
                }
            }
            Expr::Cast(cast) => Self::validate_validity_surface(&cast.expr)?,
            Expr::Range(range) => {
                Self::validate_validity_surface(&range.start)?;
                Self::validate_validity_surface(&range.end)?;
            }
            Expr::StructInit(init) => {
                for (_, value) in &init.fields {
                    Self::validate_validity_surface(value)?;
                }
            }
            Expr::Create(_)
            | Expr::Consume(_)
            | Expr::Destroy(_)
            | Expr::ReadRef(_)
            | Expr::Claim(_)
            | Expr::Settle(_)
            | Expr::CreateUnique(_)
            | Expr::ReplaceUnique(_)
            | Expr::Assign(_)
            | Expr::If(_)
            | Expr::Match(_)
            | Expr::Block(_)
            | Expr::Assert(_)
            | Expr::Require(_)
            | Expr::RequireBlock(_)
            | Expr::Preserve(_)
            | Expr::ReplaceRelation(_)
            | Expr::StdlibCall(_) => {
                return Err(CompileError::new(
                    "validity predicates must be pure expressions without lifecycle, verifier-boundary, or control-flow syntax",
                    expr.span(),
                ));
            }
            Expr::Integer(_) | Expr::Bool(_) | Expr::String(_) | Expr::ByteString(_) | Expr::Identifier(_) => {}
        }
        Ok(())
    }

    fn check_invariant(&mut self, invariant: &InvariantDef) -> Result<()> {
        let missing_trigger = invariant.trigger.is_none();
        let missing_scope = invariant.scope.is_none();
        if missing_trigger || missing_scope {
            return Err(CompileError::new(
                format!("strict CKB invariant '{}' must declare explicit trigger and scope", invariant.name),
                invariant.span,
            ));
        }

        if let Some(trigger) = &invariant.trigger {
            match trigger.as_str() {
                "explicit_entry" | "lock_group" | "type_group" => {}
                _ => {
                    return Err(CompileError::new(
                        format!(
                            "invariant '{}' has unsupported trigger '{}'; expected explicit_entry, lock_group, or type_group",
                            invariant.name, trigger
                        ),
                        invariant.span,
                    ));
                }
            }
        }

        if let Some(scope) = &invariant.scope {
            match scope.as_str() {
                "selected_cells" | "group" | "transaction" => {}
                _ => {
                    return Err(CompileError::new(
                        format!(
                            "invariant '{}' has unsupported scope '{}'; expected selected_cells, group, or transaction",
                            invariant.name, scope
                        ),
                        invariant.span,
                    ));
                }
            }
        }

        if invariant.reads.is_empty() {
            return Err(CompileError::new(
                format!("invariant '{}' must declare at least one read source", invariant.name),
                invariant.span,
            ));
        }

        for read in &invariant.reads {
            if !SourceView::TRANSACTION_VIEWS.contains(&read.source) {
                return Err(CompileError::new(
                    format!(
                        "invariant '{}' has unsupported read source '{}'; expected input/output/group_input/group_output/cell_dep/header_dep/witness/lock_args variants",
                        invariant.name, read
                    ),
                    invariant.span,
                ));
            }
        }

        if invariant.asserts.is_empty() && invariant.aggregates.is_empty() && invariant.quantifiers.is_empty() {
            return Err(CompileError::new(
                format!(
                    "invariant '{}' must contain at least one assert_invariant expression, aggregate primitive, or bounded quantifier",
                    invariant.name
                ),
                invariant.span,
            ));
        }

        for aggregate in &invariant.aggregates {
            self.check_aggregate_invariant(invariant, aggregate)?;
        }

        let previous_callable = self.current_callable.replace(CallableKind::Invariant);
        let mut assert_env = TypeEnv::default();
        let assert_result = (|| -> Result<()> {
            for expr in &invariant.asserts {
                if !matches!(expr, Expr::Assert(_)) {
                    return Err(CompileError::new(
                        format!("invariant '{}' body only supports assert_invariant expressions", invariant.name),
                        invariant.span,
                    ));
                }
                self.infer_expr(&mut assert_env, expr)?;
            }
            for quantifier in &invariant.quantifiers {
                self.check_bounded_quantifier(invariant, quantifier)?;
            }
            Ok(())
        })();
        self.current_callable = previous_callable;
        assert_result?;

        Ok(())
    }

    fn check_bounded_quantifier(&mut self, invariant: &InvariantDef, quantifier: &BoundedQuantifier) -> Result<()> {
        if !matches!(
            quantifier.range.source,
            SourceView::Input
                | SourceView::Output
                | SourceView::GroupInput
                | SourceView::GroupOutput
                | SourceView::SelectedCells
                | SourceView::CellDep
        ) {
            return Err(CompileError::new(
                format!(
                    "bounded quantifier in '{}' uses unsupported source '{}'; expected inputs, outputs, group_inputs, group_outputs, selected_cells, or cell_deps",
                    invariant.name, quantifier.range
                ),
                quantifier.span,
            ));
        }
        let Some(type_name) = quantifier.range.type_name.as_deref() else {
            return Err(CompileError::new(
                format!("bounded quantifier in '{}' must name a cell-backed type argument", invariant.name),
                quantifier.span,
            ));
        };
        if self.resolve_cell_type_kind(type_name).is_none() {
            return Err(CompileError::new(
                format!("bounded quantifier in '{}' references non-cell-backed type '{}'", invariant.name, type_name),
                quantifier.span,
            ));
        }
        if !invariant.reads.iter().any(|read| read.source == quantifier.range.source && read.type_name.as_deref() == Some(type_name)) {
            return Err(CompileError::new(
                format!(
                    "bounded quantifier range '{}' must be declared by invariant '{}' reads metadata",
                    quantifier.range, invariant.name
                ),
                quantifier.span,
            ));
        }
        let range_scope = match quantifier.range.source {
            SourceView::GroupInput | SourceView::GroupOutput => "group",
            SourceView::Input | SourceView::Output | SourceView::CellDep => "transaction",
            SourceView::SelectedCells => "selected_cells",
            _ => unreachable!("unsupported quantifier source rejected above"),
        };
        if invariant.scope.as_deref().is_some_and(|scope| scope != range_scope) {
            return Err(CompileError::new(
                format!(
                    "bounded quantifier range '{}' has scope '{}', which does not match enclosing invariant scope '{}'",
                    quantifier.range,
                    range_scope,
                    invariant.scope.as_deref().unwrap_or("unspecified")
                ),
                quantifier.span,
            ));
        }

        let mut env = TypeEnv::default();
        match quantifier.kind {
            BoundedQuantifierKind::ForAll => {
                let expected_role = match quantifier.range.source {
                    SourceView::Input | SourceView::GroupInput => "input",
                    SourceView::Output | SourceView::GroupOutput => "output",
                    SourceView::CellDep => "cell_dep",
                    SourceView::SelectedCells => "cell",
                    _ => unreachable!("unsupported quantifier source rejected above"),
                };
                if quantifier.role.as_deref() != Some(expected_role) {
                    return Err(CompileError::new(
                        format!(
                            "forall role '{}' does not match source '{}'; expected role '{}'",
                            quantifier.role.as_deref().unwrap_or("missing"),
                            quantifier.range,
                            expected_role
                        ),
                        quantifier.span,
                    ));
                }
                let binding = quantifier
                    .binding
                    .as_ref()
                    .ok_or_else(|| CompileError::new("forall quantifier is missing its element binding", quantifier.span))?;
                env.insert(binding.clone(), Type::Named(type_name.to_string()), false, false);
                for predicate in &quantifier.predicates {
                    let predicate_ty = self.infer_expr(&mut env, predicate)?;
                    if predicate_ty != Type::Bool {
                        return Err(CompileError::new("forall require predicate must be boolean", predicate.span()));
                    }
                }
            }
            BoundedQuantifierKind::Count => {
                let fields = self.resolve_named_type_fields(type_name).ok_or_else(|| {
                    CompileError::new(format!("count quantifier cannot resolve fields for type '{}'", type_name), quantifier.span)
                })?;
                for (field, ty) in fields {
                    env.insert(field, ty, false, false);
                }
                let predicate = quantifier
                    .predicates
                    .first()
                    .ok_or_else(|| CompileError::new("count quantifier is missing its where predicate", quantifier.span))?;
                let predicate_ty = self.infer_expr(&mut env, predicate)?;
                if predicate_ty != Type::Bool {
                    return Err(CompileError::new("count where predicate must be boolean", predicate.span()));
                }
                let expected = quantifier
                    .expected
                    .as_ref()
                    .ok_or_else(|| CompileError::new("count quantifier is missing its comparison expression", quantifier.span))?;
                self.infer_expr_with_expected_type(&mut env, expected, &Type::U64, expected.span())?;
            }
        }
        Ok(())
    }

    fn check_aggregate_invariant(&self, invariant: &InvariantDef, aggregate: &AggregateInvariant) -> Result<()> {
        match aggregate.scope.as_str() {
            "selected_cells" | "group" | "transaction" => {}
            _ => {
                return Err(CompileError::new(
                    format!(
                        "aggregate invariant in '{}' has unsupported scope '{}'; expected selected_cells, group, or transaction",
                        invariant.name, aggregate.scope
                    ),
                    aggregate.span,
                ));
            }
        }

        if invariant.scope.as_deref().is_some_and(|scope| scope != aggregate.scope) {
            return Err(CompileError::new(
                format!(
                    "aggregate invariant scope '{}' must match enclosing invariant scope '{}'",
                    aggregate.scope,
                    invariant.scope.as_deref().unwrap_or("unspecified")
                ),
                aggregate.span,
            ));
        }

        match aggregate.kind {
            AggregateInvariantKind::Conserved | AggregateInvariantKind::Distinct => {
                self.validate_aggregate_field_target(invariant, aggregate, &aggregate.target)?;
            }
            AggregateInvariantKind::Delta => {
                if aggregate.argument.is_none() {
                    return Err(CompileError::new(
                        format!("assert_delta in invariant '{}' requires a delta argument", invariant.name),
                        aggregate.span,
                    ));
                }
                self.validate_aggregate_field_target(invariant, aggregate, &aggregate.target)?;
            }
            AggregateInvariantKind::Sum => {
                if aggregate.relation.is_none() || aggregate.rhs.is_none() {
                    return Err(CompileError::new(
                        format!("assert_sum in invariant '{}' requires a comparison", invariant.name),
                        aggregate.span,
                    ));
                }
                self.validate_aggregate_field_target(invariant, aggregate, &aggregate.target)?;
                if let Some(rhs) = &aggregate.rhs {
                    self.validate_aggregate_field_target(invariant, aggregate, rhs)?;
                }
            }
            AggregateInvariantKind::Singleton => {
                if aggregate.target.source != SourceView::TypeIdentity {
                    self.validate_aggregate_field_target(invariant, aggregate, &aggregate.target)?;
                }
            }
        }

        Ok(())
    }

    fn validate_aggregate_field_target(
        &self,
        invariant: &InvariantDef,
        aggregate: &AggregateInvariant,
        target: &AggregateTarget,
    ) -> Result<()> {
        let Some((type_name, field_name)) = target.type_and_field() else {
            return Err(CompileError::new(
                format!(
                    "aggregate invariant in '{}' must target a concrete field like Token.amount or group_inputs<Token>.amount",
                    invariant.name
                ),
                aggregate.span,
            ));
        };
        let Some(fields) = self.type_fields.get(type_name) else {
            return Err(CompileError::new(
                format!("aggregate invariant in '{}' references unknown type '{}'", invariant.name, type_name),
                aggregate.span,
            ));
        };
        let Some(field_ty) = fields.get(field_name) else {
            return Err(CompileError::new(
                format!("aggregate invariant in '{}' references unknown field '{}.{}'", invariant.name, type_name, field_name),
                aggregate.span,
            ));
        };
        if !aggregate_field_type_is_supported(field_ty) {
            return Err(CompileError::new(
                format!(
                    "aggregate invariant in '{}' field '{}.{}' must be a fixed-width integer or fixed bytes, found {}",
                    invariant.name,
                    type_name,
                    field_name,
                    type_repr(field_ty)
                ),
                aggregate.span,
            ));
        }
        Ok(())
    }

    fn validate_schema_fields(&self, fields: &[Field], item_kind: &str, item_name: &str) -> Result<()> {
        let mut seen = HashSet::new();
        for field in fields {
            if field.name == "_" {
                return Err(CompileError::new(
                    format!(
                        "{} '{}' field must have a stable name; '_' is reserved for local wildcard bindings",
                        item_kind, item_name
                    ),
                    field.span,
                ));
            }
            if !seen.insert(field.name.clone()) {
                return Err(CompileError::new(
                    format!("duplicate field '{}' in {} '{}'", field.name, item_kind, item_name),
                    field.span,
                ));
            }
            self.validate_type(&field.ty)?;
            self.validate_stored_type_has_no_references(
                &field.ty,
                &format!("{} '{}' field '{}'", item_kind, item_name, field.name),
                field.span,
            )?;
            if self.enum_type_contains_linear_payload(&field.ty, &mut HashSet::new()) {
                return Err(CompileError::new(
                    format!(
                        "{} '{}' field '{}' cannot store an enum with a linear Cell payload; linear payload enums are local-only handles",
                        item_kind, item_name, field.name
                    ),
                    field.span,
                ));
            }
        }
        Ok(())
    }

    fn check_enum(&mut self, enum_def: &EnumDef) -> Result<()> {
        if enum_def.variants.is_empty() {
            return Err(CompileError::new(format!("enum '{}' must declare at least one variant", enum_def.name), enum_def.span));
        }
        if enum_def.variants.len() > u8::MAX as usize + 1 {
            return Err(CompileError::new(
                format!("enum '{}' has too many variants for the 0.22 u8 tag ABI", enum_def.name),
                enum_def.span,
            ));
        }
        let mut seen = HashSet::new();
        for variant in &enum_def.variants {
            if !seen.insert(variant.name.clone()) {
                return Err(CompileError::new(format!("duplicate enum variant '{}::{}'", enum_def.name, variant.name), variant.span));
            }
            for field_ty in &variant.fields {
                self.validate_type(field_ty)?;
                self.validate_stored_type_has_no_references(
                    field_ty,
                    &format!("enum variant '{}::{}' payload", enum_def.name, variant.name),
                    variant.span,
                )?;
                if self.payload_type_runtime_width(field_ty, &mut HashSet::new()).is_none() {
                    return Err(CompileError::new(
                        format!(
                            "enum variant '{}::{}' payload type '{}' is variable-width or recursive; 0.22 payload enums require a concrete fixed-width layout",
                            enum_def.name,
                            variant.name,
                            type_repr(field_ty)
                        ),
                        variant.span,
                    ));
                }
            }
        }
        Ok(())
    }

    fn payload_type_runtime_width(&self, ty: &Type, visiting: &mut HashSet<String>) -> Option<usize> {
        match ty {
            Type::U8 | Type::Bool => Some(1),
            Type::U16 => Some(2),
            Type::U32 | Type::I32 => Some(4),
            Type::U64 => Some(8),
            Type::U128 => Some(16),
            Type::Address | Type::Hash => Some(32),
            Type::Unit => Some(0),
            Type::Array(inner, len) => self.payload_type_runtime_width(inner, visiting)?.checked_mul(*len),
            Type::Tuple(items) => {
                items.iter().try_fold(0usize, |width, item| width.checked_add(self.payload_type_runtime_width(item, visiting)?))
            }
            Type::Ref(_) | Type::MutRef(_) => None,
            Type::Named(name) => {
                if name.contains('<') {
                    return None;
                }
                if self.resolve_cell_type_kind(name).is_some() {
                    return Some(8);
                }
                if !visiting.insert(name.clone()) {
                    return None;
                }
                let width = if let Some(variants) = self.resolve_enum_variant_fields(name) {
                    variants
                        .values()
                        .map(|fields| {
                            fields
                                .iter()
                                .try_fold(0usize, |width, field| width.checked_add(self.payload_type_runtime_width(field, visiting)?))
                        })
                        .collect::<Option<Vec<_>>>()?
                        .into_iter()
                        .max()
                        .unwrap_or(0)
                        .checked_add(1)
                } else {
                    self.resolve_named_type_fields(name).and_then(|fields| {
                        fields
                            .values()
                            .try_fold(0usize, |width, field| width.checked_add(self.payload_type_runtime_width(field, visiting)?))
                    })
                };
                visiting.remove(name);
                width
            }
        }
    }

    fn enum_type_contains_linear_payload(&self, ty: &Type, visiting: &mut HashSet<String>) -> bool {
        match ty {
            Type::Array(inner, _) => self.enum_type_contains_linear_payload(inner, visiting),
            Type::Tuple(items) => items.iter().any(|item| self.enum_type_contains_linear_payload(item, visiting)),
            Type::Named(name) => {
                if !visiting.insert(name.clone()) {
                    return false;
                }
                let contains = self
                    .resolve_enum_variant_fields(name)
                    .is_some_and(|variants| variants.values().flatten().any(|field| self.is_linear_type_with_seen(field, visiting)));
                visiting.remove(name);
                contains
            }
            Type::U8
            | Type::U16
            | Type::U32
            | Type::I32
            | Type::U64
            | Type::U128
            | Type::Bool
            | Type::Unit
            | Type::Address
            | Type::Hash
            | Type::Ref(_)
            | Type::MutRef(_) => false,
        }
    }

    fn check_const(&mut self, const_def: &ConstDef) -> Result<()> {
        let mut env = self.env.clone();
        let value_ty = self.infer_expr_with_expected_type(&mut env, &const_def.value, &const_def.ty, const_def.span)?;
        if !self.types_equal(&value_ty, &const_def.ty) {
            return Err(CompileError::new(
                format!("const '{}' has type mismatch: expected {:?}, found {:?}", const_def.name, const_def.ty, value_ty),
                const_def.span,
            ));
        }
        Ok(())
    }

    fn check_action(&mut self, action: &ActionDef) -> Result<()> {
        let previous_callable = self.current_callable.replace(CallableKind::Action);
        let previous_return_type = self.current_return_type.replace(action.return_type.clone());
        let result = (|| {
            let mut env = self.env.child();
            let core_evidence_bindings = action_core_evidence_binding_names(action);

            self.bind_callable_params_with_non_linear(&mut env, &action.params, "action", &action.name, &core_evidence_bindings)?;
            self.bind_action_outputs(&mut env, action)?;
            if let Some(surface) = &action.next_surface {
                self.check_next_audits(&env, &surface.audits)?;
            }
            self.validate_action_state_edges(action, &env)?;
            self.validate_action_create_targets(action)?;
            self.validate_action_branch_obligations(action)?;
            if let Some(return_type) = &action.return_type {
                self.validate_callable_return_type("action", &action.name, return_type, action.span)?;
            }
            let return_env = env.clone();
            self.check_no_unreachable_stmts(&action.body)?;
            self.validate_spawn_ipc_fd_usage(&action.body)?;

            let tail = self.check_body_statements(&mut env, &action.body)?;

            if let Some(return_type) = &action.return_type {
                self.check_body_returns_or_tail_expr("action", &action.name, &action.body, return_type, action.span, &return_env)?;
            }

            if let Some((tail_base, stmt)) = tail {
                self.mark_stmt_as_returned(&mut env, &tail_base, stmt)?;
            }

            env.check_linear_complete()
        })();
        self.current_callable = previous_callable;
        self.current_return_type = previous_return_type;
        result
    }

    fn check_action_diagnostics(&mut self, action: &ActionDef) -> Vec<CompileError> {
        let previous_callable = self.current_callable.replace(CallableKind::Action);
        let previous_return_type = self.current_return_type.replace(action.return_type.clone());
        let mut diagnostics = Vec::new();
        let mut env = self.env.child();
        let core_evidence_bindings = action_core_evidence_binding_names(action);

        push_diagnostic(
            &mut diagnostics,
            self.bind_callable_params_with_non_linear(&mut env, &action.params, "action", &action.name, &core_evidence_bindings),
        );
        push_diagnostic(&mut diagnostics, self.bind_action_outputs(&mut env, action));
        if let Some(surface) = &action.next_surface {
            push_diagnostic(&mut diagnostics, self.check_next_audits(&env, &surface.audits));
        }
        push_diagnostic(&mut diagnostics, self.validate_action_state_edges(action, &env));
        push_diagnostic(&mut diagnostics, self.validate_action_create_targets(action));
        push_diagnostic(&mut diagnostics, self.validate_action_branch_obligations(action));
        if let Some(return_type) = &action.return_type {
            push_diagnostic(&mut diagnostics, self.validate_callable_return_type("action", &action.name, return_type, action.span));
        }
        let return_env = env.clone();
        push_diagnostic(&mut diagnostics, self.check_no_unreachable_stmts(&action.body));
        push_diagnostic(&mut diagnostics, self.validate_spawn_ipc_fd_usage(&action.body));

        let body_error_start = diagnostics.len();
        let tail = self.check_body_statements_diagnostics(&mut env, &action.body, &mut diagnostics);
        let body_had_errors = diagnostics.len() > body_error_start;

        if !body_had_errors {
            if let Some(return_type) = &action.return_type {
                push_diagnostic(
                    &mut diagnostics,
                    self.check_body_returns_or_tail_expr("action", &action.name, &action.body, return_type, action.span, &return_env),
                );
            }
            if let Some((tail_base, stmt)) = tail {
                push_diagnostic(&mut diagnostics, self.mark_stmt_as_returned(&mut env, &tail_base, stmt));
            }
            push_diagnostic(&mut diagnostics, env.check_linear_complete());
        }

        self.current_callable = previous_callable;
        self.current_return_type = previous_return_type;
        diagnostics
    }

    fn bind_action_outputs(&self, env: &mut TypeEnv, action: &ActionDef) -> Result<()> {
        let mut seen = action.params.iter().map(|param| param.name.clone()).collect::<HashSet<_>>();
        for output in &action.outputs {
            if output.name == "_" {
                return Err(CompileError::new(
                    format!("action '{}' output binding must have a stable name", action.name),
                    output.span,
                ));
            }
            if !seen.insert(output.name.clone()) {
                return Err(CompileError::new(
                    format!("duplicate action binding '{}' in action '{}'", output.name, action.name),
                    output.span,
                ));
            }
            self.validate_type(&output.ty)?;
            let Some(type_name) = Self::base_type_name(&output.ty) else {
                return Err(CompileError::new(
                    format!("action output '{}' must name a Cell-backed resource, shared cell, or receipt type", output.name),
                    output.span,
                ));
            };
            if self.resolve_cell_type_kind(type_name).is_none() {
                return Err(CompileError::new(
                    format!(
                        "action output '{}' references non-Cell type {}; action outputs are proposed transaction output Cells",
                        output.name,
                        type_repr(&output.ty)
                    ),
                    output.span,
                ));
            }
            env.bind_new(output.name.clone(), output.ty.clone(), false, false, output.span)?;
        }
        Ok(())
    }

    fn check_next_audits(&mut self, env: &TypeEnv, audits: &[NextAudit]) -> Result<()> {
        for audit in audits {
            Self::validate_require_condition_is_pure(&audit.subject, "audit evidence subject")?;
            let mut audit_env = env.clone();
            let subject_ty = self.infer_expr(&mut audit_env, &audit.subject)?;
            if self.is_linear_type(&subject_ty) {
                return Err(CompileError::new(
                    format!("audit '{}' cannot capture a Cell-backed linear value; select immutable evidence fields", audit.name),
                    audit.span,
                ));
            }
        }
        Ok(())
    }

    fn validate_action_create_targets(&self, action: &ActionDef) -> Result<()> {
        let outputs = action_output_binding_names(action);
        self.validate_create_targets_in_stmts(&action.body, &outputs)
    }

    fn validate_action_branch_obligations(&self, action: &ActionDef) -> Result<()> {
        let outputs = action_output_binding_names(action).keys().cloned().collect::<HashSet<_>>();
        if outputs.is_empty() {
            return Ok(());
        }

        self.validate_branch_obligations_in_stmts(&action.body, &outputs, HashSet::new())?;
        Ok(())
    }

    fn validate_branch_obligations_in_stmts(
        &self,
        stmts: &[Stmt],
        outputs: &HashSet<String>,
        mut guaranteed: HashSet<String>,
    ) -> Result<HashSet<String>> {
        for stmt in stmts {
            match stmt {
                Stmt::Let(let_stmt) => {
                    guaranteed = self.validate_branch_obligations_in_expr(&let_stmt.value, outputs, guaranteed)?;
                }
                Stmt::Expr(expr) | Stmt::Return(ReturnStmt { value: Some(expr), .. }) => {
                    guaranteed = self.validate_branch_obligations_in_expr(expr, outputs, guaranteed)?;
                }
                Stmt::Return(ReturnStmt { value: None, .. }) => {}
                Stmt::Break(_) | Stmt::Continue(_) => {}
                Stmt::If(if_stmt) => {
                    self.validate_branch_obligations_in_expr(&if_stmt.condition, outputs, guaranteed.clone())?;
                    let then_guaranteed =
                        self.validate_branch_obligations_in_stmts(&if_stmt.then_branch, outputs, guaranteed.clone())?;
                    let else_guaranteed = if let Some(else_branch) = &if_stmt.else_branch {
                        self.validate_branch_obligations_in_stmts(else_branch, outputs, guaranteed.clone())?
                    } else {
                        guaranteed.clone()
                    };
                    self.reject_asymmetric_branch_constraints(
                        &guaranteed,
                        &[then_guaranteed.clone(), else_guaranteed.clone()],
                        if_stmt.span,
                    )?;
                    guaranteed = then_guaranteed.intersection(&else_guaranteed).cloned().collect();
                }
                Stmt::For(for_stmt) => {
                    self.validate_branch_obligations_in_expr(&for_stmt.iterable, outputs, guaranteed.clone())?;
                    self.validate_branch_obligations_in_stmts(&for_stmt.body, outputs, guaranteed.clone())?;
                }
                Stmt::While(while_stmt) => {
                    self.validate_branch_obligations_in_expr(&while_stmt.condition, outputs, guaranteed.clone())?;
                    self.validate_branch_obligations_in_stmts(&while_stmt.body, outputs, guaranteed.clone())?;
                }
                Stmt::Borrow(borrow_stmt) => {
                    guaranteed = self.validate_branch_obligations_in_stmts(&borrow_stmt.body, outputs, guaranteed)?;
                }
            }
        }

        Ok(guaranteed)
    }

    fn validate_branch_obligations_in_expr(
        &self,
        expr: &Expr,
        outputs: &HashSet<String>,
        mut guaranteed: HashSet<String>,
    ) -> Result<HashSet<String>> {
        match expr {
            Expr::Require(require_expr) => {
                collect_required_output_fields(&require_expr.condition, outputs, &mut guaranteed);
                self.validate_branch_obligations_in_expr(&require_expr.condition, outputs, guaranteed.clone())?;
                if let Some(message) = &require_expr.message {
                    self.validate_branch_obligations_in_expr(message, outputs, guaranteed.clone())?;
                }
                Ok(guaranteed)
            }
            Expr::If(if_expr) => {
                self.validate_branch_obligations_in_expr(&if_expr.condition, outputs, guaranteed.clone())?;
                let then_guaranteed = self.validate_branch_obligations_in_expr(&if_expr.then_branch, outputs, guaranteed.clone())?;
                let else_guaranteed = self.validate_branch_obligations_in_expr(&if_expr.else_branch, outputs, guaranteed.clone())?;
                self.reject_asymmetric_branch_constraints(
                    &guaranteed,
                    &[then_guaranteed.clone(), else_guaranteed.clone()],
                    if_expr.span,
                )?;
                Ok(then_guaranteed.intersection(&else_guaranteed).cloned().collect())
            }
            Expr::Match(match_expr) => {
                self.validate_branch_obligations_in_expr(&match_expr.expr, outputs, guaranteed.clone())?;
                let mut arm_sets = Vec::with_capacity(match_expr.arms.len());
                for arm in &match_expr.arms {
                    arm_sets.push(self.validate_branch_obligations_in_expr(&arm.value, outputs, guaranteed.clone())?);
                }
                self.reject_asymmetric_branch_constraints(&guaranteed, &arm_sets, match_expr.span)?;
                let mut iter = arm_sets.into_iter();
                let Some(first) = iter.next() else {
                    return Ok(guaranteed);
                };
                Ok(iter.fold(first, |acc, arm| acc.intersection(&arm).cloned().collect()))
            }
            Expr::Block(stmts) => self.validate_branch_obligations_in_stmts(stmts, outputs, guaranteed),
            Expr::Assign(assign) => {
                self.validate_branch_obligations_in_expr(&assign.target, outputs, guaranteed.clone())?;
                self.validate_branch_obligations_in_expr(&assign.value, outputs, guaranteed)
            }
            Expr::Binary(binary) => {
                self.validate_branch_obligations_in_expr(&binary.left, outputs, guaranteed.clone())?;
                self.validate_branch_obligations_in_expr(&binary.right, outputs, guaranteed)
            }
            Expr::Unary(unary) => self.validate_branch_obligations_in_expr(&unary.expr, outputs, guaranteed),
            Expr::Call(call) => {
                self.validate_branch_obligations_in_expr(&call.func, outputs, guaranteed.clone())?;
                for arg in &call.args {
                    self.validate_branch_obligations_in_expr(arg, outputs, guaranteed.clone())?;
                }
                Ok(guaranteed)
            }
            Expr::FieldAccess(field) => self.validate_branch_obligations_in_expr(&field.expr, outputs, guaranteed),
            Expr::Index(index) => {
                self.validate_branch_obligations_in_expr(&index.expr, outputs, guaranteed.clone())?;
                self.validate_branch_obligations_in_expr(&index.index, outputs, guaranteed)
            }
            Expr::Create(create) => {
                for (_, value) in &create.fields {
                    self.validate_branch_obligations_in_expr(value, outputs, guaranteed.clone())?;
                }
                if let Some(lock) = &create.lock {
                    self.validate_branch_obligations_in_expr(lock, outputs, guaranteed.clone())?;
                }
                Ok(guaranteed)
            }
            Expr::Consume(consume) => self.validate_branch_obligations_in_expr(&consume.expr, outputs, guaranteed),
            Expr::Destroy(destroy) => self.validate_branch_obligations_in_expr(&destroy.expr, outputs, guaranteed),
            Expr::Claim(claim) => self.validate_branch_obligations_in_expr(&claim.receipt, outputs, guaranteed),
            Expr::Settle(settle) => self.validate_branch_obligations_in_expr(&settle.expr, outputs, guaranteed),
            Expr::CreateUnique(create) => {
                for (_, value) in &create.fields {
                    self.validate_branch_obligations_in_expr(value, outputs, guaranteed.clone())?;
                }
                if let Some(lock) = &create.lock {
                    self.validate_branch_obligations_in_expr(lock, outputs, guaranteed.clone())?;
                }
                Ok(guaranteed)
            }
            Expr::ReplaceUnique(replace) => {
                self.validate_branch_obligations_in_expr(&replace.expr, outputs, guaranteed.clone())?;
                for (_, value) in &replace.fields {
                    self.validate_branch_obligations_in_expr(value, outputs, guaranteed.clone())?;
                }
                Ok(guaranteed)
            }
            Expr::Assert(assert_expr) => {
                self.validate_branch_obligations_in_expr(&assert_expr.condition, outputs, guaranteed.clone())?;
                self.validate_branch_obligations_in_expr(&assert_expr.message, outputs, guaranteed)
            }
            Expr::Tuple(elems) | Expr::Array(elems) => {
                for elem in elems {
                    self.validate_branch_obligations_in_expr(elem, outputs, guaranteed.clone())?;
                }
                Ok(guaranteed)
            }
            Expr::Cast(cast) => self.validate_branch_obligations_in_expr(&cast.expr, outputs, guaranteed),
            Expr::Range(range) => {
                self.validate_branch_obligations_in_expr(&range.start, outputs, guaranteed.clone())?;
                self.validate_branch_obligations_in_expr(&range.end, outputs, guaranteed)
            }
            Expr::StructInit(init) => {
                for (_, value) in &init.fields {
                    self.validate_branch_obligations_in_expr(value, outputs, guaranteed.clone())?;
                }
                Ok(guaranteed)
            }
            Expr::Integer(_)
            | Expr::Bool(_)
            | Expr::String(_)
            | Expr::ByteString(_)
            | Expr::Identifier(_)
            | Expr::ReadRef(_)
            | Expr::StdlibCall(_) => Ok(guaranteed),
            Expr::RequireBlock(require_block) => {
                let mut current = guaranteed;
                for expr in &require_block.expressions {
                    current = self.validate_branch_obligations_in_expr(expr, outputs, current)?;
                }
                Ok(current)
            }
            Expr::Preserve(preserve) => {
                for field in &preserve.fields {
                    guaranteed.insert(field.clone());
                }
                Ok(guaranteed)
            }
            Expr::ReplaceRelation(relation) => {
                // Explicitly preserved fields are guaranteed on this path. A
                // `same except` expansion is resolved against the concrete
                // schema during inference; without the type environment here
                // the conservative result keeps nothing guaranteed.
                if let ReplaceDataTreatment::Fields(treatments) = &relation.data {
                    for treatment in treatments {
                        if let ReplaceFieldTreatment::Same(field) = treatment {
                            guaranteed.insert(field.clone());
                        }
                    }
                }
                Ok(guaranteed)
            }
        }
    }

    fn reject_asymmetric_branch_constraints(&self, base: &HashSet<String>, branches: &[HashSet<String>], span: Span) -> Result<()> {
        if branches.len() < 2 {
            return Ok(());
        }

        let mut union = HashSet::new();
        for branch in branches {
            for field in branch {
                if !base.contains(field) {
                    union.insert(field.clone());
                }
            }
        }

        let mut asymmetric = union
            .into_iter()
            .filter(|field| {
                branches.iter().any(|branch| branch.contains(field)) && branches.iter().any(|branch| !branch.contains(field))
            })
            .collect::<Vec<_>>();
        asymmetric.sort();

        if let Some(field) = asymmetric.into_iter().next() {
            return Err(CompileError::new(
                format!("incomplete branch constraints: field '{}' is constrained in one branch but not all branches", field),
                span,
            ));
        }

        Ok(())
    }

    fn validate_create_targets_in_stmts(&self, stmts: &[Stmt], outputs: &HashMap<String, ActionOutputBinding>) -> Result<()> {
        for stmt in stmts {
            match stmt {
                Stmt::Let(let_stmt) => self.validate_create_targets_in_expr(&let_stmt.value, outputs)?,
                Stmt::Expr(expr) | Stmt::Return(ReturnStmt { value: Some(expr), .. }) => {
                    self.validate_create_targets_in_expr(expr, outputs)?
                }
                Stmt::Return(ReturnStmt { value: None, .. }) => {}
                Stmt::Break(_) | Stmt::Continue(_) => {}
                Stmt::If(if_stmt) => {
                    self.validate_create_targets_in_expr(&if_stmt.condition, outputs)?;
                    self.validate_create_targets_in_stmts(&if_stmt.then_branch, outputs)?;
                    if let Some(else_branch) = &if_stmt.else_branch {
                        self.validate_create_targets_in_stmts(else_branch, outputs)?;
                    }
                }
                Stmt::For(for_stmt) => {
                    self.validate_create_targets_in_expr(&for_stmt.iterable, outputs)?;
                    self.validate_create_targets_in_stmts(&for_stmt.body, outputs)?;
                }
                Stmt::While(while_stmt) => {
                    self.validate_create_targets_in_expr(&while_stmt.condition, outputs)?;
                    self.validate_create_targets_in_stmts(&while_stmt.body, outputs)?;
                }
                Stmt::Borrow(borrow_stmt) => self.validate_create_targets_in_stmts(&borrow_stmt.body, outputs)?,
            }
        }
        Ok(())
    }

    fn validate_create_targets_in_expr(&self, expr: &Expr, outputs: &HashMap<String, ActionOutputBinding>) -> Result<()> {
        match expr {
            Expr::ReplaceRelation(relation) => {
                // Every relation binds its successor through the create
                // kernel, so the successor must be an action output binding.
                if !outputs.contains_key(&relation.after) {
                    return Err(CompileError::new(
                        format!("replace relation successor '{}' must be declared as an action output binding", relation.after),
                        relation.span,
                    ));
                }
                for value in relation.value_exprs() {
                    self.validate_create_targets_in_expr(value, outputs)?;
                }
            }
            Expr::Create(create) => {
                if let Some(target) = &create.target {
                    let Some(binding) = outputs.get(target) else {
                        return Err(CompileError::new(
                            format!("create target '{}' must be declared as an action output binding", target),
                            create.span,
                        ));
                    };
                    if binding.type_name != create.ty {
                        return Err(CompileError::new(
                            format!(
                                "create target '{}' has type '{}', but initializer constructs '{}'",
                                target, binding.type_name, create.ty
                            ),
                            create.span,
                        ));
                    }
                }
                for (_, value) in &create.fields {
                    self.validate_create_targets_in_expr(value, outputs)?;
                }
                if let Some(lock) = &create.lock {
                    self.validate_create_targets_in_expr(lock, outputs)?;
                }
            }
            Expr::Assign(assign) => {
                self.validate_create_targets_in_expr(&assign.target, outputs)?;
                self.validate_create_targets_in_expr(&assign.value, outputs)?;
            }
            Expr::Binary(binary) => {
                self.validate_create_targets_in_expr(&binary.left, outputs)?;
                self.validate_create_targets_in_expr(&binary.right, outputs)?;
            }
            Expr::Unary(unary) => self.validate_create_targets_in_expr(&unary.expr, outputs)?,
            Expr::Call(call) => {
                self.validate_create_targets_in_expr(&call.func, outputs)?;
                for arg in &call.args {
                    self.validate_create_targets_in_expr(arg, outputs)?;
                }
            }
            Expr::FieldAccess(field) => self.validate_create_targets_in_expr(&field.expr, outputs)?,
            Expr::Index(index) => {
                self.validate_create_targets_in_expr(&index.expr, outputs)?;
                self.validate_create_targets_in_expr(&index.index, outputs)?;
            }
            Expr::Consume(consume) => self.validate_create_targets_in_expr(&consume.expr, outputs)?,
            Expr::Destroy(destroy) => self.validate_create_targets_in_expr(&destroy.expr, outputs)?,
            Expr::Claim(claim) => self.validate_create_targets_in_expr(&claim.receipt, outputs)?,
            Expr::Settle(settle) => self.validate_create_targets_in_expr(&settle.expr, outputs)?,
            Expr::CreateUnique(create) => {
                if let Some(target) = &create.target {
                    let Some(binding) = outputs.get(target) else {
                        return Err(CompileError::new(
                            format!("create_unique target '{}' must be declared as an action output binding", target),
                            create.span,
                        ));
                    };
                    if binding.type_name != create.ty {
                        return Err(CompileError::new(
                            format!(
                                "create_unique target '{}' has type '{}', but initializer constructs '{}'",
                                target, binding.type_name, create.ty
                            ),
                            create.span,
                        ));
                    }
                }
                for (_, value) in &create.fields {
                    self.validate_create_targets_in_expr(value, outputs)?;
                }
                if let Some(lock) = &create.lock {
                    self.validate_create_targets_in_expr(lock, outputs)?;
                }
            }
            Expr::ReplaceUnique(replace) => {
                self.validate_create_targets_in_expr(&replace.expr, outputs)?;
                for (_, value) in &replace.fields {
                    self.validate_create_targets_in_expr(value, outputs)?;
                }
            }
            Expr::Assert(assert_expr) => {
                self.validate_create_targets_in_expr(&assert_expr.condition, outputs)?;
                self.validate_create_targets_in_expr(&assert_expr.message, outputs)?;
            }
            Expr::Require(require_expr) => {
                self.validate_create_targets_in_expr(&require_expr.condition, outputs)?;
                if let Some(message) = &require_expr.message {
                    self.validate_create_targets_in_expr(message, outputs)?;
                }
            }
            Expr::Block(stmts) => self.validate_create_targets_in_stmts(stmts, outputs)?,
            Expr::Tuple(items) | Expr::Array(items) => {
                for item in items {
                    self.validate_create_targets_in_expr(item, outputs)?;
                }
            }
            Expr::If(if_expr) => {
                self.validate_create_targets_in_expr(&if_expr.condition, outputs)?;
                self.validate_create_targets_in_expr(&if_expr.then_branch, outputs)?;
                self.validate_create_targets_in_expr(&if_expr.else_branch, outputs)?;
            }
            Expr::Cast(cast) => self.validate_create_targets_in_expr(&cast.expr, outputs)?,
            Expr::Range(range) => {
                self.validate_create_targets_in_expr(&range.start, outputs)?;
                self.validate_create_targets_in_expr(&range.end, outputs)?;
            }
            Expr::StructInit(init) => {
                for (_, value) in &init.fields {
                    self.validate_create_targets_in_expr(value, outputs)?;
                }
            }
            Expr::Match(match_expr) => {
                self.validate_create_targets_in_expr(&match_expr.expr, outputs)?;
                for arm in &match_expr.arms {
                    self.validate_create_targets_in_expr(&arm.value, outputs)?;
                }
            }
            Expr::Integer(_)
            | Expr::Bool(_)
            | Expr::String(_)
            | Expr::ByteString(_)
            | Expr::Identifier(_)
            | Expr::ReadRef(_)
            | Expr::StdlibCall(_) => {}
            Expr::RequireBlock(require_block) => {
                for expr in &require_block.expressions {
                    self.validate_create_targets_in_expr(expr, outputs)?;
                }
            }
            Expr::Preserve(_) => {}
        }
        Ok(())
    }

    fn validate_action_state_edges(&self, action: &ActionDef, env: &TypeEnv) -> Result<()> {
        let output_bindings = action_output_binding_names(action);
        let mut lineage_inputs = HashMap::new();
        let mut lineage_outputs = HashMap::new();
        for state_edge in &action.state_edges {
            let from_path = &state_edge.path;
            let to_path = &state_edge.to_path;
            if let Some(previous_output) = lineage_inputs.insert(from_path.base.clone(), to_path.base.clone())
                && previous_output != to_path.base
            {
                return Err(CompileError::new(
                    format!(
                        "state transition binding '{}' points to both '{}' and '{}'; split/merge lineage is not supported",
                        from_path.base, previous_output, to_path.base
                    ),
                    state_edge.span,
                ));
            }
            if let Some(previous_input) = lineage_outputs.insert(to_path.base.clone(), from_path.base.clone())
                && previous_input != from_path.base
            {
                return Err(CompileError::new(
                    format!(
                        "state transition output '{}' is reached from both '{}' and '{}'; split/merge lineage is not supported",
                        to_path.base, previous_input, from_path.base
                    ),
                    state_edge.span,
                ));
            }
        }

        for state_edge in &action.state_edges {
            let path = &state_edge.path;
            let to_path = &state_edge.to_path;
            let ty = env
                .lookup(&path.base)
                .ok_or_else(|| CompileError::new(format!("unknown state transition binding '{}'", path.base), path.span))?;
            let Some(param) = action.params.iter().find(|param| param.name == path.base) else {
                return Err(CompileError::new(
                    format!("state transition binding '{}' must name an action input parameter", path.base),
                    path.span,
                ));
            };
            if !matches!(param.source, ParamSource::Default | ParamSource::Input)
                || param.is_read_ref
                || !matches!(param.ty, Type::Named(_))
            {
                return Err(CompileError::new(
                    format!(
                        "state transition binding '{}' must be an owned Cell input parameter, not a reference, witness, lock_args, protected, output, or read parameter",
                        path.base
                    ),
                    path.span,
                ));
            }
            let type_name = Self::base_type_name(ty)
                .ok_or_else(|| {
                    CompileError::new(format!("state transition binding '{}' is not a named state type", path.base), path.span)
                })?
                .to_string();
            let Some(output_binding) = output_bindings.get(&to_path.base) else {
                return Err(CompileError::new(
                    format!("state transition output binding '{}' must be a named action return", to_path.base),
                    to_path.span,
                ));
            };
            if output_binding.type_name != type_name {
                return Err(CompileError::new(
                    format!(
                        "state transition input '{}' has type '{}', but output '{}' has type '{}'",
                        path.base, type_name, to_path.base, output_binding.type_name
                    ),
                    state_edge.span,
                ));
            }
            if path.field.is_empty() && to_path.field.is_empty() && state_edge.from.is_empty() && state_edge.to.is_empty() {
                continue;
            }
            let spec = self
                .flows
                .get(&type_name)
                .ok_or_else(|| CompileError::new(format!("type '{}' has no declared flow", type_name), path.span))?;
            if spec.field_name != path.field {
                return Err(CompileError::new(
                    format!(
                        "state transition field '{}.{}' does not match declared flow field '{}.{}'",
                        path.base, path.field, type_name, spec.field_name
                    ),
                    path.span,
                ));
            }
            if spec.field_name != to_path.field {
                return Err(CompileError::new(
                    format!(
                        "state transition output field '{}.{}' does not match declared flow field '{}.{}'",
                        to_path.base, to_path.field, type_name, spec.field_name
                    ),
                    to_path.span,
                ));
            }

            let states = self
                .flow_states
                .get(&type_name)
                .ok_or_else(|| CompileError::new(format!("type '{}' has no declared flow", type_name), state_edge.span))?;
            let from = self.canonical_state_name_for_flow(
                &type_name,
                spec.field_enum_type.as_deref(),
                states,
                &state_edge.from,
                state_edge.span,
            )?;
            let to = self.canonical_state_name_for_flow(
                &type_name,
                spec.field_enum_type.as_deref(),
                states,
                &state_edge.to,
                state_edge.span,
            )?;
            if !spec.transitions.iter().any(|transition| transition.from == from && transition.to == to) {
                return Err(CompileError::new(
                    format!("state transition '{}.{} {} -> {}' is not declared", type_name, spec.field_name, from, to),
                    state_edge.span,
                ));
            }
        }

        Ok(())
    }

    fn check_function(&mut self, function: &FnDef) -> Result<()> {
        let previous_callable = self.current_callable.replace(CallableKind::Function);
        let previous_return_type = self.current_return_type.replace(function.return_type.clone());
        let result = (|| {
            let mut env = self.env.child();

            self.bind_callable_params(&mut env, &function.params, "function", &function.name)?;
            if let Some(return_type) = &function.return_type {
                self.validate_callable_return_type("function", &function.name, return_type, function.span)?;
            }
            let return_env = env.clone();
            self.check_no_unreachable_stmts(&function.body)?;

            let tail = self.check_body_statements(&mut env, &function.body)?;

            if let Some(return_type) = &function.return_type {
                self.check_body_returns_or_tail_expr(
                    "function",
                    &function.name,
                    &function.body,
                    return_type,
                    function.span,
                    &return_env,
                )?;
            }

            if let Some((tail_base, stmt)) = tail {
                self.mark_stmt_as_returned(&mut env, &tail_base, stmt)?;
            }

            env.check_linear_complete()
        })();
        self.current_callable = previous_callable;
        self.current_return_type = previous_return_type;
        result
    }

    fn check_function_diagnostics(&mut self, function: &FnDef) -> Vec<CompileError> {
        let previous_callable = self.current_callable.replace(CallableKind::Function);
        let previous_return_type = self.current_return_type.replace(function.return_type.clone());
        let mut diagnostics = Vec::new();
        let mut env = self.env.child();

        push_diagnostic(&mut diagnostics, self.bind_callable_params(&mut env, &function.params, "function", &function.name));
        if let Some(return_type) = &function.return_type {
            push_diagnostic(
                &mut diagnostics,
                self.validate_callable_return_type("function", &function.name, return_type, function.span),
            );
        }
        let return_env = env.clone();
        push_diagnostic(&mut diagnostics, self.check_no_unreachable_stmts(&function.body));

        let body_error_start = diagnostics.len();
        let tail = self.check_body_statements_diagnostics(&mut env, &function.body, &mut diagnostics);
        let body_had_errors = diagnostics.len() > body_error_start;

        if !body_had_errors {
            if let Some(return_type) = &function.return_type {
                push_diagnostic(
                    &mut diagnostics,
                    self.check_body_returns_or_tail_expr(
                        "function",
                        &function.name,
                        &function.body,
                        return_type,
                        function.span,
                        &return_env,
                    ),
                );
            }
            if let Some((tail_base, stmt)) = tail {
                push_diagnostic(&mut diagnostics, self.mark_stmt_as_returned(&mut env, &tail_base, stmt));
            }
            push_diagnostic(&mut diagnostics, env.check_linear_complete());
        }

        self.current_callable = previous_callable;
        self.current_return_type = previous_return_type;
        diagnostics
    }

    fn check_lock(&mut self, lock: &LockDef) -> Result<()> {
        let previous_callable = self.current_callable.replace(CallableKind::Lock);
        let previous_return_type = self.current_return_type.replace(Some(Type::Bool));
        let result = (|| {
            if lock.return_type != Type::Bool {
                return Err(CompileError::new("lock definitions must return bool", lock.span));
            }

            let mut env = self.env.child();

            self.bind_callable_params(&mut env, &lock.params, "lock", &lock.name)?;
            if let Some(surface) = &lock.next_surface {
                self.check_next_audits(&env, &surface.audits)?;
            }
            self.check_no_unreachable_stmts(&lock.body)?;
            self.validate_spawn_ipc_fd_usage(&lock.body)?;

            let tail = self.check_body_statements(&mut env, &lock.body)?;

            let Some(stmt) = lock.body.last() else {
                return Err(CompileError::new("lock body must return a bool value", lock.span));
            };
            let return_ty = self.infer_lock_terminal_stmt(&mut env, stmt)?;
            if !self.is_bool_type(&return_ty) {
                return Err(CompileError::new("lock body must evaluate to bool", lock.span));
            }
            if let Some((tail_base, stmt)) = tail {
                self.mark_stmt_as_returned(&mut env, &tail_base, stmt)?;
            }

            env.check_linear_complete()
        })();
        self.current_callable = previous_callable;
        self.current_return_type = previous_return_type;
        result
    }

    fn check_lock_diagnostics(&mut self, lock: &LockDef) -> Vec<CompileError> {
        let previous_callable = self.current_callable.replace(CallableKind::Lock);
        let previous_return_type = self.current_return_type.replace(Some(Type::Bool));
        let mut diagnostics = Vec::new();

        if lock.return_type != Type::Bool {
            diagnostics.push(CompileError::new("lock definitions must return bool", lock.span));
        }

        let mut env = self.env.child();
        push_diagnostic(&mut diagnostics, self.bind_callable_params(&mut env, &lock.params, "lock", &lock.name));
        if let Some(surface) = &lock.next_surface {
            push_diagnostic(&mut diagnostics, self.check_next_audits(&env, &surface.audits));
        }
        push_diagnostic(&mut diagnostics, self.check_no_unreachable_stmts(&lock.body));
        push_diagnostic(&mut diagnostics, self.validate_spawn_ipc_fd_usage(&lock.body));

        let body_error_start = diagnostics.len();
        let tail = self.check_body_statements_diagnostics(&mut env, &lock.body, &mut diagnostics);
        let body_had_errors = diagnostics.len() > body_error_start;

        if !body_had_errors {
            if let Some(stmt) = lock.body.last() {
                match self.infer_lock_terminal_stmt(&mut env, stmt) {
                    Ok(return_ty) if !self.is_bool_type(&return_ty) => {
                        diagnostics.push(CompileError::new("lock body must evaluate to bool", lock.span));
                    }
                    Ok(_) => {}
                    Err(error) => diagnostics.push(error),
                }
            } else {
                diagnostics.push(CompileError::new("lock body must return a bool value", lock.span));
            }
            if let Some((tail_base, stmt)) = tail {
                push_diagnostic(&mut diagnostics, self.mark_stmt_as_returned(&mut env, &tail_base, stmt));
            }
            push_diagnostic(&mut diagnostics, env.check_linear_complete());
        }

        self.current_callable = previous_callable;
        self.current_return_type = previous_return_type;
        diagnostics
    }

    fn validate_callable_return_type(&self, callable_kind: &str, callable_name: &str, return_type: &Type, span: Span) -> Result<()> {
        self.validate_type(return_type)?;
        if self.type_contains_reference(return_type) {
            return Err(CompileError::new(
                format!(
                    "{} '{}' cannot return reference type {}; references cannot escape callable boundaries",
                    callable_kind,
                    callable_name,
                    type_repr(return_type)
                ),
                span,
            ));
        }
        if callable_kind == "function" && self.type_contains_cell_backed_value(return_type) {
            return Err(CompileError::new(
                format!(
                    "function '{}' cannot return cell-backed type {}; pure helpers must return non-Cell values",
                    callable_name,
                    type_repr(return_type)
                ),
                span,
            ));
        }
        if callable_kind != "function" && self.enum_type_contains_linear_payload(return_type, &mut HashSet::new()) {
            return Err(CompileError::new(
                format!(
                    "{} '{}' cannot return a linear payload enum across an entry ABI; destructure and discharge the Cell payload locally",
                    callable_kind, callable_name
                ),
                span,
            ));
        }
        if let Type::Named(enum_name) = return_type
            && let Some(variants) = self.resolve_enum_variant_fields(enum_name)
        {
            let has_payload = variants.values().any(|fields| !fields.is_empty());
            if has_payload && callable_kind != "function" {
                return Err(CompileError::new(
                    format!(
                        "{} '{}' cannot return a payload enum across an entry ABI; payload enum returns are pure-helper ABI values",
                        callable_kind, callable_name
                    ),
                    span,
                ));
            }
            if has_payload {
                let width = self.payload_type_runtime_width(return_type, &mut HashSet::new()).ok_or_else(|| {
                    CompileError::new(format!("function '{}' payload enum return has no fixed-width ABI layout", callable_name), span)
                })?;
                if width > 16 {
                    return Err(CompileError::new(
                        format!(
                            "function '{}' payload enum return is {} bytes; 0.22 register-pair return ABI supports at most 16 bytes",
                            callable_name, width
                        ),
                        span,
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_stored_type_has_no_references(&self, ty: &Type, owner: &str, span: Span) -> Result<()> {
        if self.type_contains_reference(ty) {
            return Err(CompileError::new(
                format!("{} cannot use reference type {}; schema storage must use owned serializable values", owner, type_repr(ty)),
                span,
            ));
        }
        Ok(())
    }

    fn type_contains_reference(&self, ty: &Type) -> bool {
        match ty {
            Type::Ref(_) | Type::MutRef(_) => true,
            Type::Array(inner, _) => self.type_contains_reference(inner),
            Type::Tuple(items) => items.iter().any(|item| self.type_contains_reference(item)),
            Type::Named(name) => self.named_type_contains_reference(name),
            _ => false,
        }
    }

    fn type_contains_mutable_reference(ty: &Type) -> bool {
        match ty {
            Type::MutRef(_) => true,
            Type::Array(inner, _) => Self::type_contains_mutable_reference(inner),
            Type::Tuple(items) => items.iter().any(Self::type_contains_mutable_reference),
            Type::Named(name) => name.contains("&mut "),
            _ => false,
        }
    }

    fn type_contains_cell_backed_value(&self, ty: &Type) -> bool {
        self.type_contains_cell_backed_value_with_seen(ty, &mut HashSet::new())
    }

    fn type_contains_cell_backed_value_with_seen(&self, ty: &Type, visiting: &mut HashSet<String>) -> bool {
        match ty {
            Type::Array(inner, _) => self.type_contains_cell_backed_value_with_seen(inner, visiting),
            Type::Tuple(items) => items.iter().any(|item| self.type_contains_cell_backed_value_with_seen(item, visiting)),
            Type::Named(name) => {
                let base_name = name.split('<').next().unwrap_or(name.as_str());
                if self.resolve_cell_type_kind(base_name).is_some() || self.named_type_generic_payload_contains_cell_backed_value(name)
                {
                    return true;
                }
                if !visiting.insert(name.clone()) {
                    return false;
                }
                let contains_struct = self.resolve_named_type_fields(name).is_some_and(|fields| {
                    fields.values().any(|field| self.type_contains_cell_backed_value_with_seen(field, visiting))
                });
                let contains_enum = self.resolve_enum_variant_fields(name).is_some_and(|variants| {
                    variants.values().flatten().any(|field| self.type_contains_cell_backed_value_with_seen(field, visiting))
                });
                visiting.remove(name);
                contains_struct || contains_enum
            }
            Type::Ref(_) | Type::MutRef(_) => false,
            _ => false,
        }
    }

    fn named_type_contains_reference(&self, name: &str) -> bool {
        name.contains("read_ref ") || name.contains('&')
    }

    fn named_type_generic_payload<'b>(&self, name: &'b str) -> Option<&'b str> {
        let start = name.find('<')?;
        name.ends_with('>').then_some(&name[start + 1..name.len() - 1])
    }

    fn named_type_generic_payload_contains_cell_backed_value(&self, name: &str) -> bool {
        self.named_type_generic_payload(name).is_some_and(|payload| self.type_fragment_contains_cell_backed_name(payload))
    }

    fn type_fragment_contains_cell_backed_name(&self, fragment: &str) -> bool {
        let mut token = String::new();
        for ch in fragment.chars() {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == ':' {
                token.push(ch);
            } else if self.type_name_token_is_cell_backed(&token) {
                return true;
            } else {
                token.clear();
            }
        }
        self.type_name_token_is_cell_backed(&token)
    }

    fn type_name_token_is_cell_backed(&self, token: &str) -> bool {
        match token {
            "" | "u8" | "u16" | "u32" | "i32" | "u64" | "u128" | "bool" | "Address" | "Hash" | "String" | "Range" | "Vec"
            | "usize" | "isize" | "read_ref" | "mut" => false,
            name => self.resolve_cell_type_kind(name).is_some(),
        }
    }

    fn reference_target_is_cell_backed_aggregate(&self, ty: &Type) -> bool {
        match ty {
            Type::Array(_, _) | Type::Tuple(_) => self.type_contains_cell_backed_value(ty),
            _ => false,
        }
    }

    fn bind_callable_params(&self, env: &mut TypeEnv, params: &[Param], callable_kind: &str, callable_name: &str) -> Result<()> {
        self.bind_callable_params_with_non_linear(env, params, callable_kind, callable_name, &HashSet::new())
    }

    fn bind_callable_params_with_non_linear(
        &self,
        env: &mut TypeEnv,
        params: &[Param],
        callable_kind: &str,
        callable_name: &str,
        non_linear_params: &HashSet<String>,
    ) -> Result<()> {
        let mut seen = HashSet::new();
        for param in params {
            if param.name == "_" {
                return Err(CompileError::new(
                    format!(
                        "{} '{}' parameter must have a stable name; '_' is reserved for local wildcard bindings",
                        callable_kind, callable_name
                    ),
                    param.span,
                ));
            }
            if !seen.insert(param.name.clone()) {
                return Err(CompileError::new(
                    format!("duplicate parameter '{}' in {} '{}'", param.name, callable_kind, callable_name),
                    param.span,
                ));
            }
            self.validate_type(&param.ty)?;
            if callable_kind != "function" && self.enum_type_contains_linear_payload(&param.ty, &mut HashSet::new()) {
                return Err(CompileError::new(
                    format!(
                        "{} '{}' parameter '{}' cannot cross an entry ABI with a linear payload enum; construct and destructure it within one callable",
                        callable_kind, callable_name, param.name
                    ),
                    param.span,
                ));
            }
            self.validate_callable_param_source(param, callable_kind, callable_name)?;
            self.validate_callable_param_reference_shape(param, callable_kind, callable_name)?;
            self.validate_callable_param_state_authority(param, callable_kind, callable_name)?;
            self.validate_callable_param_mutability(param)?;
            let is_linear = self.is_linear_type(&param.ty) && !non_linear_params.contains(param.name.as_str());
            env.bind_new(param.name.clone(), param.ty.clone(), is_linear, param.is_mut, param.span)?;
        }
        Ok(())
    }

    fn validate_callable_param_source(&self, param: &Param, callable_kind: &str, callable_name: &str) -> Result<()> {
        if param.source == ParamSource::Default {
            if parse_bounded_collection_type(&param.ty).is_some() {
                return Err(CompileError::new(
                    format!(
                        "bounded collection parameter '{}' requires an explicit source classification; use input for BoundedCellSet or witness for BoundedList",
                        param.name
                    ),
                    param.span,
                ));
            }
            return Ok(());
        }
        if param.source == ParamSource::Input {
            if callable_kind != "action" {
                return Err(CompileError::new(
                    format!(
                        "{} '{}' parameter '{}' cannot use input source classification; input parameters are action verifier bindings",
                        callable_kind, callable_name, param.name
                    ),
                    param.span,
                ));
            }
            if param.is_mut || param.is_ref || param.is_read_ref || matches!(param.ty, Type::Ref(_) | Type::MutRef(_)) {
                return Err(CompileError::new(
                    format!("input action parameter '{}' must use 'input name: T' without mut/ref/read_ref modifiers", param.name),
                    param.span,
                ));
            }
            if let Some(collection) = parse_bounded_collection_type(&param.ty) {
                if collection.kind != BoundedCollectionKind::CellSet {
                    return Err(CompileError::new(
                        format!("input parameter '{}' may use BoundedCellSet<T, N>, not BoundedList<T, N>", param.name),
                        param.span,
                    ));
                }
                return Ok(());
            }
            let Some(name) = Self::base_type_name(&param.ty) else {
                return Err(CompileError::new(
                    format!("input action parameter '{}' must name a Cell-backed resource, shared cell, or receipt type", param.name),
                    param.span,
                ));
            };
            if self.resolve_cell_type_kind(name).is_none() {
                return Err(CompileError::new(
                    format!(
                        "input action parameter '{}' references non-Cell type {}; input only marks a consumed transaction input Cell",
                        param.name,
                        type_repr(&param.ty)
                    ),
                    param.span,
                ));
            }
            return Ok(());
        }
        if param.source == ParamSource::Output {
            return Err(CompileError::new(
                format!(
                    "{} '{}' parameter '{}' cannot use output source classification; bind transaction outputs on the action return side (`action f(...) -> name: T`)",
                    callable_kind, callable_name, param.name
                ),
                param.span,
            ));
        }
        if param.source == ParamSource::Witness {
            if callable_kind != "action" && callable_kind != "lock" {
                return Err(CompileError::new(
                    format!(
                        "{} '{}' parameter '{}' cannot use witness source classification; witness parameters are action or lock verifier bindings",
                        callable_kind, callable_name, param.name
                    ),
                    param.span,
                ));
            }
            if let Some(collection) = parse_bounded_collection_type(&param.ty)
                && collection.kind != BoundedCollectionKind::List
            {
                return Err(CompileError::new(
                    format!("witness parameter '{}' may use BoundedList<T, N>, not BoundedCellSet<T, N>", param.name),
                    param.span,
                ));
            }
        } else if callable_kind != "lock" {
            return Err(CompileError::new(
                format!(
                    "{} '{}' parameter '{}' cannot use {} source classification; protected and lock_args are lock parameter source syntax",
                    callable_kind,
                    callable_name,
                    param.name,
                    param_source_repr(param.source)
                ),
                param.span,
            ));
        }

        match param.source {
            ParamSource::Protected => {
                if param.is_mut || param.is_read_ref || param.is_ref {
                    return Err(CompileError::new(
                        format!(
                            "protected lock parameter '{}' must use 'protected name: T' without mut/ref/read_ref modifiers",
                            param.name
                        ),
                        param.span,
                    ));
                }
                let Type::Ref(inner) = &param.ty else {
                    return Err(CompileError::new(
                        format!("protected lock parameter '{}' must lower to a read-only Cell view", param.name),
                        param.span,
                    ));
                };
                let Some(name) = Self::base_type_name(inner) else {
                    return Err(CompileError::new(
                        format!(
                            "protected lock parameter '{}' must name a Cell-backed resource, shared cell, or receipt type",
                            param.name
                        ),
                        param.span,
                    ));
                };
                if self.resolve_cell_type_kind(name).is_none() {
                    return Err(CompileError::new(
                        format!(
                            "protected lock parameter '{}' references non-Cell type {}; protected only marks the current lock invocation's Cell spend surface",
                            param.name,
                            type_repr(inner)
                        ),
                        param.span,
                    ));
                }
            }
            ParamSource::Witness => {
                if param.is_mut || param.is_read_ref || matches!(param.ty, Type::Ref(_) | Type::MutRef(_)) {
                    return Err(CompileError::new(
                        format!(
                            "witness lock parameter '{}' must be plain transaction witness data, not a Cell reference",
                            param.name
                        ),
                        param.span,
                    ));
                }
            }
            ParamSource::LockArgs => {
                if param.is_mut || param.is_read_ref || matches!(param.ty, Type::Ref(_) | Type::MutRef(_)) {
                    return Err(CompileError::new(
                        format!(
                            "lock_args lock parameter '{}' must be plain typed script args data, not a Cell reference",
                            param.name
                        ),
                        param.span,
                    ));
                }
                if lock_args_static_type_len(&param.ty).is_none() {
                    return Err(CompileError::new(
                        format!(
                            "lock_args lock parameter '{}' must use a fixed-width script-args type such as Address, Hash, integer, bool, or [u8; N]",
                            param.name
                        ),
                        param.span,
                    ));
                }
            }
            ParamSource::Default | ParamSource::Input | ParamSource::Output => {}
        }
        Ok(())
    }

    fn identity_static_width(ty: &Type) -> Option<usize> {
        lock_args_static_type_len(ty)
    }

    fn validate_callable_param_reference_shape(&self, param: &Param, callable_kind: &str, callable_name: &str) -> Result<()> {
        if matches!(param.ty, Type::MutRef(_)) {
            return Err(CompileError::new(
                format!(
                    "`&mut` Cell parameters are not valid at callable boundaries; use `action(before: T) -> after: T` plus `transition` and `require` constraints in {} '{}'",
                    callable_kind, callable_name
                ),
                param.span,
            ));
        }
        if matches!(callable_kind, "action" | "lock")
            && matches!(param.ty, Type::Ref(_))
            && !param.is_read_ref
            && param.source != ParamSource::Protected
        {
            let help = if callable_kind == "lock" {
                "use `protected name: T` for the guarded lock cell or `read name: T` for a read-only referenced cell"
            } else {
                "use `read name: T` for a read-only referenced cell, or a signature input/output binding for consumed/proposed cells"
            };
            return Err(CompileError::new(
                format!(
                    "{} '{}' parameter '{}' cannot use bare `&T` at the verifier boundary; {}",
                    callable_kind, callable_name, param.name, help
                ),
                param.span,
            ));
        }
        let nested_reference = match &param.ty {
            Type::Ref(inner) | Type::MutRef(inner) => self.type_contains_reference(inner),
            ty => self.type_contains_reference(ty),
        };
        if nested_reference {
            return Err(CompileError::new(
                format!(
                    "parameter '{}' in {} '{}' cannot contain nested reference type {}; references are only supported as top-level callable parameter types",
                    param.name,
                    callable_kind,
                    callable_name,
                    type_repr(&param.ty)
                ),
                param.span,
            ));
        }
        if let Type::Ref(inner) | Type::MutRef(inner) = &param.ty
            && self.reference_target_is_cell_backed_aggregate(inner)
        {
            return Err(CompileError::new(
                    format!(
                        "parameter '{}' in {} '{}' cannot use reference to aggregate containing cell-backed values {}; use a direct '&T' helper view or named action outputs instead",
                        param.name,
                        callable_kind,
                        callable_name,
                        type_repr(&param.ty)
                    ),
                    param.span,
                ));
        }
        Ok(())
    }

    fn validate_callable_param_state_authority(&self, param: &Param, callable_kind: &str, callable_name: &str) -> Result<()> {
        if callable_kind != "action" && matches!(param.ty, Type::MutRef(_)) {
            return Err(CompileError::new(
                format!(
                    "{} '{}' parameter '{}' cannot use mutable reference type {}; use signature-direction outputs for Cell updates",
                    callable_kind,
                    callable_name,
                    param.name,
                    type_repr(&param.ty)
                ),
                param.span,
            ));
        }
        if callable_kind != "action" && self.type_contains_cell_backed_value(&param.ty) {
            return Err(CompileError::new(
                format!(
                    "{} '{}' parameter '{}' cannot use owned cell-backed type {}; use a read-only '&T' parameter for predicate/helper reads or transition ownership in an action",
                    callable_kind,
                    callable_name,
                    param.name,
                    type_repr(&param.ty)
                ),
                param.span,
            ));
        }
        Ok(())
    }

    fn validate_callable_param_mutability(&self, param: &Param) -> Result<()> {
        if !param.is_mut {
            return Ok(());
        }
        if param.is_read_ref || matches!(param.ty, Type::Ref(_)) {
            return Err(CompileError::new(
                format!(
                    "parameter '{}' is a read-only reference; Cell state updates must be modeled with `action(before: T) -> after: T` plus `transition` and `require` constraints",
                    param.name
                ),
                param.span,
            ));
        }
        if matches!(param.ty, Type::MutRef(_)) {
            return Err(CompileError::new(
                format!(
                    "parameter '{}' cannot use `&mut` Cell syntax; use `action(before: T) -> after: T` plus `transition` and `require` constraints",
                    param.name
                ),
                param.span,
            ));
        }
        if Self::base_type_name(&param.ty).and_then(|name| self.resolve_cell_type_kind(name)).is_some() {
            return Err(CompileError::new(
                format!(
                    "cell-backed parameter '{}' cannot use leading 'mut'; use named action outputs (`action(before: {}) -> after: {}`) or consume/create sugar",
                    param.name,
                    type_repr(&param.ty),
                    type_repr(&param.ty)
                ),
                param.span,
            ));
        }
        Ok(())
    }

    fn check_body_statements<'body>(&mut self, env: &mut TypeEnv, body: &'body [Stmt]) -> Result<Option<(TypeEnv, &'body Stmt)>> {
        let Some((last, prefix)) = body.split_last() else {
            return Ok(None);
        };
        for stmt in prefix {
            self.check_stmt(env, stmt)?;
        }
        let tail_base = env.clone();
        self.check_stmt(env, last)?;
        Ok(Some((tail_base, last)))
    }

    fn check_body_statements_diagnostics<'body>(
        &mut self,
        env: &mut TypeEnv,
        body: &'body [Stmt],
        diagnostics: &mut Vec<CompileError>,
    ) -> Option<(TypeEnv, &'body Stmt)> {
        let (last, prefix) = body.split_last()?;
        for stmt in prefix {
            self.check_stmt_diagnostics(env, stmt, diagnostics);
        }
        let tail_base = env.clone();
        self.check_stmt_diagnostics(env, last, diagnostics);
        Some((tail_base, last))
    }

    fn check_stmt_diagnostics(&mut self, env: &mut TypeEnv, stmt: &Stmt, diagnostics: &mut Vec<CompileError>) {
        match stmt {
            Stmt::If(if_stmt) => {
                let condition_ok = match self.infer_expr(env, &if_stmt.condition) {
                    Ok(cond_ty) if self.is_bool_type(&cond_ty) => true,
                    Ok(_) => {
                        diagnostics.push(CompileError::new("if condition must be boolean", if_stmt.span));
                        false
                    }
                    Err(error) => {
                        diagnostics.push(error);
                        false
                    }
                };

                let mut then_env = env.child();
                let then_error_start = diagnostics.len();
                self.check_body_statements_diagnostics(&mut then_env, &if_stmt.then_branch, diagnostics);
                let then_had_errors = diagnostics.len() > then_error_start;
                let then_returns = self.stmts_always_return(&if_stmt.then_branch);

                if let Some(else_branch) = &if_stmt.else_branch {
                    let mut else_env = env.child();
                    let else_error_start = diagnostics.len();
                    self.check_body_statements_diagnostics(&mut else_env, else_branch, diagnostics);
                    let else_had_errors = diagnostics.len() > else_error_start;
                    let else_returns = self.stmts_always_return(else_branch);
                    if condition_ok && !then_had_errors && !else_had_errors {
                        push_diagnostic(
                            diagnostics,
                            env.merge_branch_linear_states(&then_env, then_returns, Some(&else_env), else_returns, if_stmt.span),
                        );
                    }
                } else if condition_ok && !then_had_errors {
                    push_diagnostic(diagnostics, env.merge_branch_linear_states(&then_env, then_returns, None, false, if_stmt.span));
                }
            }
            Stmt::For(for_stmt) => {
                let iter_ty = match self.infer_expr(env, &for_stmt.iterable) {
                    Ok(iter_ty) => iter_ty,
                    Err(error) => {
                        diagnostics.push(error);
                        return;
                    }
                };
                let item_ty = match self.iter_item_type(&iter_ty, for_stmt.span) {
                    Ok(item_ty) => item_ty,
                    Err(error) => {
                        diagnostics.push(error);
                        return;
                    }
                };
                let mut loop_env = env.child();
                if let Err(error) = self.bind_pattern(&mut loop_env, &for_stmt.pattern, &item_ty, false, for_stmt.span) {
                    diagnostics.push(error);
                    return;
                }
                let body_error_start = diagnostics.len();
                self.loop_labels.push(for_stmt.label.clone());
                self.check_body_statements_diagnostics(&mut loop_env, &for_stmt.body, diagnostics);
                self.loop_labels.pop();
                if diagnostics.len() == body_error_start {
                    push_diagnostic(diagnostics, loop_env.check_linear_complete());
                    push_diagnostic(diagnostics, env.reject_loop_linear_state_changes(&loop_env, for_stmt.span));
                    env.merge_existing_type_refinements_from(&loop_env);
                }
            }
            Stmt::While(while_stmt) => {
                let condition_ok = match self.infer_expr(env, &while_stmt.condition) {
                    Ok(cond_ty) if self.is_bool_type(&cond_ty) => true,
                    Ok(_) => {
                        diagnostics.push(CompileError::new("while condition must be boolean", while_stmt.span));
                        false
                    }
                    Err(error) => {
                        diagnostics.push(error);
                        false
                    }
                };
                let mut while_env = env.child();
                let body_error_start = diagnostics.len();
                self.loop_labels.push(while_stmt.label.clone());
                self.check_body_statements_diagnostics(&mut while_env, &while_stmt.body, diagnostics);
                self.loop_labels.pop();
                if condition_ok && diagnostics.len() == body_error_start {
                    push_diagnostic(diagnostics, while_env.check_linear_complete());
                    push_diagnostic(diagnostics, env.reject_loop_linear_state_changes(&while_env, while_stmt.span));
                    env.merge_existing_type_refinements_from(&while_env);
                }
            }
            _ => push_diagnostic(diagnostics, self.check_stmt(env, stmt)),
        }
    }

    fn validate_spawn_ipc_fd_usage(&self, body: &[Stmt]) -> Result<()> {
        let mut state = SpawnIpcFdState::default();
        self.validate_spawn_ipc_fd_usage_statements(body, &mut state)?;
        self.reject_unclosed_spawn_ipc_fds(&state)
    }

    fn validate_spawn_ipc_fd_usage_statements(&self, body: &[Stmt], state: &mut SpawnIpcFdState) -> Result<()> {
        for stmt in body {
            self.validate_spawn_ipc_fd_usage_stmt(stmt, state)?;
        }
        Ok(())
    }

    fn validate_spawn_ipc_fd_usage_stmt(&self, stmt: &Stmt, state: &mut SpawnIpcFdState) -> Result<()> {
        match stmt {
            Stmt::Let(let_stmt) => {
                self.validate_spawn_ipc_fd_usage_expr(&let_stmt.value, state)?;
                self.bind_spawn_ipc_fd_pattern(let_stmt, state);
            }
            Stmt::Expr(expr) | Stmt::Return(ReturnStmt { value: Some(expr), .. }) => {
                self.validate_spawn_ipc_fd_usage_expr(expr, state)?;
            }
            Stmt::Return(ReturnStmt { value: None, .. }) => {}
            Stmt::Break(_) | Stmt::Continue(_) => {}
            Stmt::If(if_stmt) => {
                self.validate_spawn_ipc_fd_usage_expr(&if_stmt.condition, state)?;
                let mut then_state = state.clone();
                self.validate_spawn_ipc_fd_usage_statements(&if_stmt.then_branch, &mut then_state)?;
                if let Some(else_branch) = &if_stmt.else_branch {
                    let mut else_state = state.clone();
                    self.validate_spawn_ipc_fd_usage_statements(else_branch, &mut else_state)?;
                    let closed_on_both_paths: Vec<String> = then_state
                        .closed
                        .intersection(&else_state.closed)
                        .filter(|fd_key| !state.closed.contains(*fd_key))
                        .cloned()
                        .collect();
                    state.closed.extend(closed_on_both_paths);
                }
            }
            Stmt::For(for_stmt) => {
                self.validate_spawn_ipc_fd_usage_expr(&for_stmt.iterable, state)?;
                let mut loop_state = state.clone();
                self.validate_spawn_ipc_fd_usage_statements(&for_stmt.body, &mut loop_state)?;
            }
            Stmt::While(while_stmt) => {
                self.validate_spawn_ipc_fd_usage_expr(&while_stmt.condition, state)?;
                let mut loop_state = state.clone();
                self.validate_spawn_ipc_fd_usage_statements(&while_stmt.body, &mut loop_state)?;
            }
            Stmt::Borrow(borrow_stmt) => self.validate_spawn_ipc_fd_usage_statements(&borrow_stmt.body, state)?,
        }
        Ok(())
    }

    fn validate_spawn_ipc_fd_usage_expr(&self, expr: &Expr, state: &mut SpawnIpcFdState) -> Result<()> {
        match expr {
            Expr::Call(call) => {
                for arg in &call.args {
                    self.validate_spawn_ipc_fd_usage_expr(arg, state)?;
                }
                if let Some(name) = direct_call_name(call) {
                    match name {
                        "pipe_read" => self.require_open_spawn_ipc_fd(call.args.first(), state, "pipe_read", call.span)?,
                        "pipe_write" => self.require_open_spawn_ipc_fd(call.args.first(), state, "pipe_write", call.span)?,
                        "close" => {
                            let Some(fd_key) = call.args.first().and_then(|arg| self.spawn_ipc_fd_key(arg, state)) else {
                                return Ok(());
                            };
                            if state.closed.contains(&fd_key) {
                                return Err(CompileError::new(
                                    "close uses a Spawn/IPC file descriptor after it was already closed",
                                    call.span,
                                ));
                            }
                            state.closed.insert(fd_key);
                        }
                        _ => {}
                    }
                }
            }
            Expr::Assign(assign) => {
                self.validate_spawn_ipc_fd_usage_expr(&assign.target, state)?;
                self.validate_spawn_ipc_fd_usage_expr(&assign.value, state)?;
            }
            Expr::Binary(binary) => {
                self.validate_spawn_ipc_fd_usage_expr(&binary.left, state)?;
                self.validate_spawn_ipc_fd_usage_expr(&binary.right, state)?;
            }
            Expr::Unary(unary) => self.validate_spawn_ipc_fd_usage_expr(&unary.expr, state)?,
            Expr::FieldAccess(field) => self.validate_spawn_ipc_fd_usage_expr(&field.expr, state)?,
            Expr::Index(index) => {
                self.validate_spawn_ipc_fd_usage_expr(&index.expr, state)?;
                self.validate_spawn_ipc_fd_usage_expr(&index.index, state)?;
            }
            Expr::Create(create) => {
                for (_, value) in &create.fields {
                    self.validate_spawn_ipc_fd_usage_expr(value, state)?;
                }
                if let Some(lock) = &create.lock {
                    self.validate_spawn_ipc_fd_usage_expr(lock, state)?;
                }
            }
            Expr::Consume(consume) => self.validate_spawn_ipc_fd_usage_expr(&consume.expr, state)?,
            Expr::Destroy(destroy) => self.validate_spawn_ipc_fd_usage_expr(&destroy.expr, state)?,
            Expr::Claim(claim) => self.validate_spawn_ipc_fd_usage_expr(&claim.receipt, state)?,
            Expr::Settle(settle) => self.validate_spawn_ipc_fd_usage_expr(&settle.expr, state)?,
            Expr::CreateUnique(_) | Expr::ReplaceUnique(_) => {}
            Expr::Assert(assert_expr) => {
                self.validate_spawn_ipc_fd_usage_expr(&assert_expr.condition, state)?;
                self.validate_spawn_ipc_fd_usage_expr(&assert_expr.message, state)?;
            }
            Expr::Require(require_expr) => {
                self.validate_spawn_ipc_fd_usage_expr(&require_expr.condition, state)?;
                if let Some(message) = &require_expr.message {
                    self.validate_spawn_ipc_fd_usage_expr(message, state)?;
                }
            }
            Expr::Block(stmts) => {
                let mut block_state = state.clone();
                self.validate_spawn_ipc_fd_usage_statements(stmts, &mut block_state)?;
                *state = block_state;
            }
            Expr::Tuple(items) | Expr::Array(items) => {
                for item in items {
                    self.validate_spawn_ipc_fd_usage_expr(item, state)?;
                }
            }
            Expr::If(if_expr) => {
                self.validate_spawn_ipc_fd_usage_expr(&if_expr.condition, state)?;
                let mut then_state = state.clone();
                self.validate_spawn_ipc_fd_usage_expr(&if_expr.then_branch, &mut then_state)?;
                let mut else_state = state.clone();
                self.validate_spawn_ipc_fd_usage_expr(&if_expr.else_branch, &mut else_state)?;
                let closed_on_both_paths: Vec<String> = then_state
                    .closed
                    .intersection(&else_state.closed)
                    .filter(|fd_key| !state.closed.contains(*fd_key))
                    .cloned()
                    .collect();
                state.closed.extend(closed_on_both_paths);
            }
            Expr::Cast(cast) => self.validate_spawn_ipc_fd_usage_expr(&cast.expr, state)?,
            Expr::Range(range) => {
                self.validate_spawn_ipc_fd_usage_expr(&range.start, state)?;
                self.validate_spawn_ipc_fd_usage_expr(&range.end, state)?;
            }
            Expr::StructInit(init) => {
                for (_, value) in &init.fields {
                    self.validate_spawn_ipc_fd_usage_expr(value, state)?;
                }
            }
            Expr::Match(match_expr) => {
                self.validate_spawn_ipc_fd_usage_expr(&match_expr.expr, state)?;
                let mut shared_closed: Option<HashSet<String>> = None;
                for arm in &match_expr.arms {
                    let mut arm_state = state.clone();
                    self.validate_spawn_ipc_fd_usage_expr(&arm.value, &mut arm_state)?;
                    shared_closed = Some(match shared_closed {
                        Some(previous) => previous.intersection(&arm_state.closed).cloned().collect(),
                        None => arm_state.closed,
                    });
                }
                if let Some(shared_closed) = shared_closed {
                    let closed_on_all_arms: Vec<String> =
                        shared_closed.into_iter().filter(|fd_key| !state.closed.contains(fd_key)).collect();
                    state.closed.extend(closed_on_all_arms);
                }
            }
            Expr::StdlibCall(call) => {
                for arg in &call.args {
                    self.validate_spawn_ipc_fd_usage_expr(arg, state)?;
                }
            }
            Expr::RequireBlock(require_block) => {
                for expr in &require_block.expressions {
                    self.validate_spawn_ipc_fd_usage_expr(expr, state)?;
                }
            }
            Expr::Preserve(_)
            | Expr::Integer(_)
            | Expr::Bool(_)
            | Expr::String(_)
            | Expr::ByteString(_)
            | Expr::Identifier(_)
            | Expr::ReadRef(_) => {}
            Expr::ReplaceRelation(relation) => {
                if let ReplaceLockTreatment::Exact(lock) | ReplaceLockTreatment::ExactHash(lock) = &relation.lock {
                    self.validate_spawn_ipc_fd_usage_expr(lock, state)?;
                }
                match &relation.data {
                    ReplaceDataTreatment::Fields(treatments) => {
                        for treatment in treatments {
                            if let ReplaceFieldTreatment::Assign(_, value) = treatment {
                                self.validate_spawn_ipc_fd_usage_expr(value, state)?;
                            }
                        }
                    }
                    ReplaceDataTreatment::SameExcept(assigned) => {
                        for (_, value) in assigned {
                            self.validate_spawn_ipc_fd_usage_expr(value, state)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn bind_spawn_ipc_fd_pattern(&self, let_stmt: &LetStmt, state: &mut SpawnIpcFdState) {
        if is_direct_call(&let_stmt.value, "pipe") {
            match &let_stmt.pattern {
                BindingPattern::Name(name) => {
                    state.pipe_tuples.insert(name.clone(), (format!("{}.0", name), format!("{}.1", name)));
                }
                BindingPattern::Tuple(items) if items.len() == 2 => {
                    if let Some(read_name) = binding_pattern_name(&items[0]) {
                        self.register_spawn_ipc_fd_alias(read_name, read_name.to_string(), state);
                    }
                    if let Some(write_name) = binding_pattern_name(&items[1]) {
                        self.register_spawn_ipc_fd_alias(write_name, write_name.to_string(), state);
                    }
                }
                _ => {}
            }
            return;
        }

        if is_direct_call(&let_stmt.value, "inherited_fd") {
            if let BindingPattern::Name(name) = &let_stmt.pattern {
                self.register_spawn_ipc_fd_alias(name, name.clone(), state);
            }
            return;
        }

        if let BindingPattern::Name(name) = &let_stmt.pattern
            && let Some(fd_key) = self.spawn_ipc_fd_key(&let_stmt.value, state)
        {
            self.register_spawn_ipc_fd_alias(name, fd_key, state);
        }
    }

    fn register_spawn_ipc_fd_alias(&self, name: &str, fd_key: String, state: &mut SpawnIpcFdState) {
        state.aliases.insert(name.to_string(), fd_key);
    }

    fn require_open_spawn_ipc_fd(&self, arg: Option<&Expr>, state: &SpawnIpcFdState, operation: &str, span: Span) -> Result<()> {
        let Some(fd_key) = arg.and_then(|expr| self.spawn_ipc_fd_key(expr, state)) else {
            return Ok(());
        };
        if state.closed.contains(&fd_key) {
            return Err(CompileError::new(format!("{} uses a Spawn/IPC file descriptor after close", operation), span));
        }
        Ok(())
    }

    fn spawn_ipc_fd_key(&self, expr: &Expr, state: &SpawnIpcFdState) -> Option<String> {
        match expr {
            Expr::Identifier(name) => state.aliases.get(name).cloned(),
            Expr::FieldAccess(field) => {
                let Expr::Identifier(base) = field.expr.as_ref() else {
                    return None;
                };
                let (read_fd, write_fd) = state.pipe_tuples.get(base)?;
                match field.field.as_str() {
                    "0" => Some(read_fd.clone()),
                    "1" => Some(write_fd.clone()),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn reject_unclosed_spawn_ipc_fds(&self, state: &SpawnIpcFdState) -> Result<()> {
        let mut open_fds: Vec<String> = state
            .aliases
            .values()
            .chain(state.pipe_tuples.values().flat_map(|(read_fd, write_fd)| [read_fd, write_fd]))
            .filter(|fd_key| !state.closed.contains(*fd_key))
            .cloned()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        open_fds.sort();
        if let Some(fd_key) = open_fds.first() {
            return Err(CompileError::new(
                format!(
                    "Spawn/IPC file descriptor '{}' is not closed before callable exit; close every pipe or inherited fd on all static paths",
                    fd_key
                ),
                Span::default(),
            ));
        }
        Ok(())
    }

    fn check_stmt(&mut self, env: &mut TypeEnv, stmt: &Stmt) -> Result<()> {
        match stmt {
            Stmt::Let(let_stmt) => {
                self.reject_direct_borrow_escape(&let_stmt.value, let_stmt.span)?;
                let ty = self.infer_let_value_type(env, let_stmt)?;
                if let Some(ref declared_ty) = let_stmt.ty {
                    self.validate_type(declared_ty)?;
                    if !self.types_equal(&ty, declared_ty) {
                        return Err(CompileError::new(
                            format!("type mismatch: expected {:?}, found {:?}", declared_ty, ty),
                            let_stmt.span,
                        ));
                    }
                }
                if matches!(ty, Type::Unit) {
                    return Err(CompileError::new("cannot bind the result of a function without a return value", let_stmt.span));
                }
                self.reject_borrow_escape_type(&let_stmt.value, &ty, let_stmt.span)?;
                self.reject_local_reference_to_linear_root(env, &let_stmt.value, &ty, let_stmt.span)?;
                self.reject_local_mutable_reference_alias(&ty, let_stmt.span)?;
                self.mark_expr_as_moved(env, &let_stmt.value)?;
                self.bind_pattern(env, &let_stmt.pattern, &ty, let_stmt.is_mut, let_stmt.span)?;
                Ok(())
            }
            Stmt::Expr(expr) => {
                self.infer_expr(env, expr)?;
                Ok(())
            }
            Stmt::Return(ReturnStmt { value: None, .. }) => {
                if let Some(Some(expected)) = &self.current_return_type {
                    return Err(CompileError::new(
                        format!("return without value in function returning {:?}", expected),
                        stmt_span(stmt),
                    ));
                }
                Ok(())
            }
            Stmt::Return(ReturnStmt { value: Some(expr), .. }) => {
                let return_span = stmt_span(stmt);
                self.reject_direct_borrow_escape(expr, return_span)?;
                let ty = match self.current_return_type.clone() {
                    Some(Some(expected)) => self.infer_expr_with_expected_type(env, expr, &expected, return_span)?,
                    _ => self.infer_expr(env, expr)?,
                };
                match &self.current_return_type {
                    Some(Some(expected)) if !self.expr_type_compatible_with_expected(expr, &ty, expected, return_span)? => {
                        return Err(CompileError::new(
                            format!("return type mismatch: expected {:?}, found {:?}", expected, ty),
                            return_span,
                        ));
                    }
                    Some(None) => {
                        return Err(CompileError::new("return value is not allowed in a function without a return type", return_span));
                    }
                    _ => {}
                }
                self.reject_borrow_escape_type(expr, &ty, return_span)?;
                self.mark_expr_as_moved(env, expr)?;
                Ok(())
            }
            Stmt::If(if_stmt) => {
                let cond_ty = self.infer_expr(env, &if_stmt.condition)?;
                if !self.is_bool_type(&cond_ty) {
                    return Err(CompileError::new("if condition must be boolean", if_stmt.span));
                }
                let mut then_env = env.child();
                for stmt in &if_stmt.then_branch {
                    self.check_stmt(&mut then_env, stmt)?;
                }
                let then_returns = self.stmts_always_return(&if_stmt.then_branch);
                if let Some(ref else_branch) = if_stmt.else_branch {
                    let mut else_env = env.child();
                    for stmt in else_branch {
                        self.check_stmt(&mut else_env, stmt)?;
                    }
                    let else_returns = self.stmts_always_return(else_branch);
                    env.merge_branch_linear_states(&then_env, then_returns, Some(&else_env), else_returns, if_stmt.span)?;
                } else {
                    env.merge_branch_linear_states(&then_env, then_returns, None, false, if_stmt.span)?;
                }
                Ok(())
            }
            Stmt::For(for_stmt) => {
                let iter_ty = self.infer_expr(env, &for_stmt.iterable)?;
                let mut loop_env = env.child();
                let item_ty = self.iter_item_type(&iter_ty, for_stmt.span)?;
                self.bind_pattern(&mut loop_env, &for_stmt.pattern, &item_ty, false, for_stmt.span)?;
                self.loop_labels.push(for_stmt.label.clone());
                let body_result: Result<()> = (|| {
                    for stmt in &for_stmt.body {
                        self.check_stmt(&mut loop_env, stmt)?;
                    }
                    Ok(())
                })();
                self.loop_labels.pop();
                body_result?;
                loop_env.check_linear_complete()?;
                env.reject_loop_linear_state_changes(&loop_env, for_stmt.span)?;
                env.merge_existing_type_refinements_from(&loop_env);
                Ok(())
            }
            Stmt::While(while_stmt) => {
                let cond_ty = self.infer_expr(env, &while_stmt.condition)?;
                if !self.is_bool_type(&cond_ty) {
                    return Err(CompileError::new("while condition must be boolean", while_stmt.span));
                }
                let mut while_env = env.child();
                self.loop_labels.push(while_stmt.label.clone());
                let body_result: Result<()> = (|| {
                    for stmt in &while_stmt.body {
                        self.check_stmt(&mut while_env, stmt)?;
                    }
                    Ok(())
                })();
                self.loop_labels.pop();
                body_result?;
                while_env.check_linear_complete()?;
                env.reject_loop_linear_state_changes(&while_env, while_stmt.span)?;
                env.merge_existing_type_refinements_from(&while_env);
                Ok(())
            }
            Stmt::Break(control) | Stmt::Continue(control) => self.check_loop_control(control),
            Stmt::Borrow(borrow_stmt) => self.check_borrow_stmt(env, borrow_stmt),
        }
    }

    fn check_loop_control(&self, control: &LoopControlStmt) -> Result<()> {
        if self.loop_labels.is_empty() {
            return Err(CompileError::new("break and continue are only valid inside a loop", control.span));
        }
        if let Some(label) = &control.label
            && !self.loop_labels.iter().rev().any(|candidate| candidate.as_deref() == Some(label.as_str()))
        {
            return Err(CompileError::new(format!("unknown loop label '{label}'"), control.span));
        }
        Ok(())
    }

    fn check_borrow_stmt(&mut self, env: &mut TypeEnv, borrow_stmt: &BorrowStmt) -> Result<()> {
        let source_ty = env.lookup(&borrow_stmt.root).cloned().ok_or_else(|| {
            CompileError::new(format!("borrow root '{}' is not a local linear value", borrow_stmt.root), borrow_stmt.span)
        })?;
        let (linear_root, mut view_ty) = match source_ty {
            Type::Ref(inner) => {
                let active = self.active_borrows.iter().rev().find(|borrow| borrow.binding == borrow_stmt.root).ok_or_else(|| {
                    CompileError::new(
                        format!("reference '{}' is not an active Cell borrow and cannot be reborrowed", borrow_stmt.root),
                        borrow_stmt.span,
                    )
                })?;
                (active.root.clone(), *inner)
            }
            root_ty => {
                if !self.is_linear_type(&root_ty) {
                    return Err(CompileError::new(
                        format!("borrow root '{}' must be a cell-backed linear value or active read-only borrow", borrow_stmt.root),
                        borrow_stmt.span,
                    ));
                }
                (borrow_stmt.root.clone(), root_ty)
            }
        };
        if env.linear_state(&linear_root) != Some(LinearState::Available) {
            return Err(CompileError::new(format!("borrow root '{}' is no longer available", linear_root), borrow_stmt.span));
        }
        for field in &borrow_stmt.path {
            view_ty = self.lookup_field_type(&view_ty, field, borrow_stmt.span)?;
        }

        let mut borrow_env = env.child();
        borrow_env.bind_new(borrow_stmt.binding.clone(), Type::Ref(Box::new(view_ty.clone())), false, false, borrow_stmt.span)?;
        self.active_borrows.push(ActiveBorrow { root: linear_root, binding: borrow_stmt.binding.clone(), root_ty: view_ty });
        let result = (|| {
            for stmt in &borrow_stmt.body {
                self.check_stmt(&mut borrow_env, stmt)?;
            }
            borrow_env.check_linear_complete()
        })();
        self.active_borrows.pop();
        result?;

        env.merge_existing_linear_states_from(&borrow_env);
        env.merge_existing_type_refinements_from(&borrow_env);
        Ok(())
    }

    fn check_no_unreachable_stmts(&self, stmts: &[Stmt]) -> Result<()> {
        let mut previous_termination_message = None;
        for stmt in stmts {
            if let Some(message) = previous_termination_message {
                return Err(CompileError::new(message, stmt_span(stmt)));
            }
            self.check_no_unreachable_nested(stmt)?;
            previous_termination_message = if self.stmt_always_returns(stmt) {
                Some("unreachable statement after guaranteed return")
            } else if self.stmt_always_terminates_sequence(stmt) {
                Some("unreachable statement after terminating control flow")
            } else {
                None
            };
        }
        Ok(())
    }

    fn stmt_always_terminates_sequence(&self, stmt: &Stmt) -> bool {
        match stmt {
            Stmt::Break(_) | Stmt::Continue(_) => true,
            Stmt::If(if_stmt) => if_stmt.else_branch.as_ref().is_some_and(|else_branch| {
                if_stmt.then_branch.iter().any(|stmt| self.stmt_always_terminates_sequence(stmt))
                    && else_branch.iter().any(|stmt| self.stmt_always_terminates_sequence(stmt))
            }),
            Stmt::Expr(Expr::Block(stmts)) => stmts.iter().any(|stmt| self.stmt_always_terminates_sequence(stmt)),
            Stmt::Borrow(borrow_stmt) => borrow_stmt.body.iter().any(|stmt| self.stmt_always_terminates_sequence(stmt)),
            _ => self.stmt_always_returns(stmt),
        }
    }

    fn check_no_unreachable_nested(&self, stmt: &Stmt) -> Result<()> {
        match stmt {
            Stmt::If(if_stmt) => {
                self.check_no_unreachable_stmts(&if_stmt.then_branch)?;
                if let Some(else_branch) = &if_stmt.else_branch {
                    self.check_no_unreachable_stmts(else_branch)?;
                }
            }
            Stmt::For(for_stmt) => self.check_no_unreachable_stmts(&for_stmt.body)?,
            Stmt::While(while_stmt) => self.check_no_unreachable_stmts(&while_stmt.body)?,
            Stmt::Borrow(borrow_stmt) => self.check_no_unreachable_stmts(&borrow_stmt.body)?,
            Stmt::Expr(Expr::Block(stmts)) => self.check_no_unreachable_stmts(stmts)?,
            _ => {}
        }
        Ok(())
    }

    fn infer_let_value_type(&mut self, env: &mut TypeEnv, let_stmt: &LetStmt) -> Result<Type> {
        if let Some(declared_ty) = &let_stmt.ty {
            return self.infer_expr_with_expected_type(env, &let_stmt.value, declared_ty, let_stmt.span);
        }
        if let Expr::Array(elems) = &let_stmt.value
            && elems.is_empty()
        {
            return match &let_stmt.ty {
                Some(declared @ Type::Array(_, 0)) => Ok(declared.clone()),
                Some(Type::Array(_, size)) => Err(CompileError::new(
                    format!("empty array literal cannot initialize non-empty array of length {}", size),
                    let_stmt.span,
                )),
                Some(_) => Err(CompileError::new("empty array literal requires an array type annotation", let_stmt.span)),
                None => Err(CompileError::new("empty array literal requires an explicit array type annotation", let_stmt.span)),
            };
        }
        self.infer_expr(env, &let_stmt.value)
    }

    fn infer_expr_with_expected_type(&mut self, env: &mut TypeEnv, expr: &Expr, expected_ty: &Type, span: Span) -> Result<Type> {
        match expr {
            Expr::Integer(value) => {
                if let Some(ty) = Self::integer_literal_type_for_expected(*value, expected_ty, span)? {
                    Ok(ty)
                } else {
                    self.infer_expr(env, expr)
                }
            }
            Expr::Binary(binary)
                if matches!(
                    binary.op,
                    BinaryOp::Add
                        | BinaryOp::Sub
                        | BinaryOp::Mul
                        | BinaryOp::Div
                        | BinaryOp::Mod
                        | BinaryOp::BitAnd
                        | BinaryOp::BitOr
                        | BinaryOp::BitXor
                        | BinaryOp::Shl
                        | BinaryOp::Shr
                ) && self.is_numeric_type(expected_ty) =>
            {
                self.infer_numeric_binary_with_expected_type(env, binary, expected_ty, span)
            }
            Expr::Array(elems) => self.infer_array_literal_with_expected_type(env, elems, expected_ty, span),
            Expr::Block(stmts) => self.infer_tail_block_value_with_expected_type(env, stmts, expected_ty, span),
            Expr::If(if_expr) => {
                let cond_ty = self.infer_expr(env, &if_expr.condition)?;
                if !self.is_bool_type(&cond_ty) {
                    return Err(CompileError::new("if expression condition must be boolean", if_expr.span));
                }
                let mut then_env = env.child();
                let then_ty = self.infer_expr_with_expected_type(
                    &mut then_env,
                    &if_expr.then_branch,
                    expected_ty,
                    expr_span(&if_expr.then_branch),
                )?;
                then_env.check_linear_complete()?;
                let mut else_env = env.child();
                let else_ty = self.infer_expr_with_expected_type(
                    &mut else_env,
                    &if_expr.else_branch,
                    expected_ty,
                    expr_span(&if_expr.else_branch),
                )?;
                else_env.check_linear_complete()?;
                if self.types_equal(&then_ty, &else_ty) && self.initializer_types_equal(&then_ty, expected_ty) {
                    env.merge_branch_linear_states(&then_env, false, Some(&else_env), false, if_expr.span)?;
                    Ok(expected_ty.clone())
                } else {
                    Err(CompileError::new(
                        format!("if expression branches must have matching types, got {:?} and {:?}", then_ty, else_ty),
                        if_expr.span,
                    ))
                }
            }
            _ => self.infer_expr(env, expr),
        }
    }

    fn infer_numeric_binary_with_expected_type(
        &mut self,
        env: &mut TypeEnv,
        binary: &BinaryExpr,
        expected_ty: &Type,
        span: Span,
    ) -> Result<Type> {
        let left_ty = if matches!(binary.left.as_ref(), Expr::Integer(_) | Expr::Binary(_)) {
            self.infer_expr_with_expected_type(env, &binary.left, expected_ty, expr_span(&binary.left))?
        } else {
            self.infer_expr(env, &binary.left)?
        };
        self.require_numeric_operand_widenable(&left_ty, expected_ty, "left", span)?;
        if matches!(binary.op, BinaryOp::Shl | BinaryOp::Shr) {
            let right_ty = self.infer_expr(env, &binary.right)?;
            if !Self::is_unsigned_shift_count_type(&right_ty) {
                return Err(CompileError::new("shift amount must have type u8, u16, u32, or u64", binary.span));
            }
            if let Expr::Integer(amount) = binary.right.as_ref() {
                let width = Self::integer_type_width_bits(expected_ty).expect("numeric types have a width");
                if *amount >= width.into() {
                    return Err(CompileError::new(
                        format!("shift amount {} is out of range for {}-bit {}", amount, width, type_repr(expected_ty)),
                        binary.span,
                    )
                    .with_code("E2106"));
                }
            }
            return Ok(expected_ty.clone());
        }

        let right_ty = if matches!(binary.right.as_ref(), Expr::Integer(_) | Expr::Binary(_)) {
            self.infer_expr_with_expected_type(env, &binary.right, expected_ty, expr_span(&binary.right))?
        } else {
            self.infer_expr(env, &binary.right)?
        };
        self.require_numeric_operand_widenable(&right_ty, expected_ty, "right", span)?;
        Ok(expected_ty.clone())
    }

    fn require_numeric_operand_widenable(&self, actual: &Type, expected: &Type, side: &str, span: Span) -> Result<()> {
        if self.types_equal(actual, expected) {
            return Ok(());
        }
        let unsigned = |ty: &Type| matches!(ty, Type::U8 | Type::U16 | Type::U32 | Type::U64 | Type::U128);
        if unsigned(actual) && unsigned(expected) && Self::integer_type_width_bits(actual) <= Self::integer_type_width_bits(expected) {
            return Ok(());
        }
        if matches!(actual, Type::I32) || matches!(expected, Type::I32) {
            return Err(CompileError::new("arithmetic operations require matching numeric types", span));
        }
        Err(CompileError::new(
            format!("binary {side} operand must have expected type {}, found {}", type_repr(expected), type_repr(actual)),
            span,
        ))
    }

    fn infer_array_literal_with_expected_type(
        &mut self,
        env: &mut TypeEnv,
        elems: &[Expr],
        expected_ty: &Type,
        span: Span,
    ) -> Result<Type> {
        if let Type::Named(name) = expected_ty
            && let Some(item_ty) = self.parse_named_collection_item_type(name)
        {
            for elem in elems {
                let actual_ty = self.infer_expr_with_expected_type(env, elem, &item_ty, expr_span(elem))?;
                if self.type_contains_reference(&actual_ty) {
                    return Err(CompileError::new(
                        format!(
                            "Vec literal cannot store reference type {}; Vec<T> values must use owned non-reference items",
                            type_repr(&actual_ty)
                        ),
                        expr_span(elem),
                    ));
                }
                if !self.types_equal(&actual_ty, &item_ty) {
                    return Err(CompileError::new(
                        format!("Vec literal type mismatch: expected {:?}, found {:?}", item_ty, actual_ty),
                        expr_span(elem),
                    ));
                }
            }
            return Ok(expected_ty.clone());
        }

        if let Type::Array(item_ty, expected_len) = expected_ty {
            if elems.len() != *expected_len {
                if elems.is_empty() {
                    return Err(CompileError::new(
                        format!("empty array literal cannot initialize non-empty array of length {}", expected_len),
                        span,
                    ));
                }
                return Err(CompileError::new(
                    format!("array literal length mismatch: expected {}, found {}", expected_len, elems.len()),
                    span,
                ));
            }
            for elem in elems {
                let actual_ty = self.infer_expr_with_expected_type(env, elem, item_ty, expr_span(elem))?;
                if !self.types_equal(&actual_ty, item_ty) {
                    return Err(CompileError::new(
                        format!("array literal type mismatch: expected {:?}, found {:?}", item_ty, actual_ty),
                        expr_span(elem),
                    ));
                }
            }
            return Ok(expected_ty.clone());
        }

        self.infer_expr(env, &Expr::Array(elems.to_vec()))
    }

    fn infer_expr(&mut self, env: &mut TypeEnv, expr: &Expr) -> Result<Type> {
        self.validate_expr_allowed_in_current_callable(expr)?;
        match expr {
            Expr::Integer(value) => Ok(if *value <= u64::MAX as u128 { Type::U64 } else { Type::U128 }),
            Expr::Bool(_) => Ok(Type::Bool),
            Expr::String(_) => Ok(Type::Named("String".to_string())),
            Expr::ByteString(bytes) => Ok(Type::Array(Box::new(Type::U8), bytes.len())),
            Expr::Identifier(name) => {
                if let Some(ty) = env.lookup(name).cloned() {
                    Ok(ty)
                } else if let Some(constant) = self.resolve_constant(name) {
                    Ok(constant.ty)
                } else if let Some(ty) = self.enum_variant_expr_type(name, expr_span(expr))? {
                    Ok(ty)
                } else if let Some(ty) = self.flow_state_expr_type(name, expr_span(expr))? {
                    Ok(ty)
                } else if let Some((prefix, _)) = name.split_once("::") {
                    Ok(Type::Named(prefix.to_string()))
                } else {
                    Err(CompileError::new(format!("undefined variable '{}'", name), Span::default()))
                }
            }
            Expr::Assign(assign) => self.infer_assign_expr(env, assign),
            Expr::Binary(bin) => {
                self.reject_direct_borrow_escape(expr, bin.span)?;
                let left_ty = self.infer_expr(env, &bin.left)?;
                let right_ty = self.infer_expr(env, &bin.right)?;

                match bin.op {
                    BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => {
                        if !self.is_numeric_type(&left_ty) || !self.is_numeric_type(&right_ty) {
                            return Err(CompileError::new("arithmetic operations require numeric types", bin.span));
                        }
                        self.numeric_binary_result_type(&bin.left, &left_ty, &bin.right, &right_ty, bin.span)
                    }
                    BinaryOp::Eq | BinaryOp::Ne => {
                        if !self.binary_operand_types_compatible(&bin.left, &left_ty, &bin.right, &right_ty, bin.span)? {
                            return Err(CompileError::new("comparison requires matching types", bin.span));
                        }
                        Ok(Type::Bool)
                    }
                    BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                        if Self::is_ordered_ckb_temporal_type(&left_ty) || Self::is_ordered_ckb_temporal_type(&right_ty) {
                            if left_ty != right_ty {
                                return Err(CompileError::new("ordering comparison requires matching CKB temporal domains", bin.span));
                            }
                            return Ok(Type::Bool);
                        }
                        if !self.is_numeric_type(&left_ty) || !self.is_numeric_type(&right_ty) {
                            return Err(CompileError::new("ordering comparison requires numeric types", bin.span));
                        }
                        if let Err(err) = self.numeric_binary_result_type(&bin.left, &left_ty, &bin.right, &right_ty, bin.span) {
                            if err.message.starts_with("integer literal") {
                                return Err(err);
                            }
                            return Err(CompileError::new("ordering comparison requires matching numeric types", bin.span));
                        }
                        Ok(Type::Bool)
                    }
                    BinaryOp::And | BinaryOp::Or => {
                        if !self.is_bool_type(&left_ty) || !self.is_bool_type(&right_ty) {
                            return Err(CompileError::new("logical operations require boolean types", bin.span));
                        }
                        Ok(Type::Bool)
                    }
                    BinaryOp::BitAnd | BinaryOp::BitOr | BinaryOp::BitXor => {
                        if !self.is_numeric_type(&left_ty) || !self.is_numeric_type(&right_ty) {
                            return Err(CompileError::new("bitwise operations require integer types", bin.span));
                        }
                        self.numeric_binary_result_type(&bin.left, &left_ty, &bin.right, &right_ty, bin.span)
                    }
                    BinaryOp::Shl | BinaryOp::Shr => {
                        if !self.is_numeric_type(&left_ty) {
                            return Err(CompileError::new("shift left operand must be an integer", bin.span));
                        }
                        if !Self::is_unsigned_shift_count_type(&right_ty) {
                            return Err(CompileError::new("shift amount must have type u8, u16, u32, or u64", bin.span));
                        }
                        if let Expr::Integer(amount) = bin.right.as_ref() {
                            let width = Self::integer_type_width_bits(&left_ty).expect("numeric types have a width");
                            if *amount >= width.into() {
                                return Err(CompileError::new(
                                    format!("shift amount {} is out of range for {}-bit {}", amount, width, type_repr(&left_ty)),
                                    bin.span,
                                )
                                .with_code("E2106"));
                            }
                        }
                        Ok(left_ty)
                    }
                }
            }
            Expr::Unary(unary) => {
                if unary.op != UnaryOp::Deref {
                    self.reject_direct_borrow_escape(expr, unary.span)?;
                }
                let expr_ty = self.infer_expr(env, &unary.expr)?;
                match unary.op {
                    UnaryOp::Neg => {
                        if !self.is_numeric_type(&expr_ty) {
                            return Err(CompileError::new("negation requires numeric type", unary.span));
                        }
                        Ok(expr_ty)
                    }
                    UnaryOp::Not => {
                        if !self.is_bool_type(&expr_ty) {
                            return Err(CompileError::new("logical not requires boolean type", unary.span));
                        }
                        Ok(Type::Bool)
                    }
                    UnaryOp::Ref => Ok(Type::Ref(Box::new(expr_ty))),
                    UnaryOp::Deref => match expr_ty {
                        Type::Ref(inner) | Type::MutRef(inner) if !self.is_linear_type(&inner) => Ok((*inner).clone()),
                        Type::Ref(_) | Type::MutRef(_) => Err(CompileError::new(
                            "cannot materialize a Cell-backed linear value through a read-only borrow",
                            unary.span,
                        )),
                        _ => Err(CompileError::new("cannot dereference a non-reference value", unary.span)),
                    },
                }
            }
            Expr::Call(call) => {
                if let Some(result) = self.infer_enum_constructor_call(env, call)? {
                    return Ok(result);
                }
                if let Some(result) = self.infer_bounded_collection_each(env, call)? {
                    return Ok(result);
                }
                self.reject_forbidden_consensus_call(call)?;
                self.validate_runtime_call_allowed_in_current_callable(call)?;
                let mut arg_types = Vec::with_capacity(call.args.len());
                for arg in &call.args {
                    arg_types.push(self.infer_expr(env, arg)?);
                }
                let return_type = self.infer_call_type(env, call, &arg_types)?;
                for arg in &call.args {
                    self.mark_expr_as_moved(env, arg)?;
                }
                Ok(return_type)
            }
            Expr::FieldAccess(field) => {
                let expr_ty = self.infer_expr(env, &field.expr)?;
                let field_ty = self.lookup_field_type(&expr_ty, &field.field, field.span)?;
                if self.is_linear_type(&field_ty) {
                    return Err(CompileError::new(
                        "field access cannot move a linear value out of an aggregate; use destructuring to bind linear fields",
                        field.span,
                    ));
                }
                Ok(field_ty)
            }
            Expr::Index(index) => {
                self.reject_direct_borrow_escape(expr, index.span)?;
                let expr_ty = self.infer_expr(env, &index.expr)?;
                let index_ty = self.infer_expr(env, &index.index)?;
                if !self.is_numeric_type(&index_ty) {
                    return Err(CompileError::new("index expression requires a numeric index", index.span));
                }
                let item_ty = self.index_result_type(&expr_ty, index.span)?;
                if self.is_linear_type(&item_ty) {
                    return Err(CompileError::new(
                        "index access cannot move a linear value out of an aggregate; use destructuring or explicit iteration that handles each item",
                        index.span,
                    ));
                }
                Ok(item_ty)
            }
            Expr::Create(create) => {
                self.require_create_target_cell_backed(&create.ty, create.span)?;
                self.check_field_initializer(env, &create.ty, &create.fields, create.span, "create")?;
                if let Some(target) = &create.target {
                    let Some(target_ty) = env.lookup(target).cloned() else {
                        return Err(CompileError::new(
                            format!("create target '{}' is not declared as an action output binding", target),
                            create.span,
                        ));
                    };
                    let Type::Named(target_type_name) = target_ty else {
                        return Err(CompileError::new(
                            format!("create target '{}' must be a named Cell output binding", target),
                            create.span,
                        ));
                    };
                    if target_type_name.split('<').next().unwrap_or(target_type_name.as_str()) != create.ty {
                        return Err(CompileError::new(
                            format!(
                                "create target '{}' has type '{}', but initializer constructs '{}'",
                                target, target_type_name, create.ty
                            ),
                            create.span,
                        ));
                    }
                }
                Ok(Type::Named(create.ty.clone()))
            }
            Expr::Consume(consume) => {
                let (_consume_ty, name) = self.require_named_linear_cell_operand(env, &consume.expr, "consume", consume.span)?;
                env.consume(&name)?;
                Ok(Type::U64)
            }
            Expr::Destroy(destroy) => {
                let (destroy_ty, name) = self.require_named_linear_cell_operand(env, &destroy.expr, "destroy", destroy.span)?;
                self.require_capability_operation(&destroy_ty, CapabilityOperation::Destroy, None, destroy.span)?;
                env.destroy(&name)?;
                Ok(Type::U64)
            }
            Expr::ReadRef(read_ref) => {
                self.require_read_ref_target_cell_backed(&read_ref.ty, read_ref.span)?;
                Ok(Type::Ref(Box::new(Type::Named(read_ref.ty.clone()))))
            }
            Expr::Claim(claim) => {
                let (receipt_ty, name) = self.require_named_linear_cell_operand(env, &claim.receipt, "claim", claim.span)?;
                if !self.is_receipt_type(&receipt_ty) {
                    return Err(CompileError::new("claim requires a receipt value", claim.span));
                }
                env.consume(&name)?;
                let receipt_name = Self::base_type_name(&receipt_ty).unwrap_or_default();
                Ok(self.resolve_receipt_claim_output(receipt_name).flatten().unwrap_or(Type::U64))
            }
            Expr::Settle(settle) => {
                let (settle_ty, name) = self.require_named_linear_cell_operand(env, &settle.expr, "settle", settle.span)?;
                env.consume(&name)?;
                Ok(settle_ty)
            }
            Expr::CreateUnique(cu) => {
                self.require_create_target_cell_backed(&cu.ty, cu.span)?;
                self.check_field_initializer(env, &cu.ty, &cu.fields, cu.span, "create_unique")?;
                self.validate_unique_identity_policy(&cu.ty, &cu.identity, cu.span, "create_unique")?;
                self.require_declared_identity_match(&cu.ty, &cu.identity, cu.span, "create_unique")?;
                if let Some(target) = &cu.target {
                    let Some(target_ty) = env.lookup(target).cloned() else {
                        return Err(CompileError::new(
                            format!("create_unique target '{}' is not declared as an action output binding", target),
                            cu.span,
                        ));
                    };
                    let Type::Named(target_type_name) = target_ty else {
                        return Err(CompileError::new(
                            format!("create_unique target '{}' must be a named Cell output binding", target),
                            cu.span,
                        ));
                    };
                    if target_type_name.split('<').next().unwrap_or(target_type_name.as_str()) != cu.ty {
                        return Err(CompileError::new(
                            format!(
                                "create_unique target '{}' has type '{}', but initializer constructs '{}'",
                                target, target_type_name, cu.ty
                            ),
                            cu.span,
                        ));
                    }
                }
                if let Some(lock) = &cu.lock {
                    let lock_ty = self.infer_expr(env, lock)?;
                    if !Self::is_address_like_type(&lock_ty) {
                        return Err(CompileError::new("lock target must be address-like", cu.span));
                    }
                }
                Ok(Type::Named(cu.ty.clone()))
            }
            Expr::ReplaceUnique(ru) => {
                let (input_ty, name) = self.require_named_linear_cell_operand(env, &ru.expr, "replace_unique", ru.span)?;
                let output_ty = Type::Named(ru.ty.clone());
                if !self.types_equal(&input_ty, &output_ty) {
                    return Err(CompileError::new(
                        format!("replace_unique output type '{}' must match consumed input type {:?}", ru.ty, input_ty),
                        ru.span,
                    ));
                }
                self.check_field_initializer(env, &ru.ty, &ru.fields, ru.span, "replace_unique")?;
                self.validate_unique_identity_policy(&ru.ty, &ru.identity, ru.span, "replace_unique")?;
                self.require_capability_operation(&input_ty, CapabilityOperation::ReplaceUnique, Some(&ru.identity), ru.span)?;
                env.consume(&name)?;
                Ok(input_ty)
            }
            Expr::Assert(assert_expr) => {
                let cond_ty = self.infer_expr(env, &assert_expr.condition)?;
                if !self.is_bool_type(&cond_ty) {
                    return Err(CompileError::new("assert condition must be boolean", assert_expr.span));
                }
                if !matches!(assert_expr.message.as_ref(), Expr::String(_)) {
                    return Err(CompileError::new("assert message must be a string literal", expr_span(&assert_expr.message)));
                }
                Ok(Type::Unit)
            }
            Expr::Require(require_expr) => {
                Self::validate_require_condition_is_pure(&require_expr.condition, "require condition")?;
                let cond_ty = self.infer_expr(env, &require_expr.condition)?;
                if !self.is_bool_type(&cond_ty) {
                    return Err(CompileError::new("require condition must be boolean", require_expr.span));
                }
                if let Some(message) = &require_expr.message
                    && !matches!(message.as_ref(), Expr::String(_))
                {
                    return Err(CompileError::new("require message must be a string literal", expr_span(message)));
                }
                Ok(Type::Bool)
            }
            Expr::Block(stmts) => {
                self.reject_direct_borrow_escape(expr, expr_span(expr))?;
                let mut block_env = env.child();
                let last_ty = self.infer_tail_block_value(&mut block_env, stmts)?;
                block_env.check_linear_complete()?;
                env.merge_existing_linear_states_from(&block_env);
                Ok(last_ty)
            }
            Expr::Tuple(elems) => {
                self.reject_direct_borrow_escape(expr, expr_span(expr))?;
                let mut types = Vec::new();
                for elem in elems {
                    types.push(self.infer_expr(env, elem)?);
                }
                Ok(Type::Tuple(types))
            }
            Expr::Array(elems) => {
                self.reject_direct_borrow_escape(expr, expr_span(expr))?;
                if elems.is_empty() {
                    return Err(CompileError::new("empty array literal requires an explicit array type annotation", expr_span(expr)));
                }
                let elem_ty = self.infer_expr(env, &elems[0])?;
                for elem in elems.iter().skip(1) {
                    let next_ty = self.infer_expr(env, elem)?;
                    if !self.types_equal(&elem_ty, &next_ty) {
                        return Err(CompileError::new("array elements must have matching types", expr_span(elem)));
                    }
                }
                Ok(Type::Array(Box::new(elem_ty), elems.len()))
            }
            Expr::If(if_expr) => {
                self.reject_direct_borrow_escape(expr, if_expr.span)?;
                let cond_ty = self.infer_expr(env, &if_expr.condition)?;
                if !self.is_bool_type(&cond_ty) {
                    return Err(CompileError::new("if expression condition must be boolean", if_expr.span));
                }
                let mut then_env = env.child();
                let then_ty = self.infer_expr(&mut then_env, &if_expr.then_branch)?;
                let mut else_env = env.child();
                let else_ty = self.infer_expr(&mut else_env, &if_expr.else_branch)?;
                if self.types_equal(&then_ty, &else_ty) {
                    env.merge_branch_linear_states(&then_env, false, Some(&else_env), false, if_expr.span)?;
                    Ok(then_ty)
                } else {
                    Err(CompileError::new(
                        format!("if expression branches must have matching types, got {:?} and {:?}", then_ty, else_ty),
                        if_expr.span,
                    ))
                }
            }
            Expr::Cast(cast) => {
                self.reject_direct_borrow_escape(expr, cast.span)?;
                let source_ty = self.infer_expr(env, &cast.expr)?;
                self.validate_checked_cast(&cast.expr, &source_ty, &cast.ty, cast.span)?;
                Ok(cast.ty.clone())
            }
            Expr::Range(range) => {
                self.infer_expr(env, &range.start)?;
                self.infer_expr(env, &range.end)?;
                Ok(Type::Named("Range".to_string()))
            }
            Expr::StructInit(init) => {
                self.reject_direct_borrow_escape(expr, init.span)?;
                self.check_field_initializer(env, &init.ty, &init.fields, init.span, "struct literal")?;
                Ok(Type::Named(init.ty.clone()))
            }
            Expr::Match(match_expr) => {
                self.reject_direct_borrow_escape(expr, match_expr.span)?;
                let scrutinee_ty = self.infer_expr(env, &match_expr.expr)?;
                let payloads = self.check_match_patterns(&scrutinee_ty, match_expr)?;
                if self.is_linear_type(&scrutinee_ty) {
                    self.mark_expr_as_moved(env, &match_expr.expr)?;
                }
                let mut arm_ty = None;
                let mut arm_envs = Vec::with_capacity(match_expr.arms.len());
                for (arm, payload) in match_expr.arms.iter().zip(payloads) {
                    let mut arm_env = env.child();
                    for (binding, field_ty) in payload.bindings {
                        self.bind_pattern(&mut arm_env, &BindingPattern::Name(binding), &field_ty, false, arm.span)?;
                    }
                    let ty = self.infer_expr(&mut arm_env, &arm.value)?;
                    if arm_ty.as_ref().is_none_or(|existing| self.types_equal(existing, &ty)) {
                        arm_ty = Some(ty);
                    } else {
                        return Err(CompileError::new("match arms must have matching types", arm.span));
                    }
                    arm_env.check_linear_complete()?;
                    arm_envs.push(arm_env);
                }
                env.merge_match_linear_states(&arm_envs, match_expr.span)?;
                arm_ty.ok_or_else(|| CompileError::new("match expression must contain at least one arm", match_expr.span))
            }
            Expr::RequireBlock(require_block) => {
                for expr in &require_block.expressions {
                    Self::validate_require_condition_is_pure(expr, "require block")?;
                    let ty = self.infer_expr(env, expr)?;
                    if !self.is_bool_type(&ty) {
                        return Err(CompileError::new("require block expressions must be boolean", expr_span(expr)).with_code("E1004"));
                    }
                }
                Ok(Type::Unit)
            }
            Expr::ReplaceRelation(relation) => {
                let before_ty = env.lookup(&relation.before).cloned().ok_or_else(|| {
                    CompileError::new(format!("replace: undefined predecessor binding '{}'", relation.before), relation.span)
                })?;
                let after_ty = env.lookup(&relation.after).cloned().ok_or_else(|| {
                    CompileError::new(format!("replace: undefined successor binding '{}'", relation.after), relation.span)
                })?;
                let (Type::Named(before_name), Type::Named(after_name)) = (&before_ty, &after_ty) else {
                    return Err(CompileError::new(
                        "replace relations need concrete resource bindings for both the predecessor and the successor",
                        relation.span,
                    ));
                };
                if before_name != after_name {
                    return Err(CompileError::new(
                        format!("replace relation type mismatch: predecessor has {before_name}, successor has {after_name}"),
                        relation.span,
                    ));
                }
                let schema_fields = self
                    .resolve_named_type_fields(before_name.split('<').next().unwrap_or(before_name.as_str()))
                    .map(|fields| fields.keys().cloned().collect::<Vec<_>>())
                    .ok_or_else(|| {
                        CompileError::new(
                            format!("replace relation predecessor '{before_name}' does not resolve to a concrete schema"),
                            relation.span,
                        )
                    })?;
                let mut covered: Vec<String> = Vec::new();
                let exhaustive;
                match &relation.data {
                    ReplaceDataTreatment::Fields(treatments) => {
                        exhaustive = true;
                        for treatment in treatments {
                            let (field, value) = match treatment {
                                ReplaceFieldTreatment::Same(field) => (field, None),
                                ReplaceFieldTreatment::Assign(field, value) => (field, Some(value)),
                            };
                            note_replace_field(&schema_fields, &mut covered, field, relation.span)?;
                            if let Some(value) = value {
                                check_replace_assigned_field(self, env, &before_ty, field, value, relation.span)?;
                            }
                        }
                    }
                    // `same except` expands against the concrete schema: every
                    // unlisted field is preserved, so only the listed
                    // assignments need to exist and type-check.
                    ReplaceDataTreatment::SameExcept(assigned) => {
                        exhaustive = false;
                        for (field, value) in assigned {
                            note_replace_field(&schema_fields, &mut covered, field, relation.span)?;
                            check_replace_assigned_field(self, env, &before_ty, field, value, relation.span)?;
                        }
                    }
                }
                if exhaustive && covered.len() != schema_fields.len() {
                    let missing =
                        schema_fields.iter().filter(|field| !covered.contains(field)).cloned().collect::<Vec<_>>().join(", ");
                    return Err(CompileError::new(
                        format!(
                            "replace relation data treatment must cover every field of resource '{before_name}' exactly once; missing {missing}"
                        ),
                        relation.span,
                    ));
                }
                env.consume(&relation.before).map_err(|error| CompileError::new(error.to_string(), relation.span))?;
                match &relation.lock {
                    ReplaceLockTreatment::Exact(lock) => {
                        let lock_ty = self.infer_expr(env, lock)?;
                        if lock_ty != Type::Address {
                            return Err(CompileError::new(
                                format!("replace relation `exact` lock expects an Address, found {}", type_repr(&lock_ty)),
                                relation.span,
                            ));
                        }
                    }
                    ReplaceLockTreatment::ExactHash(lock) => {
                        let lock_ty = self.infer_expr(env, lock)?;
                        if lock_ty != Type::Named(CKB_SCRIPT_HASH_TYPE.to_string()) {
                            return Err(CompileError::new(
                                format!(
                                    "replace relation `exact_hash` lock expects a ScriptHash, found {}; convert a trusted Hash explicitly with ckb::script_hash(hash)",
                                    type_repr(&lock_ty)
                                ),
                                relation.span,
                            ));
                        }
                    }
                    ReplaceLockTreatment::Same => {}
                }
                Ok(Type::Bool)
            }
            Expr::Preserve(preserve) => {
                let output_ty = env.lookup(&preserve.output_name).cloned().ok_or_else(|| {
                    CompileError::new(format!("preserve: undefined output binding '{}'", preserve.output_name), preserve.span)
                })?;
                let input_ty = env.lookup(&preserve.input_name).cloned().ok_or_else(|| {
                    CompileError::new(format!("preserve: undefined input binding '{}'", preserve.input_name), preserve.span)
                })?;
                if preserve.fields.is_empty() {
                    return Err(CompileError::new("preserve block must list at least one field", preserve.span));
                }
                for field in &preserve.fields {
                    let output_field_ty = self.lookup_field_type(&output_ty, field, preserve.span).map_err(|_| {
                        CompileError::new(format!("field '{}' does not exist on output type '{:?}'", field, output_ty), preserve.span)
                            .with_code("E1002")
                    })?;
                    let input_field_ty = self.lookup_field_type(&input_ty, field, preserve.span).map_err(|_| {
                        CompileError::new(format!("field '{}' does not exist on input type '{:?}'", field, input_ty), preserve.span)
                            .with_code("E1003")
                    })?;
                    if !self.types_equal(&output_field_ty, &input_field_ty) {
                        return Err(CompileError::new(
                            format!(
                                "preserve field '{}' type mismatch: output has {}, input has {}",
                                field,
                                type_repr(&output_field_ty),
                                type_repr(&input_field_ty)
                            ),
                            preserve.span,
                        )
                        .with_code("E1004"));
                    }
                }
                Ok(Type::Bool)
            }
            Expr::StdlibCall(call) => self.infer_stdlib_call(env, call),
        }
    }

    fn validate_require_condition_is_pure(expr: &Expr, context: &str) -> Result<()> {
        match expr {
            Expr::Create(_)
            | Expr::Consume(_)
            | Expr::ReplaceRelation(_)
            | Expr::Destroy(_)
            | Expr::ReadRef(_)
            | Expr::Claim(_)
            | Expr::Settle(_)
            | Expr::CreateUnique(_)
            | Expr::ReplaceUnique(_) => {
                return Err(CompileError::new(
                    format!(
                        "{} contains cell/runtime operation; move state transition logic into a separate action statement",
                        context
                    ),
                    expr_span(expr),
                )
                .with_code("E1005"));
            }
            Expr::Require(_) | Expr::RequireBlock(_) | Expr::Preserve(_) | Expr::StdlibCall(_) => {
                return Err(CompileError::new(
                    format!("{} contains verifier-boundary syntax; require expressions must be pure boolean constraints", context),
                    expr_span(expr),
                )
                .with_code("E1005"));
            }
            Expr::If(_) | Expr::Match(_) | Expr::Block(_) => {
                return Err(CompileError::new(
                    format!("{} contains control flow; require expressions must be pure boolean constraints", context),
                    expr_span(expr),
                )
                .with_code("E1006"));
            }
            Expr::Assign(_) => {
                return Err(CompileError::new(
                    format!("{} contains assignment; require expressions must be pure boolean constraints", context),
                    expr_span(expr),
                )
                .with_code("E1005"));
            }
            Expr::Binary(binary) => {
                Self::validate_require_condition_is_pure(&binary.left, context)?;
                Self::validate_require_condition_is_pure(&binary.right, context)?;
            }
            Expr::Unary(unary) => Self::validate_require_condition_is_pure(&unary.expr, context)?,
            Expr::Call(call) => {
                Self::validate_require_condition_is_pure(&call.func, context)?;
                for arg in &call.args {
                    Self::validate_require_condition_is_pure(arg, context)?;
                }
            }
            Expr::FieldAccess(field) => Self::validate_require_condition_is_pure(&field.expr, context)?,
            Expr::Index(index) => {
                Self::validate_require_condition_is_pure(&index.expr, context)?;
                Self::validate_require_condition_is_pure(&index.index, context)?;
            }
            Expr::Assert(assert_expr) => {
                Self::validate_require_condition_is_pure(&assert_expr.condition, context)?;
                Self::validate_require_condition_is_pure(&assert_expr.message, context)?;
            }
            Expr::Tuple(items) | Expr::Array(items) => {
                for item in items {
                    Self::validate_require_condition_is_pure(item, context)?;
                }
            }
            Expr::Cast(cast) => Self::validate_require_condition_is_pure(&cast.expr, context)?,
            Expr::Range(range) => {
                Self::validate_require_condition_is_pure(&range.start, context)?;
                Self::validate_require_condition_is_pure(&range.end, context)?;
            }
            Expr::StructInit(init) => {
                for (_, value) in &init.fields {
                    Self::validate_require_condition_is_pure(value, context)?;
                }
            }
            Expr::Integer(_) | Expr::Bool(_) | Expr::String(_) | Expr::ByteString(_) | Expr::Identifier(_) => {}
        }
        Ok(())
    }

    fn infer_stdlib_call(&mut self, env: &mut TypeEnv, call: &StdlibCallExpr) -> Result<Type> {
        let qualified = format!("std::{}::{}", call.namespace, call.name);
        let signature = crate::stdlib::signature::lookup(&call.namespace, &call.name).ok_or_else(|| {
            CompileError::new(
                format!("unknown stdlib pattern '{}' — each stdlib primitive must have a canonical signature", qualified),
                call.span,
            )
        })?;
        self.validate_stdlib_borrow_call(&qualified, call)?;
        self.validate_stdlib_arity(&qualified, call, signature.arity)?;
        if !signature.allows_preserve_fields && !call.preserve_fields.is_empty() {
            return Err(CompileError::new(format!("{} does not accept a preserve-field block", qualified), call.span));
        }
        match qualified.as_str() {
            "std::cell::same_lock" | "std::cell::preserve_lock" | "std::cell::preserve_capacity" => {
                self.validate_stdlib_arity(&qualified, call, 2)?;
                self.require_named_cell_identifier(env, &call.args[0], &qualified, "output")?;
                self.require_named_cell_identifier(env, &call.args[1], &qualified, "input")?;
                Ok(Type::Bool)
            }
            "std::cell::same_type" | "std::cell::preserve_type" | "std::accounting::conserved" => {
                self.validate_stdlib_arity(&qualified, call, 2)?;
                let left_ty = self.infer_expr(env, &call.args[0])?;
                let right_ty = self.infer_expr(env, &call.args[1])?;
                if qualified == "std::accounting::conserved" {
                    let left_amount = self.lookup_field_type(&left_ty, "amount", call.span)?;
                    let right_amount = self.lookup_field_type(&right_ty, "amount", call.span)?;
                    if !self.types_equal(&left_amount, &right_amount) {
                        return Err(CompileError::new("std::accounting::conserved requires matching amount field types", call.span));
                    }
                }
                Ok(Type::Bool)
            }
            "std::lifecycle::transfer" => {
                self.validate_stdlib_arity(&qualified, call, 3)?;
                let (input_ty, input_name) = self.require_named_linear_cell_operand(env, &call.args[0], &qualified, call.span)?;
                let output_ty = self.require_named_cell_identifier(env, &call.args[1], &qualified, "output")?;
                let lock_ty = self.infer_expr(env, &call.args[2])?;
                if !matches!(lock_ty, Type::Address | Type::Hash) {
                    return Err(CompileError::new("std::lifecycle::transfer lock target must be Address or Hash", call.span));
                }
                if !self.types_equal(&input_ty, &output_ty) {
                    return Err(CompileError::new(
                        "std::lifecycle::transfer input and output must have the same Cell type",
                        call.span,
                    ));
                }
                self.validate_preserve_field_types(&output_ty, &input_ty, &call.preserve_fields, call.span)?;
                self.validate_stdlib_output_field_coverage(&qualified, &output_ty, &call.preserve_fields, call.span)?;
                env.consume(&input_name)?;
                Ok(Type::Bool)
            }
            "std::receipt::claim" => {
                self.validate_stdlib_arity(&qualified, call, 3)?;
                let (input_ty, input_name) = self.require_named_linear_cell_operand(env, &call.args[0], &qualified, call.span)?;
                let output_ty = self.require_named_cell_identifier(env, &call.args[1], &qualified, "output")?;
                self.validate_stdlib_lock_arg(&qualified, &call.args[2], env)?;
                self.validate_preserve_field_types(&output_ty, &input_ty, &call.preserve_fields, call.span)?;
                self.validate_stdlib_output_field_coverage(&qualified, &output_ty, &call.preserve_fields, call.span)?;
                self.validate_receipt_claim_pattern(&input_ty, &output_ty, call.span)?;
                env.consume(&input_name)?;
                Ok(Type::Bool)
            }
            "std::lifecycle::settle" => {
                self.validate_stdlib_arity(&qualified, call, 3)?;
                let (input_ty, input_name) = self.require_named_linear_cell_operand(env, &call.args[0], &qualified, call.span)?;
                let output_ty = self.require_named_cell_identifier(env, &call.args[1], &qualified, "output")?;
                self.validate_stdlib_lock_arg(&qualified, &call.args[2], env)?;
                self.validate_preserve_field_types(&output_ty, &input_ty, &call.preserve_fields, call.span)?;
                self.validate_stdlib_output_field_coverage(&qualified, &output_ty, &call.preserve_fields, call.span)?;
                env.consume(&input_name)?;
                Ok(Type::Bool)
            }
            _ => Err(CompileError::new(
                format!("unknown stdlib pattern '{}' — each stdlib primitive must have a canonical expansion", qualified),
                call.span,
            )),
        }
    }

    fn validate_stdlib_arity(&self, qualified: &str, call: &StdlibCallExpr, expected: usize) -> Result<()> {
        if call.args.len() == expected {
            Ok(())
        } else {
            Err(CompileError::new(format!("{} expects {} arguments, got {}", qualified, expected, call.args.len()), call.span))
        }
    }

    fn validate_stdlib_borrow_call(&self, qualified: &str, call: &StdlibCallExpr) -> Result<()> {
        let read_only = matches!(
            (call.namespace.as_str(), call.name.as_str()),
            ("cell", "same_lock" | "preserve_lock" | "preserve_capacity" | "same_type" | "preserve_type")
                | ("accounting", "conserved")
        );
        for arg in &call.args {
            let Some(borrow) = self.active_borrow_used_by_expr(arg) else {
                continue;
            };
            if !read_only {
                return Err(CompileError::new(
                    format!(
                        "function '{}' has Mutating effect and cannot receive borrowed linear view '{}'",
                        qualified, borrow.binding
                    ),
                    call.span,
                ));
            }
            if !matches!(arg, Expr::Identifier(name) if name == &borrow.binding) {
                return Err(CompileError::new(
                    format!("borrow '{}' cannot escape borrow block rooted at linear value '{}'", borrow.binding, borrow.root),
                    call.span,
                ));
            }
        }
        Ok(())
    }

    fn is_script_args_payload_type(ty: &Type) -> bool {
        match ty {
            Type::Hash => true,
            Type::Array(inner, _) => matches!(inner.as_ref(), Type::U8),
            _ => false,
        }
    }

    fn is_hash_bytes_type(ty: &Type) -> bool {
        matches!(ty, Type::Array(inner, 32) if matches!(inner.as_ref(), Type::U8))
    }

    fn is_script_args_type(ty: &Type) -> bool {
        matches!(ty, Type::Named(name) if name.split('<').next().unwrap_or(name.as_str()) == CKB_SCRIPT_ARGS_TYPE)
    }

    fn is_script_value_type(ty: &Type) -> bool {
        matches!(ty, Type::Named(name) if name.split('<').next().unwrap_or(name.as_str()) == CKB_SCRIPT_VALUE_TYPE)
    }

    fn validate_script_hash_type_literal(value: u128, span: Span) -> Result<()> {
        match value {
            0 | 1 | 2 | 4 => Ok(()),
            _ => Err(CompileError::new("script hash_type must be one of data(0), type(1), data1(2), or data2(4)", span)),
        }
    }

    fn require_named_cell_identifier(&mut self, env: &mut TypeEnv, expr: &Expr, operation: &str, role: &str) -> Result<Type> {
        let ty = self.infer_expr(env, expr)?;
        if !self.is_linear_type(&ty) {
            return Err(CompileError::new(format!("{} {} must be a cell-backed value", operation, role), expr_span(expr)));
        }
        if !matches!(expr, Expr::Identifier(_)) {
            return Err(CompileError::new(format!("{} {} must be a named cell-backed binding", operation, role), expr_span(expr)));
        }
        Ok(ty)
    }

    fn validate_preserve_field_types(&self, output_ty: &Type, input_ty: &Type, fields: &[String], span: Span) -> Result<()> {
        for field in fields {
            let output_field_ty = self.lookup_field_type(output_ty, field, span)?;
            let input_field_ty = self.lookup_field_type(input_ty, field, span)?;
            if !self.types_equal(&output_field_ty, &input_field_ty) {
                return Err(CompileError::new(
                    format!(
                        "preserve field '{}' type mismatch: output has {}, input has {}",
                        field,
                        type_repr(&output_field_ty),
                        type_repr(&input_field_ty)
                    ),
                    span,
                ));
            }
        }
        Ok(())
    }

    fn validate_stdlib_output_field_coverage(&self, qualified: &str, output_ty: &Type, fields: &[String], span: Span) -> Result<()> {
        let Some(output_type_name) = Self::base_type_name(output_ty) else {
            return Err(CompileError::new(format!("{} output must be a named cell-backed type", qualified), span));
        };
        let Some(output_fields) = self.resolve_named_type_fields(output_type_name) else {
            return Err(CompileError::new(format!("{} output type '{}' has no known fields", qualified, output_type_name), span));
        };
        let preserved = fields.iter().map(String::as_str).collect::<HashSet<_>>();
        let missing = output_fields.keys().filter(|field| !preserved.contains(field.as_str())).cloned().collect::<Vec<_>>();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(CompileError::new(
                format!(
                    "{} output construction must cover every '{}' field; missing {}",
                    qualified,
                    output_type_name,
                    missing.join(", ")
                ),
                span,
            ))
        }
    }

    fn validate_stdlib_lock_arg(&mut self, qualified: &str, lock: &Expr, env: &mut TypeEnv) -> Result<()> {
        let lock_ty = self.infer_expr(env, lock)?;
        if matches!(lock_ty, Type::Address | Type::Hash) {
            Ok(())
        } else {
            Err(CompileError::new(format!("{} lock target must be Address or Hash", qualified), expr_span(lock)))
        }
    }

    fn validate_receipt_claim_pattern(&self, receipt_ty: &Type, output_ty: &Type, span: Span) -> Result<()> {
        let Some(receipt_name) = Self::base_type_name(receipt_ty) else {
            return Err(CompileError::new("std::receipt::claim requires a receipt cell input", span));
        };
        if self.resolve_cell_type_kind(receipt_name) != Some(CellTypeKind::Receipt) {
            return Err(CompileError::new("std::receipt::claim requires a receipt cell input", span));
        }
        let Some(Some(declared_output)) = self.resolve_receipt_claim_output(receipt_name) else {
            return Err(CompileError::new(
                format!("std::receipt::claim with an output requires receipt '{}' to declare a claim output type", receipt_name),
                span,
            ));
        };
        if self.types_equal(output_ty, &declared_output) {
            Ok(())
        } else {
            Err(CompileError::new(
                format!(
                    "std::receipt::claim output type mismatch: receipt '{}' declares {}, got {}",
                    receipt_name,
                    type_repr(&declared_output),
                    type_repr(output_ty)
                ),
                span,
            ))
        }
    }

    fn infer_tail_block_value(&mut self, env: &mut TypeEnv, stmts: &[Stmt]) -> Result<Type> {
        let Some((last, prefix)) = stmts.split_last() else {
            return Ok(Type::Unit);
        };
        for stmt in prefix {
            self.check_stmt(env, stmt)?;
        }
        match last {
            Stmt::Expr(expr) => {
                let ty = self.infer_expr(env, expr)?;
                if self.is_linear_type(&ty) {
                    self.mark_expr_as_moved(env, expr)?;
                }
                Ok(ty)
            }
            Stmt::If(if_stmt) if if_stmt.else_branch.is_some() => self.infer_tail_if_stmt_value(env, if_stmt),
            stmt => {
                self.check_stmt(env, stmt)?;
                Ok(Type::Unit)
            }
        }
    }

    fn infer_tail_block_value_with_expected_type(
        &mut self,
        env: &mut TypeEnv,
        stmts: &[Stmt],
        expected_ty: &Type,
        span: Span,
    ) -> Result<Type> {
        let Some((last, prefix)) = stmts.split_last() else {
            return Ok(Type::Unit);
        };
        for stmt in prefix {
            self.check_stmt(env, stmt)?;
        }
        match last {
            Stmt::Expr(expr) => {
                let ty = self.infer_expr_with_expected_type(env, expr, expected_ty, expr_span(expr))?;
                if !self.initializer_types_equal(&ty, expected_ty) {
                    return Err(CompileError::new(
                        format!("block expression type mismatch: expected {:?}, found {:?}", expected_ty, ty),
                        span,
                    ));
                }
                if self.is_linear_type(&ty) {
                    self.mark_expr_as_moved(env, expr)?;
                }
                Ok(expected_ty.clone())
            }
            Stmt::If(if_stmt) if if_stmt.else_branch.is_some() => {
                self.infer_tail_if_stmt_value_with_expected_type(env, if_stmt, expected_ty)
            }
            stmt => {
                self.check_stmt(env, stmt)?;
                Ok(Type::Unit)
            }
        }
    }

    fn infer_tail_if_stmt_value(&mut self, env: &mut TypeEnv, if_stmt: &IfStmt) -> Result<Type> {
        let cond_ty = self.infer_expr(env, &if_stmt.condition)?;
        if !self.is_bool_type(&cond_ty) {
            return Err(CompileError::new("if condition must be boolean", if_stmt.span));
        }
        let Some(else_branch) = &if_stmt.else_branch else {
            return Ok(Type::Unit);
        };

        let mut then_env = env.child();
        let then_ty = self.infer_tail_block_value(&mut then_env, &if_stmt.then_branch)?;
        then_env.check_linear_complete()?;

        let mut else_env = env.child();
        let else_ty = self.infer_tail_block_value(&mut else_env, else_branch)?;
        else_env.check_linear_complete()?;

        if !self.types_equal(&then_ty, &else_ty) {
            return Err(CompileError::new(
                format!("if expression branches must have matching types, got {:?} and {:?}", then_ty, else_ty),
                if_stmt.span,
            ));
        }

        env.merge_branch_linear_states(&then_env, false, Some(&else_env), false, if_stmt.span)?;
        Ok(then_ty)
    }

    fn infer_tail_if_stmt_value_with_expected_type(
        &mut self,
        env: &mut TypeEnv,
        if_stmt: &IfStmt,
        expected_ty: &Type,
    ) -> Result<Type> {
        let cond_ty = self.infer_expr(env, &if_stmt.condition)?;
        if !self.is_bool_type(&cond_ty) {
            return Err(CompileError::new("if condition must be boolean", if_stmt.span));
        }
        let Some(else_branch) = &if_stmt.else_branch else {
            return Ok(Type::Unit);
        };

        let mut then_env = env.child();
        let then_ty =
            self.infer_tail_block_value_with_expected_type(&mut then_env, &if_stmt.then_branch, expected_ty, if_stmt.span)?;
        then_env.check_linear_complete()?;

        let mut else_env = env.child();
        let else_ty = self.infer_tail_block_value_with_expected_type(&mut else_env, else_branch, expected_ty, if_stmt.span)?;
        else_env.check_linear_complete()?;

        if !self.initializer_types_equal(&then_ty, expected_ty) || !self.initializer_types_equal(&else_ty, expected_ty) {
            return Err(CompileError::new(
                format!("if expression branches must have matching types, got {:?} and {:?}", then_ty, else_ty),
                if_stmt.span,
            ));
        }

        env.merge_branch_linear_states(&then_env, false, Some(&else_env), false, if_stmt.span)?;
        Ok(expected_ty.clone())
    }

    fn check_match_patterns(&self, scrutinee_ty: &Type, match_expr: &MatchExpr) -> Result<Vec<MatchPayloadBindings>> {
        let enum_shape = if let Type::Named(enum_name) = scrutinee_ty {
            self.resolve_enum_variants(enum_name).map(|variants| (enum_name.as_str(), variants))
        } else {
            None
        };
        let mut seen = HashSet::new();
        let mut has_catch_all = false;
        let mut payloads = Vec::with_capacity(match_expr.arms.len());
        let mut coverage_rows = Vec::with_capacity(match_expr.arms.len());

        for arm in &match_expr.arms {
            if has_catch_all {
                return Err(CompileError::new(
                    "wildcard pattern '_' or another irrefutable pattern must be the last match arm",
                    arm.span,
                ));
            }
            let analysis = self.analyze_match_pattern(scrutinee_ty, &arm.pattern, arm.span)?;
            for variant in &analysis.covered_variants {
                if !seen.insert(variant.clone()) {
                    return Err(CompileError::new(
                        format!("duplicate exhaustive match coverage for enum variant '{}'", variant),
                        arm.span,
                    ));
                }
            }
            has_catch_all = analysis.irrefutable;
            coverage_rows.push(vec![arm.pattern.clone()]);
            payloads.push(MatchPayloadBindings { bindings: analysis.bindings });
        }

        let matrix_exhaustive = has_catch_all
            || self.match_pattern_matrix_is_exhaustive(std::slice::from_ref(scrutinee_ty), coverage_rows, MATCH_EXHAUSTIVENESS_BUDGET);
        if !matrix_exhaustive {
            if let Some((enum_name, variants)) = enum_shape {
                if seen.len() != variants.len() {
                    let missing = variants.iter().filter(|variant| !seen.contains(*variant)).cloned().collect::<Vec<_>>().join(", ");
                    return Err(CompileError::new(
                        format!("non-exhaustive match for enum '{}'; missing {}", enum_name, missing),
                        match_expr.span,
                    ));
                }
            } else {
                return Err(CompileError::new(
                    "non-enum match requires a final irrefutable binding, tuple/struct pattern, or wildcard arm",
                    match_expr.span,
                ));
            }
        }

        Ok(payloads)
    }

    fn analyze_match_pattern(&self, expected: &Type, pattern: &MatchPattern, span: Span) -> Result<MatchPatternAnalysis> {
        let mut analysis = match pattern {
            MatchPattern::Wildcard => {
                if self.is_linear_type(expected) {
                    return Err(CompileError::new(
                        "wildcard match pattern cannot discard a linear Cell-backed value; bind it and discharge ownership",
                        span,
                    ));
                }
                MatchPatternAnalysis { bindings: Vec::new(), covered_variants: Vec::new(), irrefutable: true }
            }
            MatchPattern::Binding(name) => MatchPatternAnalysis {
                bindings: vec![(name.clone(), expected.clone())],
                covered_variants: Vec::new(),
                irrefutable: true,
            },
            MatchPattern::Tuple(items) => {
                let Type::Tuple(types) = expected else {
                    return Err(CompileError::new(
                        format!("tuple pattern '{}' requires a tuple scrutinee, got {}", pattern, type_repr(expected)),
                        span,
                    ));
                };
                if items.len() != types.len() {
                    return Err(CompileError::new(
                        format!("tuple pattern expects {} field(s), got {}", types.len(), items.len()),
                        span,
                    ));
                }
                self.combine_pattern_children(items.iter().zip(types).map(|(item, ty)| self.analyze_match_pattern(ty, item, span)))?
            }
            MatchPattern::Struct { path, fields } => {
                let Type::Named(type_name) = expected else {
                    return Err(CompileError::new(
                        format!("struct pattern '{}' requires a named value, got {}", pattern, type_repr(expected)),
                        span,
                    ));
                };
                if path != type_name && path.rsplit_once("::").map(|(_, name)| name) != Some(type_name.as_str()) {
                    return Err(CompileError::new(format!("struct pattern '{}' does not match type '{}'", path, type_name), span));
                }
                let declared = self
                    .resolve_named_type_fields(type_name)
                    .ok_or_else(|| CompileError::new(format!("struct pattern type '{}' has no declared fields", type_name), span))?;
                let mut seen_fields = HashSet::new();
                let mut children = Vec::with_capacity(fields.len());
                for (field, child) in fields {
                    if !seen_fields.insert(field.clone()) {
                        return Err(CompileError::new(format!("duplicate struct pattern field '{}'", field), span));
                    }
                    let field_ty = declared.get(field).ok_or_else(|| {
                        CompileError::new(format!("unknown field '{}' in struct pattern for '{}'", field, type_name), span)
                    })?;
                    children.push(self.analyze_match_pattern(field_ty, child, span));
                }
                let missing = declared.keys().filter(|field| !seen_fields.contains(*field)).cloned().collect::<Vec<_>>();
                if !missing.is_empty() {
                    return Err(CompileError::new(
                        format!("struct pattern for '{}' must name every field; missing {}", type_name, missing.join(", ")),
                        span,
                    ));
                }
                self.combine_pattern_children(children.into_iter())?
            }
            MatchPattern::Variant { path, fields } => {
                let Type::Named(enum_name) = expected else {
                    return Err(CompileError::new(
                        format!("enum pattern '{}' requires an enum scrutinee, got {}", pattern, type_repr(expected)),
                        span,
                    ));
                };
                let variants = self.resolve_enum_variants(enum_name).ok_or_else(|| {
                    CompileError::new(format!("match pattern '{}' targets non-enum type '{}'", pattern, enum_name), span)
                })?;
                let Some(variant) = match_pattern_variant(enum_name, path) else {
                    return Err(CompileError::new(format!("match pattern '{}' does not match enum '{}'", pattern, enum_name), span));
                };
                if !variants.iter().any(|candidate| candidate == variant) {
                    return Err(CompileError::new(
                        format!("unknown enum variant '{}::{}' in match pattern", enum_name, variant),
                        span,
                    ));
                }
                let declared = self
                    .resolve_enum_variant_fields(enum_name)
                    .and_then(|variants| variants.get(variant).cloned())
                    .unwrap_or_default();
                if fields.len() != declared.len() {
                    return Err(CompileError::new(
                        format!(
                            "match pattern '{}::{}' expects {} payload pattern(s), got {}",
                            enum_name,
                            variant,
                            declared.len(),
                            fields.len()
                        ),
                        span,
                    ));
                }
                let children = self.combine_pattern_children(
                    fields.iter().zip(&declared).map(|(field, ty)| self.analyze_match_pattern(ty, field, span)),
                )?;
                MatchPatternAnalysis {
                    bindings: children.bindings,
                    covered_variants: if children.irrefutable { vec![variant.to_string()] } else { Vec::new() },
                    irrefutable: variants.len() == 1 && children.irrefutable,
                }
            }
            MatchPattern::Or(patterns) => {
                if patterns.len() < 2 {
                    return Err(CompileError::new("or-pattern requires at least two alternatives", span));
                }
                let alternatives =
                    patterns.iter().map(|pattern| self.analyze_match_pattern(expected, pattern, span)).collect::<Result<Vec<_>>>()?;
                if alternatives.iter().any(|alternative| !alternative.bindings.is_empty()) {
                    return Err(CompileError::new(
                        "or-pattern alternatives cannot bind values in the 0.25 deterministic pattern kernel",
                        span,
                    ));
                }
                let covered_variants =
                    alternatives.iter().flat_map(|alternative| alternative.covered_variants.iter().cloned()).collect::<Vec<_>>();
                MatchPatternAnalysis {
                    bindings: Vec::new(),
                    covered_variants,
                    irrefutable: alternatives.iter().any(|alternative| alternative.irrefutable)
                        || self.match_pattern_matrix_is_exhaustive(
                            std::slice::from_ref(expected),
                            patterns.iter().cloned().map(|pattern| vec![pattern]).collect(),
                            MATCH_EXHAUSTIVENESS_BUDGET,
                        ),
                }
            }
        };

        let mut names = HashSet::new();
        for (name, _) in &analysis.bindings {
            if name == "_" || !names.insert(name.clone()) {
                return Err(CompileError::new(format!("duplicate match binding '{}'", name), span));
            }
        }
        analysis.bindings.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(analysis)
    }

    fn combine_pattern_children(&self, children: impl Iterator<Item = Result<MatchPatternAnalysis>>) -> Result<MatchPatternAnalysis> {
        let mut bindings = Vec::new();
        let mut irrefutable = true;
        for child in children {
            let child = child?;
            bindings.extend(child.bindings);
            irrefutable &= child.irrefutable;
        }
        Ok(MatchPatternAnalysis { bindings, covered_variants: Vec::new(), irrefutable })
    }

    fn match_pattern_matrix_is_exhaustive(&self, types: &[Type], rows: Vec<Vec<MatchPattern>>, budget: usize) -> bool {
        if budget == 0 {
            return false;
        }
        if types.is_empty() {
            return !rows.is_empty();
        }

        let mut expanded = Vec::new();
        for row in rows {
            let Some((head, tail)) = row.split_first() else {
                continue;
            };
            match head {
                MatchPattern::Or(alternatives) => {
                    for alternative in alternatives {
                        let mut next = Vec::with_capacity(row.len());
                        next.push(alternative.clone());
                        next.extend_from_slice(tail);
                        expanded.push(next);
                    }
                }
                _ => expanded.push(row),
            }
        }

        let head_ty = &types[0];
        let tail_types = &types[1..];
        let Some(constructors) = self.match_constructors_for_type(head_ty) else {
            let default_rows = expanded
                .into_iter()
                .filter_map(|row| {
                    matches!(row.first(), Some(MatchPattern::Wildcard | MatchPattern::Binding(_))).then(|| row[1..].to_vec())
                })
                .collect();
            return self.match_pattern_matrix_is_exhaustive(tail_types, default_rows, budget - 1);
        };

        constructors.into_iter().all(|constructor| {
            let mut specialized_rows = Vec::new();
            for row in &expanded {
                let Some((head, tail)) = row.split_first() else {
                    continue;
                };
                let fields = match head {
                    MatchPattern::Wildcard | MatchPattern::Binding(_) => {
                        vec![MatchPattern::Wildcard; constructor.fields.len()]
                    }
                    _ => {
                        let Some(fields) = self.specialize_match_pattern(head_ty, &constructor, head) else {
                            continue;
                        };
                        fields
                    }
                };
                let mut specialized = Vec::with_capacity(fields.len() + tail.len());
                specialized.extend(fields);
                specialized.extend_from_slice(tail);
                specialized_rows.push(specialized);
            }

            let mut specialized_types = constructor.fields.iter().map(|(_, ty)| ty.clone()).collect::<Vec<_>>();
            specialized_types.extend_from_slice(tail_types);
            self.match_pattern_matrix_is_exhaustive(&specialized_types, specialized_rows, budget - 1)
        })
    }

    fn match_constructors_for_type(&self, ty: &Type) -> Option<Vec<MatchConstructor>> {
        match ty {
            Type::Tuple(items) => Some(vec![MatchConstructor {
                name: "tuple".to_string(),
                fields: items.iter().cloned().map(|ty| (None, ty)).collect(),
            }]),
            Type::Named(name) => {
                if let (Some(variants), Some(fields)) = (self.resolve_enum_variants(name), self.resolve_enum_variant_fields(name)) {
                    return Some(
                        variants
                            .into_iter()
                            .map(|variant| MatchConstructor {
                                fields: fields.get(&variant).cloned().unwrap_or_default().into_iter().map(|ty| (None, ty)).collect(),
                                name: variant,
                            })
                            .collect(),
                    );
                }
                let fields = self.resolve_named_type_fields(name)?;
                let mut fields = fields.into_iter().collect::<Vec<_>>();
                fields.sort_by(|left, right| left.0.cmp(&right.0));
                Some(vec![MatchConstructor {
                    name: name.clone(),
                    fields: fields.into_iter().map(|(name, ty)| (Some(name), ty)).collect(),
                }])
            }
            _ => None,
        }
    }

    fn specialize_match_pattern(
        &self,
        expected: &Type,
        constructor: &MatchConstructor,
        pattern: &MatchPattern,
    ) -> Option<Vec<MatchPattern>> {
        match (expected, pattern) {
            (Type::Tuple(_), MatchPattern::Tuple(items)) if constructor.name == "tuple" => Some(items.clone()),
            (Type::Named(enum_name), MatchPattern::Variant { path, fields })
                if match_pattern_variant(enum_name, path) == Some(constructor.name.as_str()) =>
            {
                Some(fields.clone())
            }
            (Type::Named(type_name), MatchPattern::Struct { path, fields })
                if path == type_name || path.rsplit_once("::").map(|(_, name)| name) == Some(type_name.as_str()) =>
            {
                let fields = fields.iter().cloned().collect::<HashMap<_, _>>();
                constructor.fields.iter().map(|(name, _)| name.as_ref().and_then(|name| fields.get(name)).cloned()).collect()
            }
            _ => None,
        }
    }

    fn resolve_enum_variants(&self, enum_name: &str) -> Option<Vec<String>> {
        if let Some(variants) = self.enum_variants.get(enum_name) {
            return Some(variants.clone());
        }
        self.resolver
            .zip(self.current_module.as_deref())
            .and_then(|(resolver, module)| resolver.resolve_type(module, enum_name))
            .and_then(|ty| match ty {
                TypeDef::Enum(enum_def) => Some(enum_def.variants.into_iter().map(|variant| variant.name).collect()),
                _ => None,
            })
    }

    fn resolve_enum_variant_fields(&self, enum_name: &str) -> Option<HashMap<String, Vec<Type>>> {
        if let Some(variants) = self.enum_variant_fields.get(enum_name) {
            return Some(variants.clone());
        }
        self.resolver
            .zip(self.current_module.as_deref())
            .and_then(|(resolver, module)| resolver.resolve_type(module, enum_name))
            .and_then(|ty| match ty {
                TypeDef::Enum(enum_def) => Some(enum_def.variants.into_iter().map(|variant| (variant.name, variant.fields)).collect()),
                _ => None,
            })
    }

    fn check_field_initializer(
        &mut self,
        env: &mut TypeEnv,
        type_name: &str,
        fields: &[(String, Expr)],
        span: Span,
        context: &str,
    ) -> Result<()> {
        let Some(expected_fields) = self.resolve_named_type_fields(type_name) else {
            return Err(CompileError::new(format!("{} target type '{}' has no declared fields", context, type_name), span));
        };

        let mut seen = HashSet::new();
        for (field_name, value) in fields {
            if !seen.insert(field_name.clone()) {
                return Err(CompileError::new(format!("duplicate field '{}' in {} for '{}'", field_name, context, type_name), span));
            }
            let Some(expected_ty) = expected_fields.get(field_name) else {
                return Err(CompileError::new(format!("unknown field '{}' in {} for '{}'", field_name, context, type_name), span));
            };
            let actual_ty = if let Some(flow_ty) = self.flow_state_initializer_type(type_name, field_name, value, expected_ty)? {
                flow_ty
            } else {
                self.infer_expr_with_expected_type(env, value, expected_ty, expr_span(value))?
            };
            if !self.initializer_types_equal(&actual_ty, expected_ty) {
                return Err(CompileError::new(
                    format!(
                        "field '{}' in {} for '{}' has type mismatch: expected {:?}, found {:?}",
                        field_name, context, type_name, expected_ty, actual_ty
                    ),
                    expr_span(value),
                ));
            }
        }

        let missing = expected_fields
            .keys()
            .filter(|field_name| !seen.contains(*field_name))
            .filter(|field_name| {
                !(self.resolve_flow_states(type_name).is_some()
                    && !self.flows.contains_key(type_name)
                    && self.flow_state_fields.get(type_name).is_some_and(|state_field| state_field == field_name.as_str()))
            })
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(CompileError::new(
                format!("{} for '{}' is missing field(s): {}", context, type_name, missing.join(", ")),
                span,
            ));
        }

        Ok(())
    }

    fn flow_state_initializer_type(
        &self,
        type_name: &str,
        field_name: &str,
        value: &Expr,
        expected_ty: &Type,
    ) -> Result<Option<Type>> {
        if self.flow_state_fields.get(type_name).is_none_or(|state_field| state_field != field_name) {
            return Ok(None);
        }
        let Expr::Identifier(state_name) = value else {
            return Ok(None);
        };
        if let Type::Named(enum_name) = expected_ty {
            if self.enum_variant_expr_type(state_name, expr_span(value))?.is_some_and(|ty| self.types_equal(&ty, expected_ty)) {
                return Ok(Some(expected_ty.clone()));
            }
            let Some(states) = self.resolve_flow_states(type_name) else {
                return Ok(None);
            };
            if self.canonical_state_name_for_flow(type_name, Some(enum_name), &states, state_name, expr_span(value)).is_ok() {
                return Ok(Some(expected_ty.clone()));
            }
        } else if !is_state_storage_type(expected_ty) {
            return Ok(None);
        }
        let Some((qualified_type, qualified_state)) = state_name.rsplit_once("::") else {
            return Ok(self.flow_state_index(type_name, state_name).map(|_| expected_ty.clone()));
        };
        if qualified_type == type_name {
            if self.flow_state_index(type_name, state_name).is_some() {
                return Ok(Some(expected_ty.clone()));
            }
            return Err(CompileError::new(format!("unknown flow state '{}::{}'", qualified_type, qualified_state), expr_span(value)));
        }
        if self.resolve_flow_states(qualified_type).is_some() {
            return Err(CompileError::new(
                format!(
                    "flow field '{}.{}' cannot be initialized with '{}::{}'",
                    type_name, field_name, qualified_type, qualified_state
                ),
                expr_span(value),
            ));
        }
        Ok(None)
    }

    fn flow_state_expr_type(&self, name: &str, span: Span) -> Result<Option<Type>> {
        let Some((type_name, state_name)) = name.rsplit_once("::") else {
            return Ok(None);
        };
        let Some(states) = self.resolve_flow_states(type_name) else {
            return Ok(None);
        };
        if states.iter().any(|state| state == state_name) {
            if let Some(spec) = self.flows.get(type_name).and_then(|spec| spec.field_enum_type.as_ref()) {
                return Ok(Some(Type::Named(spec.clone())));
            }
            return Ok(Some(self.flow_state_field_type(type_name).unwrap_or(Type::U64)));
        }
        Err(CompileError::new(format!("unknown flow state '{}::{}'", type_name, state_name), span))
    }

    fn flow_state_field_type(&self, type_name: &str) -> Option<Type> {
        let field_name = self.flow_state_fields.get(type_name)?;
        self.resolve_named_type_fields(type_name)?.get(field_name).cloned()
    }

    fn flow_state_index(&self, type_name: &str, name: &str) -> Option<usize> {
        let states = self.resolve_flow_states(type_name)?;
        if let Some((qualified_type, state_name)) = name.rsplit_once("::") {
            if qualified_type != type_name {
                return None;
            }
            states.iter().position(|state| state == state_name)
        } else {
            states.iter().position(|state| state == name)
        }
    }

    fn validate_unique_identity_policy(&self, type_name: &str, identity: &IdentityPolicy, span: Span, operation: &str) -> Result<()> {
        match identity {
            IdentityPolicy::None | IdentityPolicy::CkbTypeId | IdentityPolicy::ScriptArgs | IdentityPolicy::SingletonType => Ok(()),
            IdentityPolicy::Field(field) => {
                let Some(expected_fields) = self.resolve_named_type_fields(type_name) else {
                    return Err(CompileError::new(
                        format!("{} identity field target type '{}' has no declared fields", operation, type_name),
                        span,
                    ));
                };
                let Some(field_ty) = expected_fields.get(field) else {
                    return Err(CompileError::new(
                        format!("{} identity field '{}' does not exist on '{}'", operation, field, type_name),
                        span,
                    ));
                };
                if Self::identity_static_width(field_ty).is_none() {
                    return Err(CompileError::new(
                        format!(
                            "{} identity field '{}.{}' must be fixed-width so CKB runtime can compare it",
                            operation, type_name, field
                        ),
                        span,
                    ));
                }
                Ok(())
            }
        }
    }

    fn require_create_target_cell_backed(&self, type_name: &str, span: Span) -> Result<()> {
        match self.resolve_cell_type_kind(type_name) {
            Some(CellTypeKind::Resource | CellTypeKind::Shared | CellTypeKind::Receipt) => Ok(()),
            None => Err(CompileError::new(
                format!("create target type '{}' must be a resource, shared, or receipt cell type", type_name),
                span,
            )),
        }
    }

    fn require_read_ref_target_cell_backed(&self, type_name: &str, span: Span) -> Result<()> {
        match self.resolve_cell_type_kind(type_name) {
            Some(CellTypeKind::Resource | CellTypeKind::Shared | CellTypeKind::Receipt) => Ok(()),
            None => Err(CompileError::new(
                format!("read_ref target type '{}' must be a resource, shared, or receipt cell type", type_name),
                span,
            )),
        }
    }

    fn enum_variant_expr_type(&self, name: &str, span: Span) -> Result<Option<Type>> {
        let Some((enum_name, variant)) = name.rsplit_once("::") else {
            return Ok(None);
        };
        let Some(variants) = self.resolve_enum_variants(enum_name) else {
            return Ok(None);
        };
        if !variants.iter().any(|candidate| candidate == variant) {
            return Err(CompileError::new(format!("unknown enum variant '{}::{}'", enum_name, variant), span));
        }
        if self.enum_variant_has_payload(enum_name, variant) {
            return Err(CompileError::new(
                format!("enum payload variant '{}::{}' requires an explicit fixed-width payload constructor call", enum_name, variant),
                span,
            ));
        }
        Ok(Some(Type::Named(enum_name.to_string())))
    }

    fn infer_enum_constructor_call(&mut self, env: &mut TypeEnv, call: &CallExpr) -> Result<Option<Type>> {
        let Expr::Identifier(path) = call.func.as_ref() else {
            return Ok(None);
        };
        let Some((enum_name, variant_name)) = path.rsplit_once("::") else {
            return Ok(None);
        };
        let Some(variants) = self.resolve_enum_variant_fields(enum_name) else {
            return Ok(None);
        };
        let Some(fields) = variants.get(variant_name) else {
            return Err(CompileError::new(format!("unknown enum variant '{}::{}'", enum_name, variant_name), call.span));
        };
        if fields.is_empty() {
            return Err(CompileError::new(
                format!("enum variant '{}::{}' has no payload and must be written without parentheses", enum_name, variant_name),
                call.span,
            ));
        }
        if call.args.len() != fields.len() {
            return Err(CompileError::new(
                format!(
                    "enum variant '{}::{}' expects {} payload value(s), got {}",
                    enum_name,
                    variant_name,
                    fields.len(),
                    call.args.len()
                ),
                call.span,
            ));
        }
        for (argument, expected) in call.args.iter().zip(fields) {
            let actual = self.infer_expr_with_expected_type(env, argument, expected, expr_span(argument))?;
            if !self.types_equal(&actual, expected) {
                return Err(CompileError::new(
                    format!(
                        "enum variant '{}::{}' payload type mismatch: expected {}, found {}",
                        enum_name,
                        variant_name,
                        type_repr(expected),
                        type_repr(&actual)
                    ),
                    expr_span(argument),
                ));
            }
        }
        for argument in &call.args {
            self.mark_expr_as_moved(env, argument)?;
        }
        Ok(Some(Type::Named(enum_name.to_string())))
    }

    fn enum_variant_has_payload(&self, enum_name: &str, variant: &str) -> bool {
        if self.enum_payload_variants.get(enum_name).is_some_and(|payloads| payloads.contains(variant)) {
            return true;
        }
        self.resolver
            .zip(self.current_module.as_deref())
            .and_then(|(resolver, module)| resolver.resolve_type(module, enum_name))
            .is_some_and(|ty| match ty {
                TypeDef::Enum(enum_def) => {
                    enum_def.variants.iter().any(|candidate| candidate.name == variant && !candidate.fields.is_empty())
                }
                _ => false,
            })
    }

    fn validate_expr_allowed_in_current_callable(&self, expr: &Expr) -> Result<()> {
        if matches!(expr, Expr::Require(_) | Expr::RequireBlock(_))
            && !matches!(self.current_callable, Some(CallableKind::Action | CallableKind::Invariant | CallableKind::Lock))
        {
            return Err(CompileError::new(
                "require/preserve is verifier-boundary syntax for actions and locks; use ordinary boolean expressions inside functions",
                expr_span(expr),
            ));
        }
        if matches!(expr, Expr::Preserve(_)) && !matches!(self.current_callable, Some(CallableKind::Action | CallableKind::Lock)) {
            return Err(CompileError::new("preserve is verifier-boundary syntax for actions and locks", expr_span(expr)));
        }
        if matches!(expr, Expr::ReplaceRelation(_))
            && !matches!(self.current_callable, Some(CallableKind::Action | CallableKind::Lock))
        {
            return Err(CompileError::new("replace relations are verifier-boundary syntax for actions and locks", expr_span(expr)));
        }

        let operation = match expr {
            Expr::Create(_) => Some("create"),
            Expr::Consume(_) => Some("consume"),
            Expr::Destroy(_) => Some("destroy"),
            Expr::ReadRef(_) => Some("read_ref"),
            Expr::StdlibCall(call) => {
                let qualified = format!("std::{}::{}", call.namespace, call.name);
                match qualified.as_str() {
                    "std::lifecycle::transfer" | "std::receipt::claim" | "std::lifecycle::settle" => Some("consume"),
                    _ => None,
                }
            }
            Expr::Claim(_) => Some("claim"),
            Expr::Settle(_) => Some("settle"),
            Expr::CreateUnique(_) => Some("create_unique"),
            Expr::ReplaceUnique(_) => Some("replace_unique"),
            _ => None,
        };

        match (self.current_callable, operation) {
            (Some(CallableKind::Invariant), Some(operation)) => {
                return Err(CompileError::new(format!("pure function cannot contain '{}'", operation), expr_span(expr)));
            }
            (Some(CallableKind::Lock), Some(operation)) if operation != "read_ref" => {
                return Err(CompileError::new(
                    format!("lock cannot contain '{}' Cell state transition; move state transition logic into an action", operation),
                    expr_span(expr),
                ));
            }
            _ => {}
        }

        Ok(())
    }

    fn validate_runtime_call_allowed_in_current_callable(&self, call: &CallExpr) -> Result<()> {
        let _ = call;
        Ok(())
    }

    fn initializer_types_equal(&self, actual: &Type, expected: &Type) -> bool {
        self.types_equal(actual, expected)
            || matches!((actual, expected), (Type::Named(actual), Type::Named(expected)) if actual == "Vec" && expected.starts_with("Vec<"))
    }

    fn integer_literal_type_for_expected(value: u128, expected_ty: &Type, span: Span) -> Result<Option<Type>> {
        if !Self::is_integer_literal_target_type(expected_ty) {
            return Ok(None);
        }
        if Self::integer_literal_fits_expected_type(value, expected_ty) {
            Ok(Some(expected_ty.clone()))
        } else {
            Err(CompileError::new(format!("integer literal {} does not fit expected type {}", value, type_repr(expected_ty)), span))
        }
    }

    fn is_integer_literal_target_type(ty: &Type) -> bool {
        match ty {
            Type::U8 | Type::U16 | Type::U32 | Type::I32 | Type::U64 | Type::U128 => true,
            Type::Named(name) => name == "usize" || name == "isize",
            _ => false,
        }
    }

    fn integer_literal_fits_expected_type(value: u128, expected_ty: &Type) -> bool {
        match expected_ty {
            Type::U8 => value <= u8::MAX as u128,
            Type::U16 => value <= u16::MAX as u128,
            Type::U32 => value <= u32::MAX as u128,
            Type::I32 => value <= i32::MAX as u128,
            Type::U64 => value <= u64::MAX as u128,
            Type::U128 => true,
            Type::Named(name) if name == "usize" => value <= u64::MAX as u128,
            Type::Named(name) if name == "isize" => value <= i64::MAX as u128,
            _ => false,
        }
    }

    fn unsigned_widening_rank(ty: &Type) -> Option<u8> {
        match ty {
            Type::U8 => Some(0),
            Type::U16 => Some(1),
            Type::U32 => Some(2),
            Type::U64 => Some(3),
            Type::U128 => Some(4),
            Type::Named(name) if name == "usize" => Some(3),
            _ => None,
        }
    }

    fn unsigned_type_for_rank(rank: u8) -> Type {
        match rank {
            0 => Type::U8,
            1 => Type::U16,
            2 => Type::U32,
            3 => Type::U64,
            _ => Type::U128,
        }
    }

    fn unsigned_widening_result_type(left_ty: &Type, right_ty: &Type) -> Option<Type> {
        let left_rank = Self::unsigned_widening_rank(left_ty)?;
        let right_rank = Self::unsigned_widening_rank(right_ty)?;
        Some(Self::unsigned_type_for_rank(left_rank.max(right_rank)))
    }

    fn expr_type_compatible_with_expected(&self, expr: &Expr, actual_ty: &Type, expected_ty: &Type, span: Span) -> Result<bool> {
        if self.types_equal(actual_ty, expected_ty) {
            return Ok(true);
        }
        if let Expr::Integer(value) = expr {
            return Self::integer_literal_type_for_expected(*value, expected_ty, span).map(|ty| ty.is_some());
        }
        Ok(false)
    }

    fn binary_operand_types_compatible(&self, left: &Expr, left_ty: &Type, right: &Expr, right_ty: &Type, span: Span) -> Result<bool> {
        if self.types_equal(left_ty, right_ty) {
            return Ok(true);
        }
        if let Expr::Integer(value) = left
            && Self::is_integer_literal_target_type(right_ty)
        {
            return Self::integer_literal_type_for_expected(*value, right_ty, span).map(|ty| ty.is_some());
        }
        if let Expr::Integer(value) = right
            && Self::is_integer_literal_target_type(left_ty)
        {
            return Self::integer_literal_type_for_expected(*value, left_ty, span).map(|ty| ty.is_some());
        }
        Ok(false)
    }

    fn numeric_binary_result_type(&self, left: &Expr, left_ty: &Type, right: &Expr, right_ty: &Type, span: Span) -> Result<Type> {
        if self.types_equal(left_ty, right_ty) {
            return Ok(left_ty.clone());
        }
        if let Expr::Integer(value) = left
            && Self::is_integer_literal_target_type(right_ty)
        {
            Self::integer_literal_type_for_expected(*value, right_ty, span)?;
            return Ok(right_ty.clone());
        }
        if let Expr::Integer(value) = right
            && Self::is_integer_literal_target_type(left_ty)
        {
            Self::integer_literal_type_for_expected(*value, left_ty, span)?;
            return Ok(left_ty.clone());
        }
        if let Some(ty) = Self::unsigned_widening_result_type(left_ty, right_ty) {
            return Ok(ty);
        }
        Err(CompileError::new("arithmetic operations require matching numeric types", span))
    }

    fn bind_pattern(&self, env: &mut TypeEnv, pattern: &BindingPattern, ty: &Type, is_mut: bool, span: Span) -> Result<()> {
        match pattern {
            BindingPattern::Name(name) => {
                if name == "_" {
                    if self.is_linear_type(ty) {
                        return Err(CompileError::new("wildcard binding cannot discard a linear value", span));
                    }
                    return Ok(());
                }
                let is_linear = self.is_linear_type(ty);
                env.bind_new(name.clone(), ty.clone(), is_linear, is_mut, span)?;
                Ok(())
            }
            BindingPattern::Wildcard => {
                if self.is_linear_type(ty) {
                    return Err(CompileError::new("wildcard binding cannot discard a linear value", span));
                }
                Ok(())
            }
            BindingPattern::Tuple(items) => {
                let Type::Tuple(types) = ty else {
                    return Err(CompileError::new("tuple binding requires a tuple value", span));
                };
                if items.len() != types.len() {
                    return Err(CompileError::new(
                        format!("tuple binding arity mismatch: pattern has {}, value has {}", items.len(), types.len()),
                        span,
                    ));
                }
                for (item, item_ty) in items.iter().zip(types.iter()) {
                    self.bind_pattern(env, item, item_ty, is_mut, span)?;
                }
                Ok(())
            }
        }
    }

    fn mark_stmt_as_returned(&mut self, env: &mut TypeEnv, tail_base: &TypeEnv, stmt: &Stmt) -> Result<()> {
        match stmt {
            Stmt::Expr(expr) => self.mark_expr_as_moved(env, expr),
            Stmt::Return(ReturnStmt { value: Some(_), .. }) => Ok(()),
            Stmt::If(if_stmt) if matches!(self.current_return_type, Some(Some(_))) => {
                let Some(else_branch) = &if_stmt.else_branch else {
                    return Ok(());
                };
                let then_env = self.branch_env_with_tail_return(tail_base, &if_stmt.then_branch)?;
                let else_env = self.branch_env_with_tail_return(tail_base, else_branch)?;
                let mut merged = tail_base.clone();
                merged.merge_branch_linear_states(&then_env, true, Some(&else_env), true, if_stmt.span)?;
                *env = merged;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn branch_env_with_tail_return(&mut self, base_env: &TypeEnv, branch: &[Stmt]) -> Result<TypeEnv> {
        let mut branch_env = base_env.child();
        let Some((last, prefix)) = branch.split_last() else {
            return Ok(branch_env);
        };
        for stmt in prefix {
            self.check_stmt(&mut branch_env, stmt)?;
        }
        let tail_base = branch_env.clone();
        self.check_stmt(&mut branch_env, last)?;
        self.mark_stmt_as_returned(&mut branch_env, &tail_base, last)?;
        Ok(branch_env)
    }

    fn stmts_always_return(&self, stmts: &[Stmt]) -> bool {
        stmts.iter().any(|stmt| self.stmt_always_returns(stmt))
    }

    fn stmt_always_returns(&self, stmt: &Stmt) -> bool {
        match stmt {
            Stmt::Return(_) => true,
            Stmt::If(if_stmt) => {
                let Some(else_branch) = &if_stmt.else_branch else {
                    return false;
                };
                self.stmts_always_return(&if_stmt.then_branch) && self.stmts_always_return(else_branch)
            }
            Stmt::Expr(Expr::Block(stmts)) => self.stmts_always_return(stmts),
            Stmt::Borrow(borrow_stmt) => self.stmts_always_return(&borrow_stmt.body),
            _ => false,
        }
    }

    fn check_body_returns_or_tail_expr(
        &mut self,
        kind: &str,
        name: &str,
        body: &[Stmt],
        return_type: &Type,
        span: Span,
        env: &TypeEnv,
    ) -> Result<()> {
        if self.body_returns_or_tail_expr(body, return_type, env)? {
            return Ok(());
        }

        Err(CompileError::new(format!("{} '{}' with a return type must return a value on all paths", kind, name), span))
    }

    fn body_returns_or_tail_expr(&mut self, body: &[Stmt], return_type: &Type, env: &TypeEnv) -> Result<bool> {
        if self.stmts_always_return(body) {
            return Ok(true);
        }

        let Some((last, prefix)) = body.split_last() else {
            return Ok(false);
        };
        let mut tail_env = env.clone();
        for stmt in prefix {
            self.check_stmt(&mut tail_env, stmt)?;
        }

        if let Stmt::Expr(expr) = last {
            let tail_ty = self.infer_expr_with_expected_type(&mut tail_env, expr, return_type, expr_span(expr))?;
            if self.initializer_types_equal(&tail_ty, return_type) {
                return Ok(true);
            }
            return Err(CompileError::new(
                format!("tail expression type mismatch: expected {:?}, found {:?}", return_type, tail_ty),
                expr_span(expr),
            ));
        }

        if let Stmt::If(if_stmt) = last {
            let Some(else_branch) = &if_stmt.else_branch else {
                return Ok(false);
            };
            let then_ok = self.body_returns_or_tail_expr(&if_stmt.then_branch, return_type, &tail_env.child())?;
            let else_ok = self.body_returns_or_tail_expr(else_branch, return_type, &tail_env.child())?;
            return Ok(then_ok && else_ok);
        }

        Ok(false)
    }

    fn infer_lock_terminal_stmt(&mut self, env: &mut TypeEnv, stmt: &Stmt) -> Result<Type> {
        match stmt {
            Stmt::Expr(expr) => self.infer_expr(env, expr),
            Stmt::Return(ReturnStmt { value: Some(expr), .. }) => self.infer_expr(env, expr),
            Stmt::If(if_stmt) => {
                let cond_ty = self.infer_expr(env, &if_stmt.condition)?;
                if !self.is_bool_type(&cond_ty) {
                    return Err(CompileError::new("if condition must be boolean", if_stmt.span));
                }
                let mut then_env = env.child();
                let then_ty = if let Some(stmt) = if_stmt.then_branch.last() {
                    for stmt in &if_stmt.then_branch[..if_stmt.then_branch.len().saturating_sub(1)] {
                        self.check_stmt(&mut then_env, stmt)?;
                    }
                    self.infer_lock_terminal_stmt(&mut then_env, stmt)?
                } else {
                    return Err(CompileError::new("lock if branch must end with a bool expression", if_stmt.span));
                };
                let else_branch = if_stmt
                    .else_branch
                    .as_ref()
                    .ok_or_else(|| CompileError::new("lock if statement must have an else branch", if_stmt.span))?;
                let mut else_env = env.child();
                let else_ty = if let Some(stmt) = else_branch.last() {
                    for stmt in &else_branch[..else_branch.len().saturating_sub(1)] {
                        self.check_stmt(&mut else_env, stmt)?;
                    }
                    self.infer_lock_terminal_stmt(&mut else_env, stmt)?
                } else {
                    return Err(CompileError::new("lock else branch must end with a bool expression", if_stmt.span));
                };
                if !self.types_equal(&then_ty, &else_ty) {
                    return Err(CompileError::new("lock branches must return matching types", if_stmt.span));
                }
                Ok(then_ty)
            }
            _ => Err(CompileError::new("lock body must end with an expression or explicit return", stmt_span(stmt))),
        }
    }

    fn mark_expr_as_moved(&mut self, env: &mut TypeEnv, expr: &Expr) -> Result<()> {
        match expr {
            Expr::Identifier(name) => {
                self.reject_active_borrow_root_lifecycle(name, "move", expr_span(expr))?;
                if let Some(ty) = env.lookup(name).cloned()
                    && self.is_linear_type(&ty)
                {
                    env.consume(name)?;
                }
                Ok(())
            }
            Expr::Tuple(items) | Expr::Array(items) => {
                for item in items {
                    self.mark_expr_as_moved(env, item)?;
                }
                Ok(())
            }
            Expr::Cast(cast) => self.mark_expr_as_moved(env, &cast.expr),
            Expr::Assign(assign) => self.mark_expr_as_moved(env, &assign.value),
            Expr::Preserve(_) => Ok(()),
            Expr::Claim(_) | Expr::Settle(_) | Expr::CreateUnique(_) | Expr::ReplaceUnique(_) => Ok(()),
            Expr::Assert(assert_expr) => self.mark_expr_as_moved(env, &assert_expr.condition),
            Expr::Require(require_expr) => {
                self.mark_expr_as_moved(env, &require_expr.condition)?;
                if let Some(message) = &require_expr.message {
                    self.mark_expr_as_moved(env, message)?;
                }
                Ok(())
            }
            Expr::If(if_expr) => {
                let mut then_env = env.child();
                self.mark_expr_as_moved(&mut then_env, &if_expr.then_branch)?;
                let mut else_env = env.child();
                self.mark_expr_as_moved(&mut else_env, &if_expr.else_branch)?;
                env.merge_branch_linear_states(&then_env, false, Some(&else_env), false, if_expr.span)
            }
            Expr::Match(match_expr) => {
                let mut arm_envs = Vec::with_capacity(match_expr.arms.len());
                for arm in &match_expr.arms {
                    let mut arm_env = env.child();
                    self.mark_expr_as_moved(&mut arm_env, &arm.value)?;
                    arm_envs.push(arm_env);
                }
                env.merge_match_linear_states(&arm_envs, match_expr.span)
            }
            Expr::Block(_) => Ok(()),
            _ => Ok(()),
        }
    }

    fn reject_local_reference_to_linear_root(&self, env: &TypeEnv, value: &Expr, ty: &Type, span: Span) -> Result<()> {
        self.reject_stored_linear_reference_alias(env, value, span)?;
        if matches!(value, Expr::Unary(_)) {
            self.reject_unrooted_linear_reference_type(ty, span)?;
        }
        Ok(())
    }

    fn reject_borrow_escape_type(&self, expr: &Expr, ty: &Type, span: Span) -> Result<()> {
        if !self.type_contains_reference(ty) {
            return Ok(());
        }
        let Some(borrow) = self.active_borrow_used_by_expr(expr) else {
            return Ok(());
        };
        Err(CompileError::new(
            format!("borrow '{}' cannot escape borrow block rooted at linear value '{}'", borrow.binding, borrow.root),
            span,
        ))
    }

    fn reject_direct_borrow_escape(&self, expr: &Expr, span: Span) -> Result<()> {
        let Some(borrow) = self.active_borrows.iter().rev().find(|borrow| expr_contains_borrow_marker(expr, &borrow.binding)) else {
            return Ok(());
        };
        Err(CompileError::new(
            format!("borrow '{}' cannot escape borrow block rooted at linear value '{}'", borrow.binding, borrow.root),
            span,
        ))
    }

    fn active_borrow_used_by_expr(&self, expr: &Expr) -> Option<&ActiveBorrow> {
        self.active_borrows.iter().rev().find(|borrow| expr_uses_identifier(expr, &borrow.binding))
    }

    fn reject_active_borrow_root_lifecycle(&self, root: &str, operation: &str, span: Span) -> Result<()> {
        let Some(borrow) = self.active_borrows.iter().rev().find(|borrow| borrow.root == root) else {
            return Ok(());
        };
        Err(CompileError::new(
            format!("borrow '{}' cannot cross {} of linear root '{}'", borrow.binding, operation, borrow.root),
            span,
        ))
    }

    fn validate_borrow_call(
        &self,
        callee_name: &str,
        callee_kind: CallableKind,
        callee_effect: EffectClass,
        params: &[Type],
        call: &CallExpr,
    ) -> Result<()> {
        for (index, arg) in call.args.iter().enumerate() {
            let Some(borrow) = self.active_borrow_used_by_expr(arg) else {
                continue;
            };
            if !matches!(arg, Expr::Identifier(name) if name == &borrow.binding) {
                return Err(CompileError::new(
                    format!("borrow '{}' cannot escape borrow block rooted at linear value '{}'", borrow.binding, borrow.root),
                    call.span,
                ));
            }
            if callee_kind != CallableKind::Function || !matches!(callee_effect, EffectClass::Pure | EffectClass::ReadOnly) {
                return Err(CompileError::new(
                    format!(
                        "function '{}' has {} effect and cannot receive borrowed linear view '{}'",
                        callee_name,
                        callee_effect.as_str(),
                        borrow.binding
                    ),
                    call.span,
                ));
            }
            let compatible =
                params.get(index).is_some_and(|param| matches!(param, Type::Ref(inner) if self.types_equal(inner, &borrow.root_ty)));
            if !compatible {
                return Err(CompileError::new(
                    format!(
                        "function '{}' argument {} must declare a dedicated read-only &{} parameter to receive borrowed view '{}'",
                        callee_name,
                        index + 1,
                        type_repr(&borrow.root_ty),
                        borrow.binding
                    ),
                    call.span,
                ));
            }
        }
        Ok(())
    }

    fn reject_borrow_view_in_builtin_call(&self, callee_name: &str, call: &CallExpr) -> Result<()> {
        let Some(borrow) = call.args.iter().find_map(|arg| self.active_borrow_used_by_expr(arg)) else {
            return Ok(());
        };
        Err(CompileError::new(
            format!(
                "builtin '{}' has no dedicated borrowed-view parameter and cannot receive borrowed linear view '{}'",
                callee_name, borrow.binding
            ),
            call.span,
        ))
    }

    fn reject_stored_linear_reference_alias(&self, env: &TypeEnv, expr: &Expr, span: Span) -> Result<()> {
        match expr {
            Expr::Unary(unary) if matches!(unary.op, UnaryOp::Ref) => {
                if let Some(root) = assignment_root_name(&unary.expr)
                    && let Some(root_ty) = env.lookup(root)
                    && self.is_linear_type(root_ty)
                {
                    return Err(CompileError::new(
                                format!(
                                    "local binding cannot store a read-only reference rooted at linear/resource value '{}'; pass the reference directly to a helper call",
                                    root
                                ),
                                span,
                            ));
                }
                Ok(())
            }
            Expr::Tuple(items) | Expr::Array(items) => {
                for item in items {
                    self.reject_stored_linear_reference_alias(env, item, span)?;
                }
                Ok(())
            }
            Expr::Cast(cast) => self.reject_stored_linear_reference_alias(env, &cast.expr, span),
            Expr::If(if_expr) => {
                self.reject_stored_linear_reference_alias(env, &if_expr.then_branch, span)?;
                self.reject_stored_linear_reference_alias(env, &if_expr.else_branch, span)
            }
            Expr::Match(match_expr) => {
                for arm in &match_expr.arms {
                    self.reject_stored_linear_reference_alias(env, &arm.value, span)?;
                }
                Ok(())
            }
            Expr::Block(stmts) => self.reject_stored_linear_reference_alias_in_tail_stmt(env, stmts, span),
            _ => Ok(()),
        }
    }

    fn reject_stored_linear_reference_alias_in_tail_stmt(&self, env: &TypeEnv, stmts: &[Stmt], span: Span) -> Result<()> {
        let Some(last) = stmts.last() else {
            return Ok(());
        };
        match last {
            Stmt::Expr(expr) | Stmt::Return(ReturnStmt { value: Some(expr), .. }) => {
                self.reject_stored_linear_reference_alias(env, expr, span)
            }
            Stmt::If(if_stmt) => {
                self.reject_stored_linear_reference_alias_in_tail_stmt(env, &if_stmt.then_branch, span)?;
                if let Some(else_branch) = &if_stmt.else_branch {
                    self.reject_stored_linear_reference_alias_in_tail_stmt(env, else_branch, span)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn reject_unrooted_linear_reference_type(&self, ty: &Type, span: Span) -> Result<()> {
        if let Type::Ref(inner) = ty
            && self.is_linear_type(inner)
        {
            return Err(CompileError::new(
                    "local binding cannot store a read-only reference to a linear/resource value; bind the cell value itself or pass the reference directly",
                    span,
                ));
        }
        Ok(())
    }

    fn reject_local_mutable_reference_alias(&self, ty: &Type, span: Span) -> Result<()> {
        if Self::type_contains_mutable_reference(ty) {
            return Err(CompileError::new(
                format!(
                    "local binding cannot store mutable reference type {}; use signature-direction outputs for Cell updates",
                    type_repr(ty)
                ),
                span,
            ));
        }
        Ok(())
    }

    fn infer_assign_expr(&mut self, env: &mut TypeEnv, assign: &AssignExpr) -> Result<Type> {
        self.reject_direct_borrow_escape(&assign.value, assign.span)?;
        match assign.target.as_ref() {
            Expr::Identifier(name) => {
                let Some(target_ty) = env.lookup(name).cloned() else {
                    return Err(CompileError::new(format!("undefined variable '{}'", name), assign.span));
                };
                let value_ty = self.infer_expr_with_expected_type(env, &assign.value, &target_ty, expr_span(&assign.value))?;
                self.reject_borrow_escape_type(&assign.value, &value_ty, assign.span)?;
                self.reject_assignment_reference_to_linear_root(env, &assign.value, assign.span)?;
                self.reject_assignment_mutable_reference_alias(&value_ty, assign.span)?;
                if self.is_linear_type(&target_ty) {
                    return Err(CompileError::new("assignment to linear/resource variables is not supported yet", assign.span));
                }
                if !env.is_mutable(name) {
                    return Err(CompileError::new(format!("variable '{}' is not mutable", name), assign.span));
                }
                match assign.op {
                    AssignOp::Assign => {
                        if !self.expr_type_compatible_with_expected(&assign.value, &value_ty, &target_ty, assign.span)? {
                            return Err(CompileError::new("assignment requires matching types", assign.span));
                        }
                    }
                    AssignOp::AddAssign => {
                        if !self.is_numeric_type(&target_ty) || !self.is_numeric_type(&value_ty) {
                            return Err(CompileError::new("'+=' requires numeric types", assign.span));
                        }
                        if !self.expr_type_compatible_with_expected(&assign.value, &value_ty, &target_ty, assign.span)? {
                            return Err(CompileError::new("'+=' requires matching numeric types", assign.span));
                        }
                    }
                }
                Ok(target_ty)
            }
            Expr::FieldAccess(_) | Expr::Index(_) => {
                let Some(root) = assignment_root_name(assign.target.as_ref()) else {
                    return Err(CompileError::new("assignment target must be rooted at a named local or parameter", assign.span));
                };
                let Some(root_ty) = env.lookup(root).cloned() else {
                    return Err(CompileError::new(format!("undefined variable '{}'", root), assign.span));
                };
                if matches!(root_ty, Type::Ref(_)) {
                    return Err(CompileError::new(
                        format!("assignment target rooted at '{}' is a read-only reference", root),
                        assign.span,
                    ));
                }
                let root_is_mut_ref = matches!(root_ty, Type::MutRef(_));
                if !root_is_mut_ref && self.is_linear_type(&root_ty) {
                    return Err(CompileError::new(
                        format!(
                            "assignment target rooted at linear/resource value '{}' is not supported; use explicit input/output parameters or consume/create sugar for ownership transitions",
                            root
                        ),
                        assign.span,
                    ));
                }
                if !env.is_mutable(root) && !root_is_mut_ref {
                    return Err(CompileError::new(format!("assignment target rooted at '{}' is not mutable", root), assign.span));
                }
                let target_ty = self.infer_expr(env, &assign.target)?;
                let value_ty = self.infer_expr_with_expected_type(env, &assign.value, &target_ty, expr_span(&assign.value))?;
                self.reject_borrow_escape_type(&assign.value, &value_ty, assign.span)?;
                self.reject_assignment_reference_to_linear_root(env, &assign.value, assign.span)?;
                self.reject_assignment_mutable_reference_alias(&value_ty, assign.span)?;
                match assign.op {
                    AssignOp::Assign => {
                        if !self.expr_type_compatible_with_expected(&assign.value, &value_ty, &target_ty, assign.span)? {
                            return Err(CompileError::new("assignment requires matching types", assign.span));
                        }
                    }
                    AssignOp::AddAssign => {
                        if !self.is_numeric_type(&target_ty) || !self.is_numeric_type(&value_ty) {
                            return Err(CompileError::new("'+=' requires numeric types", assign.span));
                        }
                        if !self.expr_type_compatible_with_expected(&assign.value, &value_ty, &target_ty, assign.span)? {
                            return Err(CompileError::new("'+=' requires matching numeric types", assign.span));
                        }
                    }
                }
                Ok(target_ty)
            }
            _ => Err(CompileError::new("invalid assignment target", assign.span)),
        }
    }

    fn reject_assignment_reference_to_linear_root(&self, env: &TypeEnv, value: &Expr, span: Span) -> Result<()> {
        self.reject_stored_linear_reference_alias(env, value, span)
    }

    fn reject_assignment_mutable_reference_alias(&self, ty: &Type, span: Span) -> Result<()> {
        if Self::type_contains_mutable_reference(ty) {
            return Err(CompileError::new(
                format!(
                    "assignment cannot store mutable reference type {}; use signature-direction outputs for Cell updates",
                    type_repr(ty)
                ),
                span,
            ));
        }
        Ok(())
    }

    fn index_result_type(&self, ty: &Type, span: Span) -> Result<Type> {
        match ty {
            Type::Array(elem, _) => Ok((**elem).clone()),
            Type::Ref(inner) | Type::MutRef(inner) => self.index_result_type(inner, span),
            Type::Named(name) => self
                .parse_named_collection_item_type(name)
                .ok_or_else(|| CompileError::new(format!("indexing is not supported for type '{}'", name), span)),
            _ => Err(CompileError::new("indexing requires an array-like value", span)),
        }
    }

    fn iter_item_type(&self, ty: &Type, span: Span) -> Result<Type> {
        match ty {
            Type::Array(elem, _) => Ok((**elem).clone()),
            Type::Ref(inner) => Ok(Type::Ref(Box::new(self.iter_item_type(inner, span)?))),
            Type::MutRef(inner) => Ok(Type::MutRef(Box::new(self.iter_item_type(inner, span)?))),
            Type::Named(name) if name == "Range" => Ok(Type::U64),
            Type::Named(name) => self
                .parse_named_collection_item_type(name)
                .ok_or_else(|| CompileError::new(format!("cannot iterate over type '{}'", name), span)),
            _ => Err(CompileError::new("for-loop iterable must be a range or collection type", span)),
        }
    }

    fn parse_named_collection_item_type(&self, name: &str) -> Option<Type> {
        if let Some(inner) = name.strip_prefix("Vec<").and_then(|rest| rest.strip_suffix('>')) {
            return Some(self.parse_named_type_repr(inner));
        }
        None
    }

    fn supports_collection_len(&self, ty: &Type) -> bool {
        match ty {
            Type::Array(_, _) => true,
            Type::Ref(inner) | Type::MutRef(inner) => self.supports_collection_len(inner),
            Type::Named(name) => name == "Vec" || self.parse_named_collection_item_type(name).is_some(),
            _ => false,
        }
    }

    fn slice_item_type(ty: &Type) -> Option<Type> {
        match ty {
            Type::Array(inner, _) => Some((**inner).clone()),
            Type::Ref(inner) | Type::MutRef(inner) => Self::slice_item_type(inner),
            _ => None,
        }
    }

    fn parse_named_type_repr(&self, repr: &str) -> Type {
        match repr.trim() {
            "u8" => Type::U8,
            "u16" => Type::U16,
            "u32" => Type::U32,
            "i32" => Type::I32,
            "u64" => Type::U64,
            "u128" => Type::U128,
            "bool" => Type::Bool,
            "Address" => Type::Address,
            "Hash" => Type::Hash,
            other => Type::Named(other.to_string()),
        }
    }

    fn lookup_field_type(&self, ty: &Type, field: &str, span: Span) -> Result<Type> {
        match ty {
            Type::U64 if field == "lock" => Ok(Type::Named(CKB_LOCK_SCRIPT_REF_TYPE.to_string())),
            Type::U64 if field == "type" || field == "type_script" => Ok(Type::Named(CKB_TYPE_SCRIPT_REF_TYPE.to_string())),
            Type::Address | Type::Hash => {
                if field == "0" {
                    return Ok(Type::Array(Box::new(Type::U8), 32));
                }
                Err(CompileError::new(format!("builtin value '{:?}' only exposes tuple field '0'", ty), span))
            }
            Type::Tuple(items) => {
                if let Ok(index) = field.parse::<usize>() {
                    if let Some(item_ty) = items.get(index) {
                        return Ok(item_ty.clone());
                    }
                    return Err(CompileError::new(format!("tuple field '{}' is out of bounds", field), span));
                }
                Err(CompileError::new(format!("tuple field '{}' must be a numeric index", field), span))
            }
            Type::Ref(inner) | Type::MutRef(inner) => self.lookup_field_type(inner, field, span),
            Type::Named(name) => {
                let base_name = name.split('<').next().unwrap_or(name.as_str());
                if matches!(base_name, CKB_INPUT_VIEW_TYPE | CKB_OUTPUT_VIEW_TYPE | CKB_CELL_DEP_VIEW_TYPE) {
                    return match field {
                        "capacity" | "occupied_capacity" | "unoccupied_capacity" | "data_size" => Ok(Type::U64),
                        "output_index" if base_name == CKB_OUTPUT_VIEW_TYPE => Ok(Type::U64),
                        "lock_hash" | "type_hash" => Ok(Type::Named(CKB_SCRIPT_HASH_TYPE.to_string())),
                        "data_hash" => Ok(Type::Hash),
                        "lock" | "type" | "type_script" => Ok(Type::Named(CKB_SCRIPT_VIEW_TYPE.to_string())),
                        "out_point" if base_name == CKB_INPUT_VIEW_TYPE => Ok(Type::Named(CKB_OUT_POINT_TYPE.to_string())),
                        "since" if base_name == CKB_INPUT_VIEW_TYPE => Ok(Type::Named(CKB_ENCODED_SINCE_TYPE.to_string())),
                        _ => Err(CompileError::new(
                            format!(
                                "unknown transaction-view field '{}'; expected capacity, occupied_capacity, unoccupied_capacity, data_size, data_hash, lock_hash, type_hash, lock, type_script{}",
                                field,
                                match base_name {
                                    CKB_INPUT_VIEW_TYPE => ", out_point, or since",
                                    CKB_OUTPUT_VIEW_TYPE => ", or output_index",
                                    _ => "",
                                }
                            ),
                            span,
                        )),
                    };
                }
                if base_name == CKB_HEADER_DEP_VIEW_TYPE {
                    return match field {
                        "epoch_number" => Ok(Type::Named(CKB_EPOCH_NUMBER_TYPE.to_string())),
                        "epoch_start_block_number" => Ok(Type::Named(CKB_BLOCK_NUMBER_TYPE.to_string())),
                        "epoch_length" => Ok(Type::Named(CKB_EPOCH_LENGTH_TYPE.to_string())),
                        _ => Err(CompileError::new(
                            format!(
                                "unknown HeaderDepView field '{}'; expected epoch_number, epoch_start_block_number, or epoch_length",
                                field
                            ),
                            span,
                        )),
                    };
                }
                if base_name == CKB_WITNESS_ARGS_VIEW_TYPE {
                    return match field {
                        "size" => Ok(Type::U64),
                        "lock" | "input_type" | "output_type" => Ok(Type::Hash),
                        _ => Err(CompileError::new(
                            format!("unknown WitnessArgsView field '{}'; expected size, lock, input_type, or output_type", field),
                            span,
                        )),
                    };
                }
                if base_name == CKB_OUT_POINT_TYPE {
                    return match field {
                        "index" => Ok(Type::U64),
                        "tx_hash" => Ok(Type::Hash),
                        _ => Err(CompileError::new(format!("unknown OutPoint field '{}'; expected tx_hash or index", field), span)),
                    };
                }
                if base_name == CKB_SCRIPT_VIEW_TYPE {
                    return match field {
                        "hash" => Ok(Type::Named(CKB_SCRIPT_HASH_TYPE.to_string())),
                        "code_hash" | "args_hash" => Ok(Type::Hash),
                        "hash_type" => Ok(Type::U64),
                        "args_empty" => Ok(Type::Bool),
                        _ => Err(CompileError::new(
                            format!(
                                "unknown ScriptView field '{}'; expected hash, code_hash, hash_type, args_empty, or args_hash",
                                field
                            ),
                            span,
                        )),
                    };
                }
                if base_name == CKB_SCRIPT_HASH_TYPE && field == "0" {
                    return Ok(Type::Array(Box::new(Type::U8), 32));
                }
                if base_name == CKB_LOCK_SCRIPT_REF_TYPE || base_name == CKB_TYPE_SCRIPT_REF_TYPE {
                    return match field {
                        "code_hash" | "args_hash" => Ok(Type::Hash),
                        "hash_type" => Ok(Type::U64),
                        "args_empty" => Ok(Type::Bool),
                        _ => Err(CompileError::new(
                            format!("unknown ScriptRef field '{}'; expected code_hash, hash_type, args_empty, or args_hash", field),
                            span,
                        )),
                    };
                }
                if base_name == CKB_SCRIPT_VALUE_TYPE {
                    return match field {
                        "code_hash" => Ok(Type::Hash),
                        "hash_type" => Ok(Type::U64),
                        "args" => Ok(Type::Named(CKB_SCRIPT_ARGS_TYPE.to_string())),
                        _ => Err(CompileError::new(
                            format!("unknown Script field '{}'; expected code_hash, hash_type, or args", field),
                            span,
                        )),
                    };
                }
                if base_name == CKB_SCRIPT_ARGS_TYPE {
                    return match field {
                        "len" => Ok(Type::U64),
                        "is_empty" => Ok(Type::Bool),
                        _ => Err(CompileError::new(format!("unknown ScriptArgs field '{}'; expected len or is_empty", field), span)),
                    };
                }
                if let Some(fields) = self.resolve_named_type_fields(base_name)
                    && let Some(field_ty) = fields.get(field)
                {
                    return Ok(field_ty.clone());
                }
                Err(CompileError::new(format!("unknown field '{}' on type '{}'", field, base_name), span))
            }
            _ => Err(CompileError::new(format!("type '{:?}' does not support field access", ty), span)),
        }
    }

    fn resolve_named_type_fields(&self, type_name: &str) -> Option<HashMap<String, Type>> {
        let base_name = type_name.split('<').next().unwrap_or(type_name);
        if let Some(fields) = self.type_fields.get(base_name) {
            return Some(fields.clone());
        }
        self.resolver
            .zip(self.current_module.as_deref())
            .and_then(|(resolver, module)| resolver.type_fields(module, base_name))
            .map(|fields| fields.into_iter().collect())
    }

    fn resolve_flow_states(&self, type_name: &str) -> Option<Vec<String>> {
        let base_name = type_name.split('<').next().unwrap_or(type_name);
        if let Some(states) = self.flow_states.get(base_name) {
            return Some(states.clone());
        }
        None
    }

    fn is_cell_view_type(ty: &Type) -> bool {
        matches!(ty, Type::U64)
            || matches!(
                ty,
                Type::Named(name)
                    if matches!(
                        name.split('<').next().unwrap_or(name.as_str()),
                        CKB_INPUT_VIEW_TYPE | CKB_OUTPUT_VIEW_TYPE | CKB_CELL_DEP_VIEW_TYPE
                    )
            )
    }

    fn is_witness_args_view_type(ty: &Type) -> bool {
        matches!(ty, Type::U64) || matches!(ty, Type::Named(name) if name == CKB_WITNESS_ARGS_VIEW_TYPE)
    }

    fn is_input_view_type(ty: &Type) -> bool {
        matches!(ty, Type::U64) || matches!(ty, Type::Named(name) if name.starts_with("InputView<"))
    }

    fn is_header_dep_view_type(ty: &Type) -> bool {
        matches!(ty, Type::U64) || matches!(ty, Type::Named(name) if name == CKB_HEADER_DEP_VIEW_TYPE)
    }

    fn typed_view_type_argument(&self, name: &str, call: &CallExpr) -> Result<String> {
        if call.type_args.len() != 1 {
            return Err(CompileError::new(format!("{} requires exactly one cell type argument", name), call.span));
        }
        let ty = &call.type_args[0];
        let Some(type_name) = Self::base_type_name(ty) else {
            return Err(CompileError::new(format!("{} type argument must be a named cell-backed type", name), call.span));
        };
        if self.resolve_cell_type_kind(type_name).is_none() {
            return Err(CompileError::new(
                format!("{} type argument '{}' is not a cell-backed resource, shared type, or receipt", name, type_repr(ty)),
                call.span,
            ));
        }
        Ok(type_repr(ty))
    }

    fn infer_transaction_view_constructor(&self, name: &str, call: &CallExpr, arg_types: &[Type]) -> Result<Option<Type>> {
        let typed_view = match name {
            "ckb::input" | "ckb::group_input" => Some(CKB_INPUT_VIEW_TYPE),
            "ckb::output" | "ckb::group_output" => Some(CKB_OUTPUT_VIEW_TYPE),
            _ => None,
        };
        if let Some(view_type) = typed_view {
            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
            if arg_types[0] != Type::U64 {
                return Err(CompileError::new(format!("{} expects a u64 index", name), call.span));
            }
            let type_name = self.typed_view_type_argument(name, call)?;
            return Ok(Some(Type::Named(format!("{view_type}<{type_name}>"))));
        }

        let result = match name {
            "ckb::cell_dep" => Some(Type::Named(CKB_CELL_DEP_VIEW_TYPE.to_string())),
            "ckb::header_dep" => Some(Type::Named(CKB_HEADER_DEP_VIEW_TYPE.to_string())),
            "witness::args" => Some(Type::Named(CKB_WITNESS_ARGS_VIEW_TYPE.to_string())),
            _ => None,
        };
        if let Some(result) = result {
            if !call.type_args.is_empty() {
                return Err(CompileError::new(format!("{} does not accept type arguments", name), call.span));
            }
            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
            if arg_types[0] != Type::U64 {
                return Err(CompileError::new(format!("{} expects a u64 index", name), call.span));
            }
            return Ok(Some(result));
        }

        let result = match name {
            "ckb::input_out_point" => {
                self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                if !Self::is_input_view_type(&arg_types[0]) {
                    return Err(CompileError::new("ckb::input_out_point expects an InputView<T>", call.span));
                }
                Some(Type::Named(CKB_OUT_POINT_TYPE.to_string()))
            }
            "ckb::lock_script" | "ckb::type_script" => {
                self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                if !Self::is_cell_view_type(&arg_types[0]) {
                    return Err(CompileError::new(format!("{} expects a cell-backed transaction view", name), call.span));
                }
                Some(Type::Named(CKB_SCRIPT_VIEW_TYPE.to_string()))
            }
            _ => None,
        };
        if result.is_some() && !call.type_args.is_empty() {
            return Err(CompileError::new(format!("{} does not accept type arguments", name), call.span));
        }
        Ok(result)
    }

    fn infer_bounded_collection_each(&mut self, env: &mut TypeEnv, call: &CallExpr) -> Result<Option<Type>> {
        let Expr::Identifier(operation) = call.func.as_ref() else {
            return Ok(None);
        };
        let kind = match operation.as_str() {
            "__cellscript_consume_each" => BoundedCollectionKind::CellSet,
            "__cellscript_create_each" => BoundedCollectionKind::List,
            _ => return Ok(None),
        };
        if !matches!(self.current_callable, Some(CallableKind::Action)) {
            return Err(CompileError::new(
                format!("{} is an action-only bounded lifecycle construct", operation.trim_start_matches("__cellscript_")),
                call.span,
            ));
        }
        let [Expr::Identifier(binding), Expr::Identifier(collection_binding), Expr::Block(body)] = call.args.as_slice() else {
            return Err(CompileError::new(
                format!("{} has an invalid internal bounded-collection shape", operation.trim_start_matches("__cellscript_")),
                call.span,
            ));
        };
        let collection_ty = env
            .lookup(collection_binding)
            .cloned()
            .ok_or_else(|| CompileError::new(format!("unknown bounded collection '{}'", collection_binding), call.span))?;
        let collection = parse_bounded_collection_type(&collection_ty).ok_or_else(|| {
            CompileError::new(
                format!(
                    "{} expects {}, found {}",
                    operation.trim_start_matches("__cellscript_"),
                    if kind == BoundedCollectionKind::CellSet { "BoundedCellSet<Resource, N>" } else { "BoundedList<Plan, N>" },
                    type_repr(&collection_ty)
                ),
                call.span,
            )
        })?;
        if collection.kind != kind {
            return Err(CompileError::new(
                format!(
                    "{} expects {}, found {}",
                    operation.trim_start_matches("__cellscript_"),
                    if kind == BoundedCollectionKind::CellSet { "BoundedCellSet" } else { "BoundedList" },
                    if collection.kind == BoundedCollectionKind::CellSet { "BoundedCellSet" } else { "BoundedList" }
                ),
                call.span,
            ));
        }

        let element_ty = self.parse_named_type_repr(&collection.element_type);
        let mut body_env = env.child();
        body_env.bind_new(binding.clone(), element_ty, false, false, call.span)?;
        let mut created_types = Vec::new();
        for stmt in body {
            let Stmt::Expr(expr) = stmt else {
                return Err(CompileError::new(
                    format!(
                        "{} body only accepts require predicates{}",
                        operation.trim_start_matches("__cellscript_"),
                        if kind == BoundedCollectionKind::List { " and one create template" } else { "" }
                    ),
                    call.span,
                ));
            };
            match (kind, expr) {
                (_, Expr::Require(_) | Expr::RequireBlock(_)) => {
                    let previous_callable = self.current_callable.replace(CallableKind::Invariant);
                    let result = self.infer_expr(&mut body_env, expr);
                    self.current_callable = previous_callable;
                    result?;
                }
                (BoundedCollectionKind::List, Expr::Create(create)) => {
                    self.infer_expr(&mut body_env, expr)?;
                    created_types.push(create.ty.clone());
                }
                (_, Expr::Assign(assign)) => {
                    let Expr::Identifier(accumulator) = assign.target.as_ref() else {
                        return Err(CompileError::new(
                            format!(
                                "{} only permits '+=' updates to named outer numeric accumulators",
                                operation.trim_start_matches("__cellscript_")
                            ),
                            assign.span,
                        ));
                    };
                    let Some(accumulator_ty) = env.lookup(accumulator).cloned() else {
                        return Err(CompileError::new(
                            format!(
                                "{} accumulator '{}' must be declared outside the bounded body",
                                operation.trim_start_matches("__cellscript_"),
                                accumulator
                            ),
                            assign.span,
                        ));
                    };
                    if assign.op != AssignOp::AddAssign || !env.is_mutable(accumulator) || !self.is_numeric_type(&accumulator_ty) {
                        return Err(CompileError::new(
                            format!(
                                "{} only permits '+=' updates to mutable outer numeric accumulators",
                                operation.trim_start_matches("__cellscript_")
                            ),
                            assign.span,
                        ));
                    }
                    let previous_callable = self.current_callable.replace(CallableKind::Invariant);
                    let mut purity_env = body_env.clone();
                    let result =
                        self.infer_expr_with_expected_type(&mut purity_env, &assign.value, &accumulator_ty, expr_span(&assign.value));
                    self.current_callable = previous_callable;
                    result?;
                    self.infer_expr(&mut body_env, expr)?;
                }
                _ => {
                    return Err(CompileError::new(
                        format!(
                            "{} body contains unsupported statement; {}",
                            operation.trim_start_matches("__cellscript_"),
                            if kind == BoundedCollectionKind::CellSet {
                                "consume_each owns the per-element consume and permits require predicates plus outer numeric '+=' accumulators"
                            } else {
                                "create_each permits require predicates, outer numeric '+=' accumulators, and exactly one create template"
                            }
                        ),
                        expr.span(),
                    ));
                }
            }
        }
        if kind == BoundedCollectionKind::CellSet {
            env.consume(collection_binding)?;
        } else if created_types.len() != 1 {
            return Err(CompileError::new(
                format!("create_each requires exactly one create template per bounded plan element, found {}", created_types.len()),
                call.span,
            ));
        }
        Ok(Some(Type::Unit))
    }

    fn infer_call_type(&mut self, env: &mut TypeEnv, call: &CallExpr, arg_types: &[Type]) -> Result<Type> {
        match call.func.as_ref() {
            Expr::Identifier(name) => {
                if let Some(view_type) = self.infer_transaction_view_constructor(name, call, arg_types)? {
                    return Ok(view_type);
                }
                if !call.type_args.is_empty() {
                    return Err(CompileError::new(format!("function '{}' does not accept type arguments", name), call.span));
                }
                if let Some(signature) = self.functions.get(name).cloned() {
                    self.validate_call_allowed(name, signature.kind, signature.effect, call.span)?;
                    self.validate_borrow_call(name, signature.kind, signature.effect, &signature.params, call)?;
                    self.validate_call_args(name, &signature.params, arg_types, &call.args, call.span)?;
                    return Ok(signature.return_type.unwrap_or(Type::Unit));
                }
                if let Some(function) = self.resolve_function(name) {
                    let kind = function_def_kind(&function);
                    let effect = function_def_effect(&function);
                    self.validate_call_allowed(name, kind, effect, call.span)?;
                    let params = function_def_param_types(&function);
                    self.validate_borrow_call(name, kind, effect, &params, call)?;
                    self.validate_call_args(name, &params, arg_types, &call.args, call.span)?;
                    return Ok(self.function_return_type(&function).unwrap_or(Type::Unit));
                }
                if let Some((prefix, suffix)) = name.rsplit_once("::") {
                    if self.current_module.as_deref() == Some(prefix)
                        && let Some(signature) = self.functions.get(suffix).cloned()
                    {
                        self.validate_call_allowed(name, signature.kind, signature.effect, call.span)?;
                        self.validate_borrow_call(name, signature.kind, signature.effect, &signature.params, call)?;
                        self.validate_call_args(name, &signature.params, arg_types, &call.args, call.span)?;
                        return Ok(signature.return_type.unwrap_or(Type::Unit));
                    }
                    self.reject_borrow_view_in_builtin_call(name, call)?;
                    return Ok(match (prefix, suffix) {
                        ("env", "current_timepoint") => {
                            self.validate_builtin_arity(name, 0, arg_types, call.span)?;
                            Type::U64
                        }
                        ("env", "block_number") if self.current_validity => {
                            self.validate_builtin_arity(name, 0, arg_types, call.span)?;
                            Type::U64
                        }
                        ("script", "hash_type_data" | "hash_type_type" | "hash_type_data1" | "hash_type_data2") => {
                            self.validate_builtin_arity(name, 0, arg_types, call.span)?;
                            Type::U64
                        }
                        ("Hash", "from_bytes") => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            if !Self::is_hash_bytes_type(&arg_types[0]) {
                                return Err(CompileError::new("Hash::from_bytes expects exactly 32 bytes ([u8; 32])", call.span));
                            }
                            Type::Hash
                        }
                        ("script", "args_empty") => {
                            self.validate_builtin_arity(name, 0, arg_types, call.span)?;
                            Type::Named(CKB_SCRIPT_ARGS_TYPE.to_string())
                        }
                        ("script", "args") => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            if !Self::is_script_args_payload_type(&arg_types[0]) {
                                return Err(CompileError::new("script::args expects fixed bytes ([u8; N]) or Hash input", call.span));
                            }
                            Type::Named(CKB_SCRIPT_ARGS_TYPE.to_string())
                        }
                        ("script", "new") => {
                            self.validate_builtin_arity(name, 3, arg_types, call.span)?;
                            if arg_types[0] != Type::Hash || arg_types[1] != Type::U64 || !Self::is_script_args_type(&arg_types[2]) {
                                return Err(CompileError::new(
                                    "script::new expects (code_hash: Hash, hash_type: u64, args: ScriptArgs)",
                                    call.span,
                                ));
                            }
                            if let Expr::Integer(value) = &call.args[1] {
                                Self::validate_script_hash_type_literal(*value, call.span)?;
                            }
                            Type::Named(CKB_SCRIPT_VALUE_TYPE.to_string())
                        }
                        ("script", "require_cell_lock_matches" | "require_cell_type_matches") => {
                            self.validate_builtin_arity(name, 2, arg_types, call.span)?;
                            if !Self::is_cell_view_type(&arg_types[0]) || !Self::is_script_value_type(&arg_types[1]) {
                                return Err(CompileError::new(
                                    format!("{} expects (source_view: u64, expected_script: Script)", name),
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("env", "sighash_all") => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            if !Self::is_cell_view_type(&arg_types[0]) {
                                return Err(CompileError::new(
                                    "env::sighash_all expects a source view returned by source::*",
                                    call.span,
                                ));
                            }
                            Type::Hash
                        }
                        (
                            "ckb",
                            "header_epoch_number"
                            | "header_epoch_start_block_number"
                            | "header_epoch_length"
                            | "input_since"
                            | "current_role",
                        ) => {
                            self.validate_builtin_arity(name, 0, arg_types, call.span)?;
                            Type::U64
                        }
                        ("ckb", "exec_cell_dep_u8_args") => {
                            self.validate_builtin_arity(name, 6, arg_types, call.span)?;
                            if arg_types.iter().any(|ty| *ty != Type::U64) {
                                return Err(CompileError::new(
                                    "ckb::exec_cell_dep_u8_args expects six u64 values: CellDep index, argc, and four byte arguments",
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("ckb", "trusted_exec_cell_dep_u8_args") => {
                            self.validate_builtin_arity(name, 7, arg_types, call.span)?;
                            if arg_types[0] != Type::U64
                                || arg_types[1] != Type::Hash
                                || arg_types[2..].iter().any(|ty| *ty != Type::U64)
                            {
                                return Err(CompileError::new(
                                    "ckb::trusted_exec_cell_dep_u8_args expects (dep: u64, code_hash: Hash, argc: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64)",
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("ckb", "exec_cell_dep_hex4" | "spawn_wait_cell_dep_hex4") => {
                            self.validate_builtin_arity(name, 6, arg_types, call.span)?;
                            if arg_types[0] != Type::U64
                                || arg_types[1] != Type::Named("Vec<u8>".to_string())
                                || arg_types[2..].iter().any(|ty| *ty != Type::U64)
                            {
                                return Err(CompileError::new(
                                    format!("{name} expects (dep: u64, bytes: Vec<u8>, len0: u64, len1: u64, len2: u64, len3: u64)"),
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("ckb", "trusted_exec_cell_dep_hex4" | "trusted_spawn_wait_cell_dep_hex4") => {
                            self.validate_builtin_arity(name, 7, arg_types, call.span)?;
                            if arg_types[0] != Type::U64
                                || arg_types[1] != Type::Hash
                                || arg_types[2] != Type::Named("Vec<u8>".to_string())
                                || arg_types[3..].iter().any(|ty| *ty != Type::U64)
                            {
                                return Err(CompileError::new(
                                    format!("{name} expects (dep: u64, code_hash: Hash, bytes: Vec<u8>, len0: u64, len1: u64, len2: u64, len3: u64)"),
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("ckb", "current_script_hash" | "raw_transaction_hash_without_cell_deps") => {
                            self.validate_builtin_arity(name, 0, arg_types, call.span)?;
                            Type::Hash
                        }
                        ("ckb", "script_hash") => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            if arg_types[0] != Type::Hash {
                                return Err(CompileError::new(
                                    "ckb::script_hash expects a Hash and explicitly treats it as a complete CKB Script hash",
                                    call.span,
                                ));
                            }
                            Type::Named(CKB_SCRIPT_HASH_TYPE.to_string())
                        }
                        ("ckb", "transaction_u32_le") => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            if arg_types[0] != Type::U64 {
                                return Err(CompileError::new("transaction_u32_le expects a u64 offset", call.span));
                            }
                            Type::U64
                        }
                        ("ckb", "transaction_blake2b_gather") => {
                            self.validate_builtin_arity(name, 4, arg_types, call.span)?;
                            for (ty, expected) in arg_types.iter().zip(["Vec<u64>", "Vec<u64>", "Vec<u8>", "Vec<u8>"]) {
                                if *ty != Type::Named(expected.to_string()) {
                                    return Err(CompileError::new("transaction_blake2b_gather expects (offsets: Vec<u64>, lengths: Vec<u64>, prefix: Vec<u8>, suffix: Vec<u8>)", call.span));
                                }
                            }
                            Type::Hash
                        }
                        ("witness", "blake2b_select_chunks") => {
                            self.validate_builtin_arity(name, 6, arg_types, call.span)?;
                            if !Self::is_witness_args_view_type(&arg_types[0])
                                || arg_types[1..3].iter().any(|ty| *ty != Type::U64)
                                || arg_types[3..].iter().any(|ty| *ty != Type::Named("Vec<u8>".into()))
                            {
                                return Err(CompileError::new("witness::blake2b_select_chunks expects (view, start: u64, stride: u64, selection: Vec<u8>, prefix: Vec<u8>, suffix: Vec<u8>)", call.span));
                            }
                            Type::Hash
                        }
                        ("ckb", "since_epoch_absolute" | "since_epoch_relative") => {
                            self.validate_builtin_arity(name, 3, arg_types, call.span)?;
                            if arg_types.iter().any(|ty| *ty != Type::U64) {
                                return Err(CompileError::new(
                                    format!("{} expects (number: u64, index: u64, length: u64)", name),
                                    call.span,
                                ));
                            }
                            Type::U64
                        }
                        ("ckb", "since_absolute_epoch" | "since_relative_epoch") => {
                            self.validate_builtin_arity(name, 3, arg_types, call.span)?;
                            if arg_types.iter().any(|ty| *ty != Type::U64) {
                                return Err(CompileError::new(
                                    format!("{} expects (number: u64, index: u64, length: u64)", name),
                                    call.span,
                                ));
                            }
                            Type::Named(
                                if suffix == "since_absolute_epoch" {
                                    CKB_ABSOLUTE_EPOCH_SINCE_TYPE
                                } else {
                                    CKB_RELATIVE_EPOCH_SINCE_TYPE
                                }
                                .to_string(),
                            )
                        }
                        ("ckb", "since_to_raw") => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            if !Self::is_ckb_since_type(&arg_types[0]) {
                                return Err(CompileError::new(
                                    "ckb::since_to_raw expects EncodedSince or a typed Since<Mode, Metric> value",
                                    call.span,
                                ));
                            }
                            Type::U64
                        }
                        ("ckb", "epoch_number_to_u64" | "block_number_to_u64" | "epoch_length_to_u64") => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            let expected = match suffix {
                                "epoch_number_to_u64" => CKB_EPOCH_NUMBER_TYPE,
                                "block_number_to_u64" => CKB_BLOCK_NUMBER_TYPE,
                                _ => CKB_EPOCH_LENGTH_TYPE,
                            };
                            if arg_types[0] != Type::Named(expected.to_string()) {
                                return Err(CompileError::new(format!("{} expects a {} value", name, expected), call.span));
                            }
                            Type::U64
                        }
                        (
                            "ckb",
                            "cell_capacity"
                            | "cell_occupied_capacity"
                            | "cell_unoccupied_capacity"
                            | "cell_output_index"
                            | "input_out_point_index"
                            | "input_out_point_tx_hash_low"
                            | "input_since_at"
                            | "cell_lock_hash_low"
                            | "cell_type_hash_low"
                            | "cell_lock_hash_type"
                            | "cell_type_hash_type"
                            | "cell_count"
                            | "cell_lock_size"
                            | "cell_type_size"
                            | "cell_data_size",
                        ) => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            let source_ok =
                                if matches!(suffix, "input_out_point_index" | "input_out_point_tx_hash_low" | "input_since_at") {
                                    Self::is_input_view_type(&arg_types[0])
                                } else {
                                    Self::is_cell_view_type(&arg_types[0])
                                };
                            if !source_ok {
                                return Err(CompileError::new(
                                    format!("{} expects a source view returned by source::*", name),
                                    call.span,
                                ));
                            }
                            Type::U64
                        }
                        ("ckb", "input_out_point_tx_hash") => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            if !Self::is_input_view_type(&arg_types[0]) {
                                return Err(CompileError::new(
                                    format!("{} expects a source view returned by source::*", name),
                                    call.span,
                                ));
                            }
                            Type::Hash
                        }
                        ("ckb", "hash_data_packed") => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            if matches!(arg_types[0], Type::Unit) {
                                return Err(CompileError::new("ckb::hash_data_packed expects packed data", call.span));
                            }
                            Type::Hash
                        }
                        ("ckb", "hash_sha256" | "hash_sha256d") => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            if arg_types[0] != Type::Hash {
                                return Err(CompileError::new(format!("{} expects Hash input", name), call.span));
                            }
                            Type::Hash
                        }
                        ("ckb", "hash_sha256_pair" | "hash_sha256d_pair") => {
                            self.validate_builtin_arity(name, 2, arg_types, call.span)?;
                            if arg_types.iter().any(|ty| *ty != Type::Hash) {
                                return Err(CompileError::new(format!("{} expects (Hash, Hash)", name), call.span));
                            }
                            Type::Hash
                        }
                        ("ckb", "require_sha256d_merkle_root") => {
                            self.validate_builtin_arity(name, 5, arg_types, call.span)?;
                            let siblings_ty = Type::Array(Box::new(Type::Hash), 16);
                            if arg_types[0] != Type::Hash
                                || arg_types[1] != siblings_ty
                                || arg_types[2] != Type::U64
                                || arg_types[3] != Type::U64
                                || arg_types[4] != Type::Hash
                            {
                                return Err(CompileError::new(
                                    "ckb::require_sha256d_merkle_root expects (leaf: Hash, siblings: [Hash; 16], depth: u64, leaf_index: u64, expected_root: Hash)",
                                    call.span,
                                ));
                            }
                            match &call.args[2] {
                                Expr::Integer(0..=16) => {}
                                Expr::Integer(_) => {
                                    return Err(CompileError::new(
                                        "ckb::require_sha256d_merkle_root depth must be in 0..=16",
                                        call.span,
                                    ));
                                }
                                _ => {
                                    return Err(CompileError::new(
                                        "ckb::require_sha256d_merkle_root depth must be an integer literal",
                                        call.span,
                                    ));
                                }
                            }
                            Type::Unit
                        }
                        ("ckb", "cell_data_blake2b_span") | ("witness", "blake2b_span") => {
                            self.validate_builtin_arity(name, 3, arg_types, call.span)?;
                            let valid_view = if prefix == "ckb" {
                                Self::is_cell_view_type(&arg_types[0])
                            } else {
                                Self::is_witness_args_view_type(&arg_types[0])
                            };
                            if !valid_view || arg_types[1] != Type::U64 || arg_types[2] != Type::U64 {
                                return Err(CompileError::new(
                                    format!("{} expects (source_view, offset: u64, length: u64)", name),
                                    call.span,
                                ));
                            }
                            Type::Hash
                        }
                        ("ckb", "cell_data_hash_at") => {
                            self.validate_builtin_arity(name, 2, arg_types, call.span)?;
                            if !Self::is_cell_view_type(&arg_types[0]) || arg_types[1] != Type::U64 {
                                return Err(CompileError::new(
                                    "ckb::cell_data_hash_at expects (source_view: u64, offset: u64)",
                                    call.span,
                                ));
                            }
                            Type::Hash
                        }
                        ("ckb", "cell_data_u8" | "cell_data_u32_le" | "cell_data_u64_le" | "cell_lock_u8" | "cell_type_u8") => {
                            self.validate_builtin_arity(name, 2, arg_types, call.span)?;
                            if !Self::is_cell_view_type(&arg_types[0]) || arg_types[1] != Type::U64 {
                                return Err(CompileError::new(format!("{} expects (source_view: u64, offset: u64)", name), call.span));
                            }
                            Type::U64
                        }
                        (
                            "ckb",
                            "cell_lock_hash"
                            | "cell_type_hash"
                            | "cell_data_hash_field"
                            | "cell_data_hash"
                            | "cell_lock_code_hash"
                            | "cell_type_code_hash"
                            | "cell_lock_args32"
                            | "cell_type_args32"
                            | "cell_lock_args_hash"
                            | "cell_type_args_hash",
                        ) => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            if !Self::is_cell_view_type(&arg_types[0]) {
                                return Err(CompileError::new(
                                    format!("{} expects a source view returned by source::*", name),
                                    call.span,
                                ));
                            }
                            Type::Hash
                        }
                        ("ckb", "cell_lock_args_empty" | "cell_type_args_empty" | "cell_has_type") => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            if !Self::is_cell_view_type(&arg_types[0]) {
                                return Err(CompileError::new(
                                    format!("{} expects a source view returned by source::*", name),
                                    call.span,
                                ));
                            }
                            Type::Bool
                        }
                        ("ckb", "require_cell_lock_hash" | "require_cell_type_hash" | "require_cell_data_hash") => {
                            self.validate_builtin_arity(name, 2, arg_types, call.span)?;
                            if !Self::is_cell_view_type(&arg_types[0]) || arg_types[1] != Type::Hash {
                                return Err(CompileError::new(
                                    format!("{} expects (source_view: u64, expected_hash: Hash)", name),
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("ckb", "require_bounded_cell_dep_data_hash") => {
                            self.validate_builtin_arity(name, 2, arg_types, call.span)?;
                            if arg_types[0] != Type::U64 || arg_types[1] != Type::Hash {
                                return Err(CompileError::new(
                                    "ckb::require_bounded_cell_dep_data_hash expects (max_deps: u64, expected_data_hash: Hash)",
                                    call.span,
                                ));
                            }
                            match &call.args[0] {
                                Expr::Integer(1..=64) => {}
                                Expr::Integer(_) => {
                                    return Err(CompileError::new(
                                        "ckb::require_bounded_cell_dep_data_hash max_deps must be in 1..=64",
                                        call.span,
                                    ));
                                }
                                _ => {
                                    return Err(CompileError::new(
                                        "ckb::require_bounded_cell_dep_data_hash max_deps must be an integer literal",
                                        call.span,
                                    ));
                                }
                            }
                            Type::Unit
                        }
                        ("ckb", "require_current_script_args_empty") => {
                            self.validate_builtin_arity(name, 0, arg_types, call.span)?;
                            Type::Unit
                        }
                        ("ckb", "require_cell_lock_args_empty" | "require_cell_type_args_empty") => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            if !Self::is_cell_view_type(&arg_types[0]) {
                                return Err(CompileError::new(
                                    format!("{} expects a source view returned by source::*", name),
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        (
                            "ckb",
                            "require_cell_lock_args_hash"
                            | "require_cell_type_args_hash"
                            | "require_cell_lock_args_prefix_hash"
                            | "require_cell_type_args_prefix_hash"
                            | "require_cell_lock_args_suffix_hash"
                            | "require_cell_type_args_suffix_hash",
                        ) => {
                            self.validate_builtin_arity(name, 2, arg_types, call.span)?;
                            if !Self::is_cell_view_type(&arg_types[0]) || arg_types[1] != Type::Hash {
                                return Err(CompileError::new(
                                    format!("{} expects (source_view: u64, expected_args_hash: Hash)", name),
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("ckb", "require_cell_lock_script_hash_type" | "require_cell_type_script_hash_type") => {
                            self.validate_builtin_arity(name, 3, arg_types, call.span)?;
                            if !Self::is_cell_view_type(&arg_types[0]) || arg_types[1] != Type::Hash || arg_types[2] != Type::U64 {
                                return Err(CompileError::new(
                                    format!("{} expects (source_view: u64, expected_code_hash: Hash, expected_hash_type: u64)", name),
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("ckb", "require_input_out_point_tx_hash" | "require_input_out_point") => {
                            let expects_index = suffix == "require_input_out_point";
                            let expected_arity = if expects_index { 3 } else { 2 };
                            self.validate_builtin_arity(name, expected_arity, arg_types, call.span)?;
                            let expected_index_ok = !expects_index || arg_types[2] == Type::U64;
                            if !Self::is_input_view_type(&arg_types[0]) || arg_types[1] != Type::Hash || !expected_index_ok {
                                return Err(CompileError::new(
                                    format!(
                                        "{} expects {}",
                                        name,
                                        if expects_index {
                                            "(source_view: u64, expected_hash: Hash, expected_index: u64)"
                                        } else {
                                            "(source_view: u64, expected_hash: Hash)"
                                        }
                                    ),
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("verifier::btc::bip340", "require_signature" | "require_signature_from_cell_dep") => {
                            let explicit_dep = suffix == "require_signature_from_cell_dep";
                            self.validate_builtin_arity(name, if explicit_dep { 4 } else { 3 }, arg_types, call.span)?;
                            let value_offset = usize::from(explicit_dep);
                            let pubkey_ty = Type::Array(Box::new(Type::U8), 32);
                            let signature_ty = Type::Array(Box::new(Type::U8), 64);
                            if (explicit_dep && arg_types[0] != Type::U64)
                                || arg_types[value_offset] != Type::Hash
                                || arg_types[value_offset + 1] != pubkey_ty
                                || arg_types[value_offset + 2] != signature_ty
                            {
                                return Err(CompileError::new(
                                    if explicit_dep {
                                        "verifier::btc::bip340::require_signature_from_cell_dep expects (dep_index: u64, message_hash: Hash, pubkey: [u8; 32], signature: [u8; 64])"
                                    } else {
                                        "verifier::btc::bip340::require_signature expects (message_hash: Hash, pubkey: [u8; 32], signature: [u8; 64])"
                                    },
                                    call.span,
                                ));
                            }
                            if explicit_dep {
                                match &call.args[0] {
                                    Expr::Integer(0..=63) => {}
                                    Expr::Integer(_) => {
                                        return Err(CompileError::new(
                                            "verifier::btc::bip340::require_signature_from_cell_dep dep_index must be in 0..=63",
                                            call.span,
                                        ));
                                    }
                                    _ => {
                                        return Err(CompileError::new(
                                            "verifier::btc::bip340::require_signature_from_cell_dep dep_index must be an integer literal",
                                            call.span,
                                        ));
                                    }
                                }
                            }
                            Type::Unit
                        }
                        ("ckb", "require_metapoint_relative") => {
                            self.validate_builtin_arity(name, 3, arg_types, call.span)?;
                            if !Self::is_cell_view_type(&arg_types[0])
                                || !Self::is_cell_view_type(&arg_types[1])
                                || arg_types[2] != Type::I32
                            {
                                return Err(CompileError::new(
                                    "ckb::require_metapoint_relative expects (base_view: u64, related_view: u64, relative_distance: i32)",
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("ckb", "require_lock_type_metapoint_pairs" | "require_type_lock_metapoint_pairs") => {
                            self.validate_builtin_arity(name, 2, arg_types, call.span)?;
                            if !Self::is_cell_view_type(&arg_types[0]) || arg_types[1] != Type::I32 {
                                return Err(CompileError::new(
                                    format!("{} expects (source_view: u64, relative_distance: i32)", name),
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        (
                            "ckb",
                            "require_lock_type_metapoint_pairs_from_i32_data" | "require_type_lock_metapoint_pairs_from_i32_data",
                        ) => {
                            self.validate_builtin_arity(name, 2, arg_types, call.span)?;
                            if !Self::is_cell_view_type(&arg_types[0]) || arg_types[1] != Type::U64 {
                                return Err(CompileError::new(
                                    format!("{} expects (source_view: u64, distance_offset: u64)", name),
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        (
                            "ckb",
                            "require_lock_type_metapoint_pairs_from_i32_data_filtered"
                            | "require_type_lock_metapoint_pairs_from_i32_data_filtered",
                        ) => {
                            self.validate_builtin_arity(name, 4, arg_types, call.span)?;
                            if !Self::is_cell_view_type(&arg_types[0])
                                || arg_types[1] != Type::U64
                                || arg_types[2] != Type::Hash
                                || arg_types[3] != Type::U64
                            {
                                return Err(CompileError::new(
                                    format!(
                                        "{} expects (source_view: u64, distance_offset: u64, expected_related_type_hash: Hash, related_data_rule: u64)",
                                        name
                                    ),
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("ckb", "require_lock_match_master_out_point_pairs_from_data") => {
                            self.validate_builtin_arity(name, 5, arg_types, call.span)?;
                            if !Self::is_cell_view_type(&arg_types[0])
                                || !Self::is_cell_view_type(&arg_types[1])
                                || arg_types[2..].iter().any(|ty| *ty != Type::U64)
                            {
                                return Err(CompileError::new(
                                    "ckb::require_lock_match_master_out_point_pairs_from_data expects (input_source_view: u64, output_source_view: u64, action_offset: u64, tx_hash_offset: u64, index_offset: u64)",
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("source", "input" | "output" | "cell_dep" | "header_dep" | "group_input" | "group_output") => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            if arg_types[0] != Type::U64 {
                                return Err(CompileError::new(format!("{} expects a u64 index", name), call.span));
                            }
                            Type::U64
                        }
                        ("dao", "accumulated_rate") => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            if !Self::is_header_dep_view_type(&arg_types[0]) {
                                return Err(CompileError::new(
                                    "dao::accumulated_rate expects a HeaderDep source view returned by source::header_dep",
                                    call.span,
                                ));
                            }
                            Type::U64
                        }
                        ("dao", "input_accumulated_rate") => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            if !Self::is_input_view_type(&arg_types[0]) {
                                return Err(CompileError::new(
                                    "dao::input_accumulated_rate expects an Input or GroupInput source view returned by source::input/source::group_input",
                                    call.span,
                                ));
                            }
                            Type::U64
                        }
                        ("dao", "is_deposit_data" | "is_withdrawal_request_data" | "has_dao_type") => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            if !Self::is_cell_view_type(&arg_types[0]) {
                                return Err(CompileError::new(
                                    format!("{} expects a source view returned by source::*", name),
                                    call.span,
                                ));
                            }
                            Type::Bool
                        }
                        ("dao", "require_header_dep_for_input") => {
                            self.validate_builtin_arity(name, 2, arg_types, call.span)?;
                            if !Self::is_input_view_type(&arg_types[0]) || !Self::is_header_dep_view_type(&arg_types[1]) {
                                return Err(CompileError::new(
                                    "dao::require_header_dep_for_input expects (input_view: u64, header_view: u64)",
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("dao", "require_input_since_at_least") => {
                            self.validate_builtin_arity(name, 2, arg_types, call.span)?;
                            if !Self::is_input_view_type(&arg_types[0])
                                || (arg_types[1] != Type::U64 && !Self::is_ckb_since_type(&arg_types[1]))
                            {
                                return Err(CompileError::new(
                                    "dao::require_input_since_at_least expects (input_view, required_since: u64 or typed Since)",
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("dao", "require_input_relative_epoch_since_at_least") => {
                            self.validate_builtin_arity(name, 4, arg_types, call.span)?;
                            if !Self::is_input_view_type(&arg_types[0]) || arg_types[1..].iter().any(|ty| *ty != Type::U64) {
                                return Err(CompileError::new(
                                    "dao::require_input_relative_epoch_since_at_least expects (input_view: u64, number: u64, index: u64, length: u64)",
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("xudt", "owner_mode_input_type_hash" | "amount_low" | "amount_high") => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            if !Self::is_cell_view_type(&arg_types[0]) {
                                return Err(CompileError::new(
                                    format!("{} expects a source view returned by source::*", name),
                                    call.span,
                                ));
                            }
                            Type::U64
                        }
                        ("xudt", "require_owner_mode_input_type") => {
                            self.validate_builtin_arity(name, 2, arg_types, call.span)?;
                            if !Self::is_cell_view_type(&arg_types[0]) || arg_types[1] != Type::Hash {
                                return Err(CompileError::new(
                                    "xudt::require_owner_mode_input_type expects (source_view: u64, expected_hash: Hash)",
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("xudt", "require_owner_mode_type_args") => {
                            self.validate_builtin_arity(name, 3, arg_types, call.span)?;
                            if !Self::is_cell_view_type(&arg_types[0]) || arg_types[1] != Type::Hash || arg_types[2] != Type::U64 {
                                return Err(CompileError::new(
                                    "xudt::require_owner_mode_type_args expects (source_view: u64, owner_hash: Hash, flags: u64)",
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("xudt", "require_owner_mode_type_args_current_script") => {
                            self.validate_builtin_arity(name, 2, arg_types, call.span)?;
                            if !Self::is_cell_view_type(&arg_types[0]) || arg_types[1] != Type::U64 {
                                return Err(CompileError::new(
                                    "xudt::require_owner_mode_type_args_current_script expects (source_view: u64, flags: u64)",
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("xudt", "require_group_amount_conserved") => {
                            self.validate_builtin_arity(name, 0, arg_types, call.span)?;
                            Type::Unit
                        }
                        ("xudt", "require_group_amount_minted" | "require_group_amount_burned") => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            if arg_types[0] != Type::U128 {
                                return Err(CompileError::new(format!("{} expects a u128 delta amount", name), call.span));
                            }
                            Type::Unit
                        }
                        ("c256", "require_product_lte" | "require_product_eq") => {
                            self.validate_builtin_arity(name, 4, arg_types, call.span)?;
                            if arg_types.iter().any(|ty| *ty != Type::U128) {
                                return Err(CompileError::new(
                                    format!("{} expects four u128 operands: (left_amount, left_multiplier, right_amount, right_multiplier)", name),
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("c256", "require_sum2_products_lte" | "require_sum2_products_eq") => {
                            self.validate_builtin_arity(name, 8, arg_types, call.span)?;
                            if arg_types.iter().any(|ty| *ty != Type::U128) {
                                return Err(CompileError::new(
                                    format!(
                                        "{} expects eight u128 operands: left pair 1, left pair 2, right pair 1, right pair 2",
                                        name
                                    ),
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("witness", "count") => {
                            self.validate_builtin_arity(name, 0, arg_types, call.span)?;
                            Type::U64
                        }
                        ("witness", "byte" | "u32_le" | "u64_le" | "bytes32") => {
                            self.validate_builtin_arity(name, 2, arg_types, call.span)?;
                            if !Self::is_witness_args_view_type(&arg_types[0]) || arg_types[1] != Type::U64 {
                                return Err(CompileError::new(format!("{} expects (witness_view, offset: u64)", name), call.span));
                            }
                            if suffix == "bytes32" {
                                Type::Hash
                            } else {
                                Type::U64
                            }
                        }
                        ("witness", "raw" | "lock" | "input_type" | "output_type" | "size") => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            if !Self::is_witness_args_view_type(&arg_types[0]) {
                                return Err(CompileError::new(
                                    format!("{} expects a source view returned by source::*", name),
                                    call.span,
                                ));
                            }
                            if suffix == "size" {
                                Type::U64
                            } else {
                                Type::Hash
                            }
                        }
                        ("ckb", "require_witness_size_at_least") => {
                            self.validate_builtin_arity(name, 2, arg_types, call.span)?;
                            if !Self::is_witness_args_view_type(&arg_types[0]) || arg_types[1] != Type::U64 {
                                return Err(CompileError::new(
                                    format!("{} expects (source_view: u64, min_size: u64)", name),
                                    call.span,
                                ));
                            }
                            Type::Unit
                        }
                        ("Address", "zero") => {
                            self.validate_builtin_arity(name, 0, arg_types, call.span)?;
                            Type::Address
                        }
                        ("Hash", "zero") => {
                            self.validate_builtin_arity(name, 0, arg_types, call.span)?;
                            Type::Hash
                        }
                        ("Vec", "with_capacity") => {
                            self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                            if arg_types[0] != Type::U64 {
                                return Err(CompileError::new("Vec::with_capacity expects a u64 capacity", call.span));
                            }
                            Type::Named("Vec".to_string())
                        }
                        (_, "new") => {
                            self.validate_builtin_arity(name, 0, arg_types, call.span)?;
                            self.validate_namespaced_type_constructor(prefix, suffix, call.span)?;
                            Type::Named(prefix.to_string())
                        }
                        (_, "zero") => {
                            self.validate_builtin_arity(name, 0, arg_types, call.span)?;
                            self.validate_namespaced_type_constructor(prefix, suffix, call.span)?;
                            Type::Named(prefix.to_string())
                        }
                        _ => return Err(CompileError::new(format!("unknown namespaced function '{}'", name), call.span)),
                    });
                }
                self.reject_borrow_view_in_builtin_call(name, call)?;
                if name == "min" || name == "max" || name == "isqrt" {
                    self.validate_numeric_builtin_call(name, arg_types, call.span)?;
                    return Ok(Type::U64);
                }
                match name.as_str() {
                    "spawn" => {
                        self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                        if !matches!(arg_types[0], Type::Named(ref ty) if ty == "String") {
                            return Err(CompileError::new("spawn expects a static script name String", call.span));
                        }
                        self.validate_static_spawn_target_expr(&call.args[0], call.span)?;
                        return Ok(Type::U64);
                    }
                    "wait" | "process_id" | "pipe_read" | "inherited_fd" | "close" => {
                        let expected = if matches!(name.as_str(), "wait" | "process_id") { 0 } else { 1 };
                        self.validate_builtin_arity(name, expected, arg_types, call.span)?;
                        if expected == 1 && arg_types[0] != Type::U64 {
                            return Err(CompileError::new(format!("{} expects a u64 file descriptor or index", name), call.span));
                        }
                        return Ok(Type::U64);
                    }
                    "pipe" => {
                        self.validate_builtin_arity(name, 0, arg_types, call.span)?;
                        return Ok(Type::Tuple(vec![Type::U64, Type::U64]));
                    }
                    "pipe_write" => {
                        self.validate_builtin_arity(name, 2, arg_types, call.span)?;
                        if arg_types[0] != Type::U64 || arg_types[1] != Type::U64 {
                            return Err(CompileError::new("pipe_write expects (fd: u64, value: u64)", call.span));
                        }
                        return Ok(Type::U64);
                    }
                    "require_maturity" | "require_time" => {
                        self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                        if arg_types[0] != Type::U64 {
                            return Err(CompileError::new(format!("{} expects a u64 CKB since/time value", name), call.span));
                        }
                        return Ok(Type::Unit);
                    }
                    "require_epoch_after" | "require_epoch_relative" => {
                        self.validate_builtin_arity(name, 3, arg_types, call.span)?;
                        if arg_types.iter().any(|ty| *ty != Type::U64) {
                            return Err(CompileError::new(
                                format!("{} expects (number: u64, index: u64, length: u64)", name),
                                call.span,
                            ));
                        }
                        return Ok(Type::Unit);
                    }
                    "occupied_capacity" => {
                        self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                        if !matches!(arg_types[0], Type::Named(ref ty) if ty == "String") {
                            return Err(CompileError::new("occupied_capacity expects a type name string literal", call.span));
                        }
                        return Ok(Type::U64);
                    }
                    "hash_chain" => {
                        self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                        if arg_types[0] != Type::Hash {
                            return Err(CompileError::new("hash_chain expects Hash input", call.span));
                        }
                        return Ok(Type::Hash);
                    }
                    "hash_pair" => {
                        self.validate_builtin_arity(name, 2, arg_types, call.span)?;
                        if arg_types[0] != Type::Hash || arg_types[1] != Type::Hash {
                            return Err(CompileError::new("hash_pair expects (Hash, Hash)", call.span));
                        }
                        return Ok(Type::Hash);
                    }
                    "hash_blake2b" => {
                        self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                        if arg_types[0] != Type::Hash {
                            return Err(CompileError::new("hash_blake2b expects Hash input", call.span));
                        }
                        return Ok(Type::Hash);
                    }
                    "hash_blake2b_packed" => {
                        self.validate_builtin_arity(name, 1, arg_types, call.span)?;
                        if matches!(arg_types[0], Type::Unit) {
                            return Err(CompileError::new("hash_blake2b_packed expects packed data", call.span));
                        }
                        return Ok(Type::Hash);
                    }
                    _ => {}
                }
                Err(CompileError::new(format!("unknown function '{}'", name), call.span))
            }
            Expr::FieldAccess(field) => {
                let receiver_ty = self.infer_expr(env, &field.expr)?;
                match field.field.as_str() {
                    "type_hash" => {
                        self.validate_builtin_arity(&field.field, 0, arg_types, call.span)?;
                        Ok(Type::Hash)
                    }
                    "len" => {
                        self.validate_builtin_arity(&field.field, 0, arg_types, call.span)?;
                        if self.supports_collection_len(&receiver_ty) {
                            Ok(Type::U64)
                        } else {
                            Err(CompileError::new("len is only supported on array or Vec values", call.span))
                        }
                    }
                    "is_empty" => {
                        self.validate_builtin_arity(&field.field, 0, arg_types, call.span)?;
                        if self.supports_collection_len(&receiver_ty) {
                            Ok(Type::Bool)
                        } else {
                            Err(CompileError::new("is_empty is only supported on array or Vec values", call.span))
                        }
                    }
                    "capacity" => {
                        self.validate_builtin_arity("Vec.capacity", 0, arg_types, call.span)?;
                        match &receiver_ty {
                            Type::Named(name) if self.parse_named_collection_item_type(name).is_some() => Ok(Type::U64),
                            Type::Named(name) if name == "Vec" => Err(CompileError::new(
                                "Vec.capacity requires a typed Vec<T>; push or annotate the Vec before reading capacity",
                                call.span,
                            )),
                            _ => Err(CompileError::new("capacity is only supported on Vec values", call.span)),
                        }
                    }
                    "first" | "last" => {
                        self.validate_builtin_arity(&format!("Vec.{}", field.field), 0, arg_types, call.span)?;
                        match &receiver_ty {
                            Type::Named(name) => {
                                let Some(item_ty) = self.parse_named_collection_item_type(name) else {
                                    return Err(CompileError::new(
                                        format!(
                                            "Vec.{} requires a typed Vec<T>; push or annotate the Vec before reading",
                                            field.field
                                        ),
                                        call.span,
                                    ));
                                };
                                Ok(item_ty)
                            }
                            _ => Err(CompileError::new(format!("{} is only supported on Vec values", field.field), call.span)),
                        }
                    }
                    "push" => {
                        self.validate_builtin_arity("Vec.push", 1, arg_types, call.span)?;
                        let arg_ty = &arg_types[0];
                        if self.type_contains_reference(arg_ty) {
                            return Err(CompileError::new(
                                format!(
                                    "Vec.push cannot store reference type {}; Vec<T> values must use owned non-reference items",
                                    type_repr(arg_ty)
                                ),
                                call.span,
                            ));
                        }
                        if let Type::Named(name) = &receiver_ty {
                            if name == "Vec" {
                                if let Expr::Identifier(receiver_name) = field.expr.as_ref() {
                                    env.update_type(receiver_name, Type::Named(format!("Vec<{}>", type_repr(arg_ty))));
                                }
                                return Ok(Type::Unit);
                            }
                            if let Some(item_ty) = self.parse_named_collection_item_type(name) {
                                if !self.expr_type_compatible_with_expected(&call.args[0], arg_ty, &item_ty, call.span)? {
                                    return Err(CompileError::new(
                                        format!("Vec.push type mismatch: expected {:?}, found {:?}", item_ty, arg_ty),
                                        call.span,
                                    ));
                                }
                                return Ok(Type::Unit);
                            }
                        }
                        Err(CompileError::new("push is only supported on Vec values", call.span))
                    }
                    "clear" => {
                        self.validate_builtin_arity("Vec.clear", 0, arg_types, call.span)?;
                        match &receiver_ty {
                            Type::Named(name) if name == "Vec" || self.parse_named_collection_item_type(name).is_some() => {
                                Ok(Type::Unit)
                            }
                            _ => Err(CompileError::new("clear is only supported on Vec values", call.span)),
                        }
                    }
                    "reverse" => {
                        self.validate_builtin_arity("Vec.reverse", 0, arg_types, call.span)?;
                        match &receiver_ty {
                            Type::Named(name) if name == "Vec" || self.parse_named_collection_item_type(name).is_some() => {
                                Ok(Type::Unit)
                            }
                            _ => Err(CompileError::new("reverse is only supported on Vec values", call.span)),
                        }
                    }
                    "truncate" => {
                        self.validate_builtin_arity("Vec.truncate", 1, arg_types, call.span)?;
                        if arg_types[0] != Type::U64 {
                            return Err(CompileError::new("Vec.truncate expects a u64 length", call.span));
                        }
                        match &receiver_ty {
                            Type::Named(name) if name == "Vec" || self.parse_named_collection_item_type(name).is_some() => {
                                Ok(Type::Unit)
                            }
                            _ => Err(CompileError::new("truncate is only supported on Vec values", call.span)),
                        }
                    }
                    "swap" => {
                        self.validate_builtin_arity("Vec.swap", 2, arg_types, call.span)?;
                        if arg_types[0] != Type::U64 || arg_types[1] != Type::U64 {
                            return Err(CompileError::new("Vec.swap expects u64 indices", call.span));
                        }
                        match &receiver_ty {
                            Type::Named(name) if name == "Vec" || self.parse_named_collection_item_type(name).is_some() => {
                                Ok(Type::Unit)
                            }
                            _ => Err(CompileError::new("swap is only supported on Vec values", call.span)),
                        }
                    }
                    "contains" => {
                        self.validate_builtin_arity("Vec.contains", 1, arg_types, call.span)?;
                        let arg_ty = &arg_types[0];
                        match &receiver_ty {
                            Type::Named(name) if name == "Vec" => {
                                if let Expr::Identifier(receiver_name) = field.expr.as_ref() {
                                    env.update_type(receiver_name, Type::Named(format!("Vec<{}>", type_repr(arg_ty))));
                                }
                                Ok(Type::Bool)
                            }
                            Type::Named(name) => {
                                let Some(item_ty) = self.parse_named_collection_item_type(name) else {
                                    return Err(CompileError::new("contains is only supported on Vec values", call.span));
                                };
                                if !self.expr_type_compatible_with_expected(&call.args[0], arg_ty, &item_ty, call.span)? {
                                    return Err(CompileError::new(
                                        format!("Vec.contains type mismatch: expected {:?}, found {:?}", item_ty, arg_ty),
                                        call.span,
                                    ));
                                }
                                Ok(Type::Bool)
                            }
                            _ => Err(CompileError::new("contains is only supported on Vec values", call.span)),
                        }
                    }
                    "remove" => {
                        self.validate_builtin_arity("Vec.remove", 1, arg_types, call.span)?;
                        if arg_types[0] != Type::U64 {
                            return Err(CompileError::new("Vec.remove expects a u64 index", call.span));
                        }
                        match &receiver_ty {
                            Type::Named(name) => {
                                let Some(item_ty) = self.parse_named_collection_item_type(name) else {
                                    return Err(CompileError::new(
                                        "Vec.remove requires a typed Vec<T>; push or annotate the Vec before removing",
                                        call.span,
                                    ));
                                };
                                Ok(item_ty)
                            }
                            _ => Err(CompileError::new("remove is only supported on Vec values", call.span)),
                        }
                    }
                    "pop" => {
                        self.validate_builtin_arity("Vec.pop", 0, arg_types, call.span)?;
                        match &receiver_ty {
                            Type::Named(name) => {
                                let Some(item_ty) = self.parse_named_collection_item_type(name) else {
                                    return Err(CompileError::new(
                                        "Vec.pop requires a typed Vec<T>; push or annotate the Vec before popping",
                                        call.span,
                                    ));
                                };
                                Ok(item_ty)
                            }
                            _ => Err(CompileError::new("pop is only supported on Vec values", call.span)),
                        }
                    }
                    "insert" => {
                        self.validate_builtin_arity("Vec.insert", 2, arg_types, call.span)?;
                        if arg_types[0] != Type::U64 {
                            return Err(CompileError::new("Vec.insert expects a u64 index", call.span));
                        }
                        let arg_ty = &arg_types[1];
                        if self.type_contains_reference(arg_ty) {
                            return Err(CompileError::new(
                                format!(
                                    "Vec.insert cannot store reference type {}; Vec<T> values must use owned non-reference items",
                                    type_repr(arg_ty)
                                ),
                                call.span,
                            ));
                        }
                        match &receiver_ty {
                            Type::Named(name) if name == "Vec" => {
                                if let Expr::Identifier(receiver_name) = field.expr.as_ref() {
                                    env.update_type(receiver_name, Type::Named(format!("Vec<{}>", type_repr(arg_ty))));
                                }
                                Ok(Type::Unit)
                            }
                            Type::Named(name) => {
                                let Some(item_ty) = self.parse_named_collection_item_type(name) else {
                                    return Err(CompileError::new("insert is only supported on Vec values", call.span));
                                };
                                if !self.expr_type_compatible_with_expected(&call.args[1], arg_ty, &item_ty, call.span)? {
                                    return Err(CompileError::new(
                                        format!("Vec.insert type mismatch: expected {:?}, found {:?}", item_ty, arg_ty),
                                        call.span,
                                    ));
                                }
                                Ok(Type::Unit)
                            }
                            _ => Err(CompileError::new("insert is only supported on Vec values", call.span)),
                        }
                    }
                    "set" => {
                        self.validate_builtin_arity("Vec.set", 2, arg_types, call.span)?;
                        if arg_types[0] != Type::U64 {
                            return Err(CompileError::new("Vec.set expects a u64 index", call.span));
                        }
                        let arg_ty = &arg_types[1];
                        if self.type_contains_reference(arg_ty) {
                            return Err(CompileError::new(
                                format!(
                                    "Vec.set cannot store reference type {}; Vec<T> values must use owned non-reference items",
                                    type_repr(arg_ty)
                                ),
                                call.span,
                            ));
                        }
                        match &receiver_ty {
                            Type::Named(name) if name == "Vec" => {
                                if let Expr::Identifier(receiver_name) = field.expr.as_ref() {
                                    env.update_type(receiver_name, Type::Named(format!("Vec<{}>", type_repr(arg_ty))));
                                }
                                Ok(Type::Unit)
                            }
                            Type::Named(name) => {
                                let Some(item_ty) = self.parse_named_collection_item_type(name) else {
                                    return Err(CompileError::new("set is only supported on Vec values", call.span));
                                };
                                if !self.expr_type_compatible_with_expected(&call.args[1], arg_ty, &item_ty, call.span)? {
                                    return Err(CompileError::new(
                                        format!("Vec.set type mismatch: expected {:?}, found {:?}", item_ty, arg_ty),
                                        call.span,
                                    ));
                                }
                                Ok(Type::Unit)
                            }
                            _ => Err(CompileError::new("set is only supported on Vec values", call.span)),
                        }
                    }
                    "extend_from_slice" => {
                        self.validate_builtin_arity("Vec.extend_from_slice", 1, arg_types, call.span)?;
                        let Some(slice_item_ty) = Self::slice_item_type(&arg_types[0]) else {
                            return Err(CompileError::new("Vec.extend_from_slice expects an array or byte-slice source", call.span));
                        };
                        if self.type_contains_reference(&slice_item_ty) {
                            return Err(CompileError::new(
                                format!(
                                    "Vec.extend_from_slice cannot store reference type {}; Vec<T> values must use owned non-reference items",
                                    type_repr(&slice_item_ty)
                                ),
                                call.span,
                            ));
                        }
                        match &receiver_ty {
                            Type::Named(name) if name == "Vec" => {
                                if let Expr::Identifier(receiver_name) = field.expr.as_ref() {
                                    env.update_type(receiver_name, Type::Named(format!("Vec<{}>", type_repr(&slice_item_ty))));
                                }
                                Ok(Type::Unit)
                            }
                            Type::Named(name) => {
                                let Some(item_ty) = self.parse_named_collection_item_type(name) else {
                                    return Err(CompileError::new("extend_from_slice is only supported on Vec values", call.span));
                                };
                                if !self.types_equal(&item_ty, &slice_item_ty) {
                                    return Err(CompileError::new(
                                        format!(
                                            "Vec.extend_from_slice type mismatch: expected {:?}, found {:?}",
                                            item_ty, slice_item_ty
                                        ),
                                        call.span,
                                    ));
                                }
                                Ok(Type::Unit)
                            }
                            _ => Err(CompileError::new("extend_from_slice is only supported on Vec values", call.span)),
                        }
                    }
                    _ => self.lookup_field_type(&receiver_ty, &field.field, field.span),
                }
            }
            _ => Err(CompileError::new("unsupported call target", call.span)),
        }
    }

    fn validate_namespaced_type_constructor(&self, type_name: &str, constructor: &str, span: Span) -> Result<()> {
        if type_name == "Vec" {
            return Ok(());
        }
        self.validate_named_type(type_name)
            .map_err(|_| CompileError::new(format!("unknown namespaced function '{}::{}'", type_name, constructor), span))
    }

    fn validate_call_args(&self, callee_name: &str, expected: &[Type], actual: &[Type], args: &[Expr], span: Span) -> Result<()> {
        if actual.len() != expected.len() {
            return Err(CompileError::new(
                format!(
                    "function '{}' expects {} argument{}, found {}",
                    callee_name,
                    expected.len(),
                    if expected.len() == 1 { "" } else { "s" },
                    actual.len()
                ),
                span,
            ));
        }

        for (index, ((expected_ty, actual_ty), arg)) in expected.iter().zip(actual.iter()).zip(args.iter()).enumerate() {
            if !self.call_argument_type_compatible(expected_ty, actual_ty)
                && !self.expr_type_compatible_with_expected(arg, actual_ty, expected_ty, span)?
            {
                return Err(CompileError::new(
                    format!(
                        "function '{}' argument {} type mismatch: expected {}, found {}",
                        callee_name,
                        index + 1,
                        type_repr(expected_ty),
                        type_repr(actual_ty)
                    ),
                    span,
                ));
            }
        }

        self.reject_duplicate_mutable_reference_call_roots(callee_name, expected, actual, args, span)?;

        Ok(())
    }

    fn reject_duplicate_mutable_reference_call_roots(
        &self,
        callee_name: &str,
        expected: &[Type],
        actual: &[Type],
        args: &[Expr],
        span: Span,
    ) -> Result<()> {
        let mut roots: HashMap<&str, bool> = HashMap::new();
        for (expected_ty, (actual_ty, arg)) in expected.iter().zip(actual.iter().zip(args.iter())) {
            if !matches!(actual_ty, Type::MutRef(_)) {
                continue;
            }
            let participates_in_mutable_alias = matches!(expected_ty, Type::MutRef(_));
            for root in mutable_reference_root_names(arg) {
                if let Some(prior_participated) = roots.get(root).copied() {
                    if participates_in_mutable_alias || prior_participated {
                        return Err(CompileError::new(
                            format!(
                                "function '{}' cannot receive mutable reference root '{}' more than once in one call; use signature-direction outputs for Cell updates",
                                callee_name, root
                            ),
                            span,
                        ));
                    }
                } else {
                    roots.insert(root, participates_in_mutable_alias);
                }
            }
        }
        Ok(())
    }

    fn call_argument_type_compatible(&self, expected: &Type, actual: &Type) -> bool {
        match (expected, actual) {
            (Type::Ref(expected_inner), Type::MutRef(actual_inner)) => self.types_equal(expected_inner, actual_inner),
            _ => self.types_equal(expected, actual),
        }
    }

    fn validate_builtin_arity(&self, name: &str, expected: usize, actual: &[Type], span: Span) -> Result<()> {
        if actual.len() == expected {
            Ok(())
        } else {
            Err(CompileError::new(
                format!("{} expects {} argument{}, found {}", name, expected, if expected == 1 { "" } else { "s" }, actual.len()),
                span,
            ))
        }
    }

    fn validate_numeric_builtin_call(&self, name: &str, arg_types: &[Type], span: Span) -> Result<()> {
        let expected = if name == "isqrt" { 1 } else { 2 };
        self.validate_builtin_arity(name, expected, arg_types, span)?;
        for (index, arg_ty) in arg_types.iter().enumerate() {
            if !self.is_numeric_type(arg_ty) {
                return Err(CompileError::new(
                    format!("{} argument {} must be numeric, found {}", name, index + 1, type_repr(arg_ty)),
                    span,
                ));
            }
        }
        Ok(())
    }

    fn validate_static_spawn_target_expr(&self, expr: &Expr, span: Span) -> Result<()> {
        match expr {
            Expr::String(_) => Ok(()),
            Expr::Identifier(name) if self.is_string_constant(name) => {
                Ok(())
            }
            _ => Err(CompileError::new(
                "spawn target must be a static script reference: use a string literal or String const, not runtime witness/action data",
                span,
            )),
        }
    }

    fn is_string_constant(&self, name: &str) -> bool {
        self.constants.get(name).is_some_and(|constant| matches!(constant.ty, Type::Named(ref ty) if ty == "String"))
            || self.resolve_constant(name).is_some_and(|constant| matches!(constant.ty, Type::Named(ref ty) if ty == "String"))
    }

    fn reject_forbidden_consensus_call(&self, call: &CallExpr) -> Result<()> {
        if let Some(name) = forbidden_consensus_call_name(call.func.as_ref()) {
            return Err(CompileError::new(
                format!("{} is forbidden in consensus CellScript; use explicit control flow and checked error handling instead", name),
                call.span,
            ));
        }
        Ok(())
    }

    fn resolve_function(&self, name: &str) -> Option<FunctionDef> {
        self.resolver.zip(self.current_module.as_deref()).and_then(|(resolver, module)| resolver.resolve_function(module, name))
    }

    fn resolve_constant(&self, name: &str) -> Option<crate::resolve::ConstantDef> {
        self.resolver.zip(self.current_module.as_deref()).and_then(|(resolver, module)| resolver.resolve_constant(module, name))
    }

    fn function_return_type(&self, function: &FunctionDef) -> Option<Type> {
        match function {
            FunctionDef::Action(action) => action.return_type.clone(),
            FunctionDef::Function(function) => function.return_type.clone(),
            FunctionDef::Lock(_) => Some(Type::Bool),
        }
    }

    fn validate_call_allowed(
        &self,
        callee_name: &str,
        callee_kind: CallableKind,
        callee_effect: EffectClass,
        span: Span,
    ) -> Result<()> {
        match (self.current_callable, callee_kind) {
            (Some(CallableKind::Invariant), CallableKind::Action | CallableKind::Lock) => {
                let context = if self.current_validity { "validity predicate" } else { "invariant" };
                Err(CompileError::new(
                    format!("{} cannot call stateful entry '{}'; call a pure helper instead", context, callee_name),
                    span,
                ))
            }
            (Some(CallableKind::Function), CallableKind::Lock) => {
                Err(CompileError::new(format!("function cannot call lock '{}'", callee_name), span))
            }
            (Some(CallableKind::Lock), CallableKind::Action) => {
                Err(CompileError::new(format!("lock cannot call action '{}'", callee_name), span))
            }
            (Some(CallableKind::Lock), CallableKind::Lock) => {
                Err(CompileError::new(format!("lock cannot call lock '{}'", callee_name), span))
            }
            (Some(CallableKind::Invariant), CallableKind::Function) if callee_effect != EffectClass::Pure => {
                let context = if self.current_validity { "validity predicate" } else { "invariant predicate" };
                Err(CompileError::new(
                    format!(
                        "{} cannot call function '{}' with {} effect; only transitively Pure helpers are allowed",
                        context,
                        callee_name,
                        callee_effect.as_str()
                    ),
                    span,
                ))
            }
            _ => Ok(()),
        }
    }

    fn validate_type(&self, ty: &Type) -> Result<()> {
        match ty {
            Type::Unit => Ok(()),
            Type::Array(elem_ty, _) => self.validate_type(elem_ty),
            Type::Tuple(types) => {
                for t in types {
                    self.validate_type(t)?;
                }
                Ok(())
            }
            Type::Ref(inner) | Type::MutRef(inner) => self.validate_type(inner),
            Type::Named(name) => self.validate_named_type(name),
            _ => Ok(()),
        }
    }

    fn validate_named_type(&self, name: &str) -> Result<()> {
        let base_name = name.split('<').next().unwrap_or(name);
        match base_name {
            "Option" | "Result" => {
                return Err(CompileError::new(
                    format!("type '{}' is reserved for the explicit error model but is not implemented yet", base_name),
                    Span::default(),
                ));
            }
            _ => {}
        }

        if let Some(collection) = parse_bounded_collection_type(&Type::Named(name.to_string())) {
            if collection.max_elements == 0 || collection.max_elements > 1024 {
                return Err(CompileError::new(format!("type '{}' requires a maximum cardinality in 1..=1024", name), Span::default()));
            }
            let element_ty = self.parse_named_type_repr(&collection.element_type);
            match collection.kind {
                BoundedCollectionKind::CellSet => {
                    let Some(element_name) = Self::base_type_name(&element_ty) else {
                        return Err(CompileError::new(
                            format!("type '{}' requires a named cell-backed element type", name),
                            Span::default(),
                        ));
                    };
                    match self.resolve_cell_type_kind(element_name) {
                        Some(CellTypeKind::Resource) => {}
                        Some(CellTypeKind::Shared | CellTypeKind::Receipt) => {
                            return Err(CompileError::new(
                                format!(
                                    "type '{}' requires a linear resource element; shared and receipt Cell kinds are not accepted",
                                    name
                                ),
                                Span::default(),
                            ));
                        }
                        None => {
                            return Err(CompileError::new(
                                format!("type '{}' requires a cell-backed linear resource element", name),
                                Span::default(),
                            ));
                        }
                    }
                }
                BoundedCollectionKind::List => {
                    if Self::base_type_name(&element_ty).and_then(|element| self.resolve_cell_type_kind(element)).is_some() {
                        return Err(CompileError::new(
                            format!("type '{}' cannot store a cell-backed linear value; use BoundedCellSet<T, N>", name),
                            Span::default(),
                        ));
                    }
                    if !self.bounded_list_element_is_fixed_width(&element_ty, &mut HashSet::new()) {
                        return Err(CompileError::new(
                            format!("type '{}' requires a fixed-width element type in the first 0.22 surface", name),
                            Span::default(),
                        ));
                    }
                }
            }
            return Ok(());
        }

        if matches!(base_name, "BoundedCellSet" | "BoundedList") {
            return Err(CompileError::new(
                format!(
                    "type '{}' requires exactly one element type and an explicit maximum cardinality, for example {}<T, 16>",
                    name, base_name
                ),
                Span::default(),
            ));
        }

        if matches!(base_name, CKB_INPUT_VIEW_TYPE | CKB_OUTPUT_VIEW_TYPE) {
            let inner = name
                .split_once('<')
                .and_then(|(_, rest)| rest.strip_suffix('>'))
                .ok_or_else(|| CompileError::new(format!("type '{}' requires one cell type argument", base_name), Span::default()))?;
            let inner_type = self.parse_named_type_repr(inner);
            let Some(inner_name) = Self::base_type_name(&inner_type) else {
                return Err(CompileError::new(format!("type '{}' requires a named cell type argument", base_name), Span::default()));
            };
            if self.resolve_cell_type_kind(inner_name).is_none() {
                return Err(CompileError::new(
                    format!("type '{}' requires a cell-backed resource, shared type, or receipt argument", base_name),
                    Span::default(),
                ));
            }
            return Ok(());
        }

        if name.contains('<') && base_name != "Vec" {
            return Err(CompileError::new(
                format!(
                    "generic type '{}' has no local template available for deterministic 0.25 monomorphization; import a concrete specialization or declare the template in this module",
                    name
                ),
                Span::default(),
            )
            .with_code("E2111"));
        }
        if base_name == "Vec"
            && name.contains('<')
            && let Some(item_ty) = self.parse_named_collection_item_type(name)
            && Self::base_type_name(&item_ty).and_then(|item| self.resolve_cell_type_kind(item)).is_some()
        {
            return Err(CompileError::new(
                format!(
                    "type '{}' cannot store a cell-backed resource; use a source-aware BoundedCellSet<T, N> with explicit ownership",
                    name
                ),
                Span::default(),
            ));
        }
        if base_name == "Vec" && name.contains('<') && self.named_type_contains_reference(name) {
            return Err(CompileError::new(
                format!("type '{}' cannot contain reference type; Vec<T> values must use owned non-reference items", name),
                Span::default(),
            ));
        }

        match base_name {
            "String"
            | "Range"
            | "Vec"
            | "usize"
            | "isize"
            | CKB_SCRIPT_ARGS_TYPE
            | CKB_SCRIPT_VALUE_TYPE
            | CKB_CELL_DEP_VIEW_TYPE
            | CKB_HEADER_DEP_VIEW_TYPE
            | CKB_WITNESS_ARGS_VIEW_TYPE
            | CKB_OUT_POINT_TYPE
            | CKB_SCRIPT_VIEW_TYPE
            | CKB_SCRIPT_HASH_TYPE
            | CKB_EPOCH_NUMBER_TYPE
            | CKB_BLOCK_NUMBER_TYPE
            | CKB_EPOCH_LENGTH_TYPE
            | CKB_ENCODED_SINCE_TYPE
            | CKB_ABSOLUTE_EPOCH_SINCE_TYPE
            | CKB_RELATIVE_EPOCH_SINCE_TYPE
            | "Since"
            | "Absolute"
            | "Relative"
            | "EpochFraction" => return Ok(()),
            _ => {}
        }

        if self.type_fields.contains_key(base_name)
            || self.enum_variants.contains_key(base_name)
            || self.cell_type_kinds.contains_key(base_name)
            || self
                .resolver
                .zip(self.current_module.as_deref())
                .and_then(|(resolver, module)| resolver.resolve_type(module, base_name))
                .is_some()
        {
            Ok(())
        } else {
            Err(CompileError::new(format!("unknown type '{}'", name), Span::default()))
        }
    }

    fn bounded_list_element_is_fixed_width(&self, ty: &Type, visiting: &mut HashSet<String>) -> bool {
        match ty {
            Type::U8 | Type::U16 | Type::U32 | Type::I32 | Type::U64 | Type::U128 | Type::Bool | Type::Address | Type::Hash => true,
            Type::Array(inner, _) => self.bounded_list_element_is_fixed_width(inner, visiting),
            Type::Tuple(items) => items.iter().all(|item| self.bounded_list_element_is_fixed_width(item, visiting)),
            Type::Named(name) => {
                let base = name.split('<').next().unwrap_or(name.as_str());
                if matches!(base, "String" | "Vec" | "BoundedList" | "BoundedCellSet") || !visiting.insert(base.to_string()) {
                    return false;
                }
                let fixed = if self.resolve_enum_variant_fields(base).is_some() {
                    self.payload_type_runtime_width(ty, &mut HashSet::new()).is_some()
                        && !self.enum_type_contains_linear_payload(ty, &mut HashSet::new())
                } else {
                    self.resolve_named_type_fields(base)
                        .is_some_and(|fields| fields.values().all(|field| self.bounded_list_element_is_fixed_width(field, visiting)))
                };
                visiting.remove(base);
                fixed
            }
            Type::Unit | Type::Ref(_) | Type::MutRef(_) => false,
        }
    }

    fn types_equal(&self, a: &Type, b: &Type) -> bool {
        match (a, b) {
            (Type::U8, Type::U8) => true,
            (Type::U16, Type::U16) => true,
            (Type::U32, Type::U32) => true,
            (Type::I32, Type::I32) => true,
            (Type::U64, Type::U64) => true,
            (Type::U128, Type::U128) => true,
            (Type::Bool, Type::Bool) => true,
            (Type::Unit, Type::Unit) => true,
            (Type::Address, Type::Address) => true,
            (Type::Hash, Type::Hash) => true,
            (Type::Array(a1, n1), Type::Array(b1, n2)) => n1 == n2 && self.types_equal(a1, b1),
            (Type::Tuple(a1), Type::Tuple(b1)) => {
                a1.len() == b1.len() && a1.iter().zip(b1.iter()).all(|(x, y)| self.types_equal(x, y))
            }
            (Type::Named(a1), Type::Named(b1)) => a1 == b1,
            (Type::Ref(a1), Type::Ref(b1)) => self.types_equal(a1, b1),
            (Type::MutRef(a1), Type::MutRef(b1)) => self.types_equal(a1, b1),
            _ => false,
        }
    }

    fn base_type_name(ty: &Type) -> Option<&str> {
        match ty {
            Type::Named(name) => Some(name.split('<').next().unwrap_or(name.as_str())),
            Type::Ref(inner) | Type::MutRef(inner) => Self::base_type_name(inner),
            _ => None,
        }
    }

    fn is_address_like_type(ty: &Type) -> bool {
        matches!(ty, Type::Address | Type::Hash)
    }

    fn is_receipt_type(&self, ty: &Type) -> bool {
        Self::base_type_name(ty).and_then(|name| self.resolve_cell_type_kind(name)).is_some_and(|kind| kind == CellTypeKind::Receipt)
    }

    fn resolve_cell_type_kind(&self, name: &str) -> Option<CellTypeKind> {
        if let Some(kind) = self.cell_type_kinds.get(name).copied() {
            return Some(kind);
        }
        let (resolver, module) = (self.resolver?, self.current_module.as_ref()?);
        match resolver.resolve_type(module, name)? {
            TypeDef::Resource(_) => Some(CellTypeKind::Resource),
            TypeDef::Shared(_) => Some(CellTypeKind::Shared),
            TypeDef::Receipt(_) => Some(CellTypeKind::Receipt),
            TypeDef::Struct(_) | TypeDef::Enum(_) => None,
        }
    }

    fn validate_receipt_claim_output(&self, output: &Type, span: Span) -> Result<()> {
        let Some(type_name) = Self::base_type_name(output) else {
            return Err(CompileError::new("receipt claim output must be a cell-backed resource or shared type", span));
        };
        match self.resolve_cell_type_kind(type_name) {
            Some(CellTypeKind::Resource | CellTypeKind::Shared) => Ok(()),
            Some(CellTypeKind::Receipt) => Err(CompileError::new("receipt claim output must not be another receipt", span)),
            None => Err(CompileError::new("receipt claim output must be a cell-backed resource or shared type", span)),
        }
    }

    fn resolve_receipt_claim_output(&self, name: &str) -> Option<Option<Type>> {
        if let Some(output) = self.receipt_claim_outputs.get(name) {
            return Some(output.clone());
        }
        let (resolver, module) = (self.resolver?, self.current_module.as_ref()?);
        match resolver.resolve_type(module, name)? {
            TypeDef::Receipt(receipt) => Some(receipt.claim_output),
            TypeDef::Resource(_) | TypeDef::Shared(_) | TypeDef::Struct(_) | TypeDef::Enum(_) => None,
        }
    }

    fn require_named_linear_cell_operand(
        &mut self,
        env: &mut TypeEnv,
        expr: &Expr,
        operation: &str,
        span: Span,
    ) -> Result<(Type, String)> {
        let ty = self.infer_expr(env, expr)?;
        if !self.is_linear_type(&ty) {
            return Err(CompileError::new(format!("{} requires a cell-backed linear value", operation), span));
        }
        match expr {
            Expr::Identifier(name) => {
                self.reject_active_borrow_root_lifecycle(name, operation, span)?;
                Ok((ty, name.clone()))
            }
            _ => Err(CompileError::new(
                format!("{} requires a named cell-backed value so the compiler can track linear ownership", operation),
                span,
            )),
        }
    }

    fn resolve_capabilities(&self, name: &str) -> Option<HashSet<Capability>> {
        if let Some(capabilities) = self.type_capabilities.get(name) {
            return Some(capabilities.clone());
        }
        let (resolver, module) = (self.resolver?, self.current_module.as_ref()?);
        match resolver.resolve_type(module, name)? {
            TypeDef::Resource(resource) => Some(resource.capabilities.into_iter().collect()),
            TypeDef::Shared(shared) => Some(shared.capabilities.into_iter().collect()),
            TypeDef::Receipt(receipt) => Some(receipt.capabilities.into_iter().collect()),
            TypeDef::Struct(_) | TypeDef::Enum(_) => None,
        }
    }

    fn resolve_identity_policy(&self, name: &str) -> Option<IdentityPolicy> {
        if let Some(identity) = self.type_identities.get(name) {
            return Some(identity.clone());
        }
        let (resolver, module) = (self.resolver?, self.current_module.as_ref()?);
        match resolver.resolve_type(module, name)? {
            TypeDef::Resource(resource) => Some(resource.identity),
            TypeDef::Shared(shared) => Some(shared.identity),
            TypeDef::Receipt(receipt) => Some(receipt.identity),
            TypeDef::Struct(_) | TypeDef::Enum(_) => None,
        }
    }

    fn require_declared_identity_match(&self, type_name: &str, requested: &IdentityPolicy, span: Span, operation: &str) -> Result<()> {
        let declared = self.resolve_identity_policy(type_name).unwrap_or_default();
        if declared == *requested && !matches!(&declared, IdentityPolicy::None) {
            return Ok(());
        }
        let required = identity_condition(requested);
        let provided = identity_condition(&declared);
        Err(CompileError::new(
            format!(
                "{} rejected for type '{}': required identity condition '{}'; provided '{}'; missing '{}'; capability-set version {}; entailment version {}",
                operation,
                type_name,
                required,
                provided,
                required,
                Capability::REGISTRY_VERSION,
                CapabilityOperation::ENTAILMENT_VERSION
            ),
            span,
        ))
    }

    fn require_capability_operation(
        &self,
        ty: &Type,
        operation: CapabilityOperation,
        requested_identity: Option<&IdentityPolicy>,
        span: Span,
    ) -> Result<()> {
        let Some(type_name) = Self::base_type_name(ty) else {
            return Err(CompileError::new(format!("{} requires a cell-backed value", operation.as_str()), span));
        };
        let Some(capabilities) = self.resolve_capabilities(type_name) else {
            return Err(CompileError::new(format!("{} requires a cell-backed value", operation.as_str()), span));
        };
        let entailment = operation.evaluate(&capabilities);
        let declared_identity = self.resolve_identity_policy(type_name).unwrap_or_default();
        let identity_matches = !operation.requires_identity_preservation()
            || requested_identity
                .is_some_and(|requested| *requested == declared_identity && !matches!(&declared_identity, IdentityPolicy::None));
        if entailment.missing.is_empty() && identity_matches {
            return Ok(());
        }

        let mut required = entailment.required.iter().map(|capability| capability.as_str().to_string()).collect::<Vec<_>>();
        if operation.requires_identity_preservation() {
            required.push("identity-preservation".to_string());
        }
        let mut provided = capabilities.iter().copied().collect::<Vec<_>>();
        provided.sort_by_key(|capability| capability.registry_index());
        let mut provided = provided.iter().map(|capability| capability.as_str().to_string()).collect::<Vec<_>>();
        if !matches!(&declared_identity, IdentityPolicy::None) {
            provided.push(identity_condition(&declared_identity));
        }
        let mut entailed = entailment.entailed.iter().map(|capability| capability.as_str().to_string()).collect::<Vec<_>>();
        let mut missing = entailment.missing.iter().map(|capability| capability.as_str().to_string()).collect::<Vec<_>>();
        if operation.requires_identity_preservation() {
            if identity_matches {
                entailed.push("identity-preservation".to_string());
            } else {
                missing.push(requested_identity.map_or_else(|| "identity(...)".to_string(), identity_condition));
            }
        }
        Err(CompileError::new(
            format!(
                "capability check rejected for operation '{}' on type '{}': required [{}]; provided [{}]; entailed [{}]; missing [{}]; capability-set version {}; entailment version {}",
                operation.as_str(),
                type_name,
                required.join(", "),
                provided.join(", "),
                entailed.join(", "),
                missing.join(", "),
                Capability::REGISTRY_VERSION,
                CapabilityOperation::ENTAILMENT_VERSION
            ),
            span,
        ))
    }

    fn is_linear_type(&self, ty: &Type) -> bool {
        self.is_linear_type_with_seen(ty, &mut HashSet::new())
    }

    fn is_linear_type_with_seen(&self, ty: &Type, visiting: &mut HashSet<String>) -> bool {
        match ty {
            Type::Array(inner, _) => self.is_linear_type_with_seen(inner, visiting),
            Type::Tuple(items) => items.iter().any(|item| self.is_linear_type_with_seen(item, visiting)),
            Type::Named(name) => {
                if parse_bounded_collection_type(ty).is_some_and(|collection| collection.kind == BoundedCollectionKind::CellSet) {
                    return true;
                }
                let base_name = name.split('<').next().unwrap_or(name.as_str());
                if self.linear_types.contains(base_name)
                    || self
                        .resolver
                        .zip(self.current_module.as_ref())
                        .is_some_and(|(resolver, module)| resolver.type_is_linear(module, base_name))
                {
                    return true;
                }
                if !visiting.insert(name.clone()) {
                    return false;
                }
                let linear_struct = self
                    .resolve_named_type_fields(name)
                    .is_some_and(|fields| fields.values().any(|field| self.is_linear_type_with_seen(field, visiting)));
                let linear_enum = self
                    .resolve_enum_variant_fields(name)
                    .is_some_and(|variants| variants.values().flatten().any(|field| self.is_linear_type_with_seen(field, visiting)));
                visiting.remove(name);
                linear_struct || linear_enum
            }
            _ => false,
        }
    }

    fn is_numeric_type(&self, ty: &Type) -> bool {
        matches!(ty, Type::U8 | Type::U16 | Type::U32 | Type::I32 | Type::U64 | Type::U128)
            || matches!(ty, Type::Named(name) if name == "usize" || name == "isize")
    }

    fn is_ordered_ckb_temporal_type(ty: &Type) -> bool {
        matches!(
            ty,
            Type::Named(name)
                if matches!(
                    name.as_str(),
                    CKB_EPOCH_NUMBER_TYPE
                        | CKB_BLOCK_NUMBER_TYPE
                        | CKB_EPOCH_LENGTH_TYPE
                        | CKB_ABSOLUTE_EPOCH_SINCE_TYPE
                        | CKB_RELATIVE_EPOCH_SINCE_TYPE
                )
        )
    }

    fn is_ckb_since_type(ty: &Type) -> bool {
        matches!(
            ty,
            Type::Named(name)
                if name == CKB_ENCODED_SINCE_TYPE
                    || name == CKB_ABSOLUTE_EPOCH_SINCE_TYPE
                    || name == CKB_RELATIVE_EPOCH_SINCE_TYPE
                    || name.starts_with("Since<Absolute, ")
                    || name.starts_with("Since<Relative, ")
        )
    }

    fn is_unsigned_shift_count_type(ty: &Type) -> bool {
        matches!(ty, Type::U8 | Type::U16 | Type::U32 | Type::U64) || matches!(ty, Type::Named(name) if name == "usize")
    }

    fn integer_type_width_bits(ty: &Type) -> Option<u16> {
        match ty {
            Type::U8 => Some(8),
            Type::U16 => Some(16),
            Type::U32 | Type::I32 => Some(32),
            Type::U64 | Type::Named(_) => Some(64),
            Type::U128 => Some(128),
            _ => None,
        }
    }

    fn validate_checked_cast(&self, expr: &Expr, source: &Type, target: &Type, span: Span) -> Result<()> {
        if self.types_equal(source, target) {
            return Ok(());
        }

        if let Expr::Integer(value) = expr
            && Self::integer_literal_fits_expected_type(*value, target)
        {
            return Ok(());
        }

        if self.is_numeric_type(source) && self.is_numeric_type(target) {
            let source_signed = matches!(source, Type::I32) || matches!(source, Type::Named(name) if name == "isize");
            let target_signed = matches!(target, Type::I32) || matches!(target, Type::Named(name) if name == "isize");
            if source_signed || target_signed {
                return Err(CompileError::new(
                    format!(
                        "unsupported signed numeric cast from {} to {}; 0.22 casts must preserve signedness or use a checked conversion",
                        type_repr(source),
                        type_repr(target)
                    ),
                    span,
                ));
            }
            if matches!(source, Type::U128) && !matches!(target, Type::U128) {
                return Err(CompileError::new(
                    format!(
                        "unsupported full-width narrowing cast from {} to {}; use an explicit checked conversion once u128 narrowing is available",
                        type_repr(source),
                        type_repr(target)
                    ),
                    span,
                ));
            }
            return Ok(());
        }

        Err(CompileError::new(
            format!(
                "unsupported cast from {} to {}; casts cannot erase Cell identity, linear ownership, reference, or capability boundaries",
                type_repr(source),
                type_repr(target)
            ),
            span,
        ))
    }

    fn is_bool_type(&self, ty: &Type) -> bool {
        matches!(ty, Type::Bool)
    }
}

fn stmt_span(stmt: &Stmt) -> Span {
    match stmt {
        Stmt::Let(let_stmt) => let_stmt.span,
        Stmt::Expr(expr) => expr_span(expr),
        Stmt::Return(ReturnStmt { value: Some(expr), span }) => non_default_span(expr_span(expr), *span),
        Stmt::Return(ReturnStmt { value: None, span }) => *span,
        Stmt::If(if_stmt) => if_stmt.span,
        Stmt::For(for_stmt) => for_stmt.span,
        Stmt::While(while_stmt) => while_stmt.span,
        Stmt::Break(control) | Stmt::Continue(control) => control.span,
        Stmt::Borrow(borrow_stmt) => borrow_stmt.span,
    }
}

fn non_default_span(preferred: Span, fallback: Span) -> Span {
    if preferred.line == 0 || preferred.column == 0 {
        fallback
    } else {
        preferred
    }
}

fn push_diagnostic(diagnostics: &mut Vec<CompileError>, result: Result<()>) {
    if let Err(error) = result {
        diagnostics.push(error);
    }
}

fn note_replace_field(schema_fields: &[String], covered: &mut Vec<String>, field: &str, span: crate::error::Span) -> Result<()> {
    if !schema_fields.iter().any(|candidate| candidate == field) {
        return Err(CompileError::new(format!("replace relation field '{field}' does not exist on the relation's resource"), span)
            .with_code("E1002"));
    }
    if covered.iter().any(|candidate| candidate == field) {
        return Err(CompileError::new(format!("replace relation states field '{field}' more than once"), span));
    }
    covered.push(field.to_string());
    Ok(())
}

fn check_replace_assigned_field(
    checker: &mut TypeChecker,
    env: &mut TypeEnv,
    resource_ty: &Type,
    field: &str,
    value: &Expr,
    span: crate::error::Span,
) -> Result<()> {
    let expected = checker.lookup_field_type(resource_ty, field, span)?;
    let actual = checker.infer_expr(env, value)?;
    if !checker.types_equal(&expected, &actual) {
        return Err(CompileError::new(
            format!("replace relation field '{field}' expects {}, found {}", type_repr(&expected), type_repr(&actual)),
            span,
        )
        .with_code("E1004"));
    }
    Ok(())
}

fn expr_span(expr: &Expr) -> Span {
    match expr {
        Expr::Integer(_) | Expr::Bool(_) | Expr::String(_) | Expr::ByteString(_) | Expr::Identifier(_) => Span::default(),
        Expr::StdlibCall(call) => call.span,
        Expr::Assign(assign) => assign.span,
        Expr::Binary(binary) => binary.span,
        Expr::Unary(unary) => unary.span,
        Expr::Call(call) => call.span,
        Expr::FieldAccess(field) => field.span,
        Expr::Index(index) => index.span,
        Expr::Create(create) => create.span,
        Expr::Consume(consume) => consume.span,
        Expr::Destroy(destroy) => destroy.span,
        Expr::ReadRef(read_ref) => read_ref.span,
        Expr::Claim(claim) => claim.span,
        Expr::Settle(settle) => settle.span,
        Expr::CreateUnique(cu) => cu.span,
        Expr::ReplaceUnique(ru) => ru.span,
        Expr::Assert(assert_expr) => assert_expr.span,
        Expr::Require(require_expr) => require_expr.span,
        Expr::Block(stmts) => stmts.last().map(stmt_span).unwrap_or_default(),
        Expr::Tuple(_) | Expr::Array(_) => Span::default(),
        Expr::If(if_expr) => if_expr.span,
        Expr::Cast(cast) => cast.span,
        Expr::Range(range) => range.span,
        Expr::StructInit(init) => init.span,
        Expr::Match(match_expr) => match_expr.span,
        Expr::RequireBlock(require_block) => require_block.span,
        Expr::Preserve(preserve) => preserve.span,
        Expr::ReplaceRelation(relation) => relation.span,
    }
}

fn expr_uses_identifier(expr: &Expr, expected: &str) -> bool {
    match expr {
        Expr::Identifier(name) => name == expected,
        Expr::Assign(assign) => expr_uses_identifier(&assign.target, expected) || expr_uses_identifier(&assign.value, expected),
        Expr::Binary(binary) => expr_uses_identifier(&binary.left, expected) || expr_uses_identifier(&binary.right, expected),
        Expr::Unary(unary) => expr_uses_identifier(&unary.expr, expected),
        Expr::Call(call) => {
            expr_uses_identifier(&call.func, expected) || call.args.iter().any(|arg| expr_uses_identifier(arg, expected))
        }
        Expr::FieldAccess(field) => expr_uses_identifier(&field.expr, expected),
        Expr::Index(index) => expr_uses_identifier(&index.expr, expected) || expr_uses_identifier(&index.index, expected),
        Expr::Create(create) => {
            create.fields.iter().any(|(_, value)| expr_uses_identifier(value, expected))
                || create.lock.as_ref().is_some_and(|lock| expr_uses_identifier(lock, expected))
        }
        Expr::Consume(consume) => expr_uses_identifier(&consume.expr, expected),
        Expr::Destroy(destroy) => expr_uses_identifier(&destroy.expr, expected),
        Expr::ReadRef(_) => false,
        Expr::Claim(claim) => expr_uses_identifier(&claim.receipt, expected),
        Expr::Settle(settle) => expr_uses_identifier(&settle.expr, expected),
        Expr::CreateUnique(create) => {
            create.fields.iter().any(|(_, value)| expr_uses_identifier(value, expected))
                || create.lock.as_ref().is_some_and(|lock| expr_uses_identifier(lock, expected))
        }
        Expr::ReplaceUnique(replace) => {
            expr_uses_identifier(&replace.expr, expected)
                || replace.fields.iter().any(|(_, value)| expr_uses_identifier(value, expected))
        }
        Expr::Assert(assert_expr) => {
            expr_uses_identifier(&assert_expr.condition, expected) || expr_uses_identifier(&assert_expr.message, expected)
        }
        Expr::Require(require_expr) => {
            expr_uses_identifier(&require_expr.condition, expected)
                || require_expr.message.as_ref().is_some_and(|message| expr_uses_identifier(message, expected))
        }
        Expr::Block(stmts) => stmts.iter().any(|stmt| stmt_uses_identifier(stmt, expected)),
        Expr::Tuple(items) | Expr::Array(items) => items.iter().any(|item| expr_uses_identifier(item, expected)),
        Expr::If(if_expr) => {
            expr_uses_identifier(&if_expr.condition, expected)
                || expr_uses_identifier(&if_expr.then_branch, expected)
                || expr_uses_identifier(&if_expr.else_branch, expected)
        }
        Expr::Cast(cast) => expr_uses_identifier(&cast.expr, expected),
        Expr::Range(range) => expr_uses_identifier(&range.start, expected) || expr_uses_identifier(&range.end, expected),
        Expr::StructInit(init) => init.fields.iter().any(|(_, value)| expr_uses_identifier(value, expected)),
        Expr::Match(match_expr) => {
            expr_uses_identifier(&match_expr.expr, expected)
                || match_expr.arms.iter().any(|arm| expr_uses_identifier(&arm.value, expected))
        }
        Expr::RequireBlock(require_block) => require_block.expressions.iter().any(|expr| expr_uses_identifier(expr, expected)),
        Expr::Preserve(preserve) => preserve.output_name == expected || preserve.input_name == expected,
        Expr::ReplaceRelation(relation) => {
            relation.before == expected
                || relation.after == expected
                || match &relation.lock {
                    ReplaceLockTreatment::Exact(lock) | ReplaceLockTreatment::ExactHash(lock) => expr_uses_identifier(lock, expected),
                    ReplaceLockTreatment::Same => false,
                }
                || match &relation.data {
                    ReplaceDataTreatment::Fields(treatments) => treatments.iter().any(|treatment| match treatment {
                        ReplaceFieldTreatment::Same(_) => false,
                        ReplaceFieldTreatment::Assign(_, value) => expr_uses_identifier(value, expected),
                    }),
                    ReplaceDataTreatment::SameExcept(assigned) => {
                        assigned.iter().any(|(_, value)| expr_uses_identifier(value, expected))
                    }
                }
        }
        Expr::StdlibCall(call) => call.args.iter().any(|arg| expr_uses_identifier(arg, expected)),
        Expr::Integer(_) | Expr::Bool(_) | Expr::String(_) | Expr::ByteString(_) => false,
    }
}

fn expr_contains_borrow_marker(expr: &Expr, binding: &str) -> bool {
    match expr {
        Expr::Identifier(name) => name == binding,
        Expr::ReplaceRelation(relation) => relation.value_exprs().iter().any(|value| expr_contains_borrow_marker(value, binding)),
        Expr::Tuple(items) | Expr::Array(items) => items.iter().any(|item| expr_contains_borrow_marker(item, binding)),
        Expr::StructInit(init) => init.fields.iter().any(|(_, value)| expr_contains_borrow_marker(value, binding)),
        Expr::Cast(cast) => expr_contains_borrow_marker(&cast.expr, binding),
        Expr::If(if_expr) => {
            expr_contains_borrow_marker(&if_expr.then_branch, binding) || expr_contains_borrow_marker(&if_expr.else_branch, binding)
        }
        Expr::Match(match_expr) => match_expr.arms.iter().any(|arm| expr_contains_borrow_marker(&arm.value, binding)),
        Expr::Block(stmts) => stmts.last().is_some_and(|stmt| match stmt {
            Stmt::Expr(expr) | Stmt::Return(ReturnStmt { value: Some(expr), .. }) => expr_contains_borrow_marker(expr, binding),
            _ => false,
        }),
        Expr::Unary(unary) if unary.op == UnaryOp::Deref => false,
        Expr::Unary(unary) => expr_contains_borrow_marker(&unary.expr, binding),
        Expr::Assign(assign) => expr_contains_borrow_marker(&assign.value, binding),
        Expr::Integer(_)
        | Expr::Bool(_)
        | Expr::String(_)
        | Expr::ByteString(_)
        | Expr::Call(_)
        | Expr::FieldAccess(_)
        | Expr::Create(_)
        | Expr::Consume(_)
        | Expr::Destroy(_)
        | Expr::ReadRef(_)
        | Expr::Claim(_)
        | Expr::Settle(_)
        | Expr::CreateUnique(_)
        | Expr::ReplaceUnique(_)
        | Expr::Assert(_)
        | Expr::Require(_)
        | Expr::Range(_)
        | Expr::RequireBlock(_)
        | Expr::Preserve(_)
        | Expr::StdlibCall(_) => false,
        Expr::Binary(binary) => {
            expr_contains_borrow_marker(&binary.left, binding) || expr_contains_borrow_marker(&binary.right, binding)
        }
        Expr::Index(index) => expr_contains_borrow_marker(&index.expr, binding),
    }
}

fn stmt_uses_identifier(stmt: &Stmt, expected: &str) -> bool {
    match stmt {
        Stmt::Let(let_stmt) => expr_uses_identifier(&let_stmt.value, expected),
        Stmt::Expr(expr) => expr_uses_identifier(expr, expected),
        Stmt::Return(return_stmt) => return_stmt.value.as_ref().is_some_and(|value| expr_uses_identifier(value, expected)),
        Stmt::Break(_) | Stmt::Continue(_) => false,
        Stmt::If(if_stmt) => {
            expr_uses_identifier(&if_stmt.condition, expected)
                || if_stmt.then_branch.iter().any(|stmt| stmt_uses_identifier(stmt, expected))
                || if_stmt.else_branch.as_ref().is_some_and(|branch| branch.iter().any(|stmt| stmt_uses_identifier(stmt, expected)))
        }
        Stmt::For(for_stmt) => {
            expr_uses_identifier(&for_stmt.iterable, expected) || for_stmt.body.iter().any(|stmt| stmt_uses_identifier(stmt, expected))
        }
        Stmt::While(while_stmt) => {
            expr_uses_identifier(&while_stmt.condition, expected)
                || while_stmt.body.iter().any(|stmt| stmt_uses_identifier(stmt, expected))
        }
        Stmt::Borrow(borrow_stmt) => borrow_stmt.body.iter().any(|stmt| stmt_uses_identifier(stmt, expected)),
    }
}

fn collect_required_output_fields(expr: &Expr, outputs: &HashSet<String>, fields: &mut HashSet<String>) {
    if let Some(field) = output_field_constraint(expr, outputs) {
        fields.insert(field);
    }

    match expr {
        Expr::Assign(assign) => {
            collect_required_output_fields(&assign.target, outputs, fields);
            collect_required_output_fields(&assign.value, outputs, fields);
        }
        Expr::Binary(binary) => {
            collect_required_output_fields(&binary.left, outputs, fields);
            collect_required_output_fields(&binary.right, outputs, fields);
        }
        Expr::Unary(unary) => collect_required_output_fields(&unary.expr, outputs, fields),
        Expr::Call(call) => {
            collect_required_output_fields(&call.func, outputs, fields);
            for arg in &call.args {
                collect_required_output_fields(arg, outputs, fields);
            }
        }
        Expr::FieldAccess(field) => collect_required_output_fields(&field.expr, outputs, fields),
        Expr::Index(index) => {
            collect_required_output_fields(&index.expr, outputs, fields);
            collect_required_output_fields(&index.index, outputs, fields);
        }
        Expr::Create(create) => {
            for (_, value) in &create.fields {
                collect_required_output_fields(value, outputs, fields);
            }
            if let Some(lock) = &create.lock {
                collect_required_output_fields(lock, outputs, fields);
            }
        }
        Expr::Consume(consume) => collect_required_output_fields(&consume.expr, outputs, fields),
        Expr::Destroy(destroy) => collect_required_output_fields(&destroy.expr, outputs, fields),
        Expr::Claim(claim) => collect_required_output_fields(&claim.receipt, outputs, fields),
        Expr::Settle(settle) => collect_required_output_fields(&settle.expr, outputs, fields),
        Expr::CreateUnique(create) => {
            for (_, value) in &create.fields {
                collect_required_output_fields(value, outputs, fields);
            }
            if let Some(lock) = &create.lock {
                collect_required_output_fields(lock, outputs, fields);
            }
        }
        Expr::ReplaceUnique(replace) => {
            collect_required_output_fields(&replace.expr, outputs, fields);
            for (_, value) in &replace.fields {
                collect_required_output_fields(value, outputs, fields);
            }
        }
        Expr::Assert(assert_expr) => {
            collect_required_output_fields(&assert_expr.condition, outputs, fields);
            collect_required_output_fields(&assert_expr.message, outputs, fields);
        }
        Expr::Require(require_expr) => {
            collect_required_output_fields(&require_expr.condition, outputs, fields);
            if let Some(message) = &require_expr.message {
                collect_required_output_fields(message, outputs, fields);
            }
        }
        Expr::Block(stmts) => {
            for stmt in stmts {
                collect_required_output_fields_from_stmt(stmt, outputs, fields);
            }
        }
        Expr::Tuple(elems) | Expr::Array(elems) => {
            for elem in elems {
                collect_required_output_fields(elem, outputs, fields);
            }
        }
        Expr::If(if_expr) => {
            collect_required_output_fields(&if_expr.condition, outputs, fields);
            collect_required_output_fields(&if_expr.then_branch, outputs, fields);
            collect_required_output_fields(&if_expr.else_branch, outputs, fields);
        }
        Expr::Cast(cast) => collect_required_output_fields(&cast.expr, outputs, fields),
        Expr::Range(range) => {
            collect_required_output_fields(&range.start, outputs, fields);
            collect_required_output_fields(&range.end, outputs, fields);
        }
        Expr::StructInit(init) => {
            for (_, value) in &init.fields {
                collect_required_output_fields(value, outputs, fields);
            }
        }
        Expr::Match(match_expr) => {
            collect_required_output_fields(&match_expr.expr, outputs, fields);
            for arm in &match_expr.arms {
                collect_required_output_fields(&arm.value, outputs, fields);
            }
        }
        Expr::Integer(_)
        | Expr::Bool(_)
        | Expr::String(_)
        | Expr::ByteString(_)
        | Expr::Identifier(_)
        | Expr::ReadRef(_)
        | Expr::StdlibCall(_) => {}
        Expr::RequireBlock(require_block) => {
            for expr in &require_block.expressions {
                collect_required_output_fields(expr, outputs, fields);
            }
        }
        Expr::Preserve(preserve) => {
            for field in &preserve.fields {
                if outputs.contains(field) {
                    fields.insert(field.clone());
                }
            }
        }
        Expr::ReplaceRelation(relation) => {
            let relation_fields: Vec<String> = match &relation.data {
                ReplaceDataTreatment::Fields(treatments) => treatments
                    .iter()
                    .map(|treatment| match treatment {
                        ReplaceFieldTreatment::Same(field) => field.clone(),
                        ReplaceFieldTreatment::Assign(field, _) => field.clone(),
                    })
                    .collect(),
                ReplaceDataTreatment::SameExcept(_) => Vec::new(),
            };
            for field in relation_fields {
                if outputs.contains(&field) {
                    fields.insert(field);
                }
            }
        }
    }
}

fn collect_required_output_fields_from_stmt(stmt: &Stmt, outputs: &HashSet<String>, fields: &mut HashSet<String>) {
    match stmt {
        Stmt::Let(let_stmt) => collect_required_output_fields(&let_stmt.value, outputs, fields),
        Stmt::Expr(expr) | Stmt::Return(ReturnStmt { value: Some(expr), .. }) => collect_required_output_fields(expr, outputs, fields),
        Stmt::Return(ReturnStmt { value: None, .. }) => {}
        Stmt::Break(_) | Stmt::Continue(_) => {}
        Stmt::If(if_stmt) => {
            collect_required_output_fields(&if_stmt.condition, outputs, fields);
            for stmt in &if_stmt.then_branch {
                collect_required_output_fields_from_stmt(stmt, outputs, fields);
            }
            if let Some(else_branch) = &if_stmt.else_branch {
                for stmt in else_branch {
                    collect_required_output_fields_from_stmt(stmt, outputs, fields);
                }
            }
        }
        Stmt::For(for_stmt) => {
            collect_required_output_fields(&for_stmt.iterable, outputs, fields);
            for stmt in &for_stmt.body {
                collect_required_output_fields_from_stmt(stmt, outputs, fields);
            }
        }
        Stmt::While(while_stmt) => {
            collect_required_output_fields(&while_stmt.condition, outputs, fields);
            for stmt in &while_stmt.body {
                collect_required_output_fields_from_stmt(stmt, outputs, fields);
            }
        }
        Stmt::Borrow(borrow_stmt) => {
            for stmt in &borrow_stmt.body {
                collect_required_output_fields_from_stmt(stmt, outputs, fields);
            }
        }
    }
}

fn output_field_constraint(expr: &Expr, outputs: &HashSet<String>) -> Option<String> {
    let Expr::FieldAccess(field) = expr else {
        return None;
    };
    let Expr::Identifier(base) = field.expr.as_ref() else {
        return None;
    };
    if outputs.contains(base) {
        Some(format!("{}.{}", base, field.field))
    } else {
        None
    }
}

fn forbidden_consensus_call_name(expr: &Expr) -> Option<&'static str> {
    match expr {
        Expr::Identifier(name) => forbidden_consensus_terminal(name),
        Expr::FieldAccess(field) => forbidden_consensus_terminal(&field.field),
        _ => None,
    }
}

fn forbidden_consensus_terminal(name: &str) -> Option<&'static str> {
    match name.rsplit("::").next().unwrap_or(name) {
        "unwrap" => Some("unwrap"),
        "expect" => Some("expect"),
        "unwrap_or" => Some("unwrap_or"),
        _ => None,
    }
}

fn match_pattern_variant<'a>(enum_name: &str, pattern: &'a str) -> Option<&'a str> {
    if let Some((qualifier, variant)) = pattern.rsplit_once("::") {
        let qualifier_terminal = qualifier.rsplit("::").next().unwrap_or(qualifier);
        if qualifier == enum_name || qualifier_terminal == enum_name {
            Some(variant)
        } else {
            None
        }
    } else {
        Some(pattern)
    }
}

fn lock_args_static_type_len(ty: &Type) -> Option<usize> {
    match ty {
        Type::Bool | Type::U8 => Some(1),
        Type::U16 => Some(2),
        Type::U32 | Type::I32 => Some(4),
        Type::U64 => Some(8),
        Type::U128 => Some(16),
        Type::Address | Type::Hash => Some(32),
        Type::Array(inner, len) => lock_args_static_type_len(inner).map(|inner_len| inner_len * len),
        Type::Tuple(items) => items.iter().try_fold(0usize, |acc, item| lock_args_static_type_len(item).map(|len| acc + len)),
        Type::Unit => Some(0),
        Type::Named(_) | Type::Ref(_) | Type::MutRef(_) => None,
    }
}

fn item_symbol_name_and_span(item: &Item) -> Option<(&str, Span)> {
    match item {
        Item::Resource(def) => Some((&def.name, def.span)),
        Item::Shared(def) => Some((&def.name, def.span)),
        Item::Receipt(def) => Some((&def.name, def.span)),
        Item::Struct(def) => Some((&def.name, def.span)),
        Item::Flow(def) => def.name.as_deref().map(|name| (name, def.span)),
        Item::Invariant(def) => Some((&def.name, def.span)),
        Item::Enum(def) => Some((&def.name, def.span)),
        Item::Const(def) => Some((&def.name, def.span)),
        Item::Action(def) => Some((&def.name, def.span)),
        Item::Function(def) => Some((&def.name, def.span)),
        Item::Lock(def) => Some((&def.name, def.span)),
        Item::Use(_) => None,
    }
}

fn aggregate_field_type_is_supported(ty: &Type) -> bool {
    match ty {
        Type::U8 | Type::U16 | Type::U32 | Type::I32 | Type::U64 | Type::U128 | Type::Address | Type::Hash => true,
        Type::Array(inner, _) => matches!(inner.as_ref(), Type::U8),
        _ => false,
    }
}

fn assignment_root_name(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Identifier(name) => Some(name.as_str()),
        Expr::FieldAccess(field) => assignment_root_name(&field.expr),
        Expr::Index(index) => assignment_root_name(&index.expr),
        _ => None,
    }
}

fn action_param_owned_named_type<'a>(action: &'a ActionDef, name: &str) -> Option<&'a str> {
    action.params.iter().find(|param| param.name == name).and_then(|param| match &param.ty {
        Type::Named(type_name) if matches!(param.source, ParamSource::Default | ParamSource::Input) && !param.is_read_ref => {
            Some(type_name.split('<').next().unwrap_or(type_name.as_str()))
        }
        _ => None,
    })
}

fn action_param_output_named_type<'a>(action: &'a ActionDef, name: &str) -> Option<&'a str> {
    if let Some(output) = action.outputs.iter().find(|output| output.name == name)
        && let Type::Named(type_name) = &output.ty
    {
        return Some(type_name.split('<').next().unwrap_or(type_name.as_str()));
    }
    None
}

fn action_output_binding_names(action: &ActionDef) -> HashMap<String, ActionOutputBinding> {
    let mut bindings = HashMap::new();
    for output in &action.outputs {
        if let Type::Named(type_name) = &output.ty {
            bindings.insert(
                output.name.clone(),
                ActionOutputBinding { type_name: type_name.split('<').next().unwrap_or(type_name.as_str()).to_string() },
            );
        }
    }
    bindings
}

fn action_core_evidence_binding_names(action: &ActionDef) -> HashSet<String> {
    let mut bindings = action_output_binding_names(action).keys().cloned().collect::<HashSet<_>>();
    for input in action_inferred_lineage_bindings(action).keys() {
        bindings.insert(input.clone());
    }
    bindings
}

fn action_inferred_lineage_bindings(action: &ActionDef) -> HashMap<String, String> {
    let mut bindings = HashMap::new();
    let consumed = action_consumed_bindings(action);
    for state_edge in &action.state_edges {
        if consumed.contains(&state_edge.path.base) {
            continue;
        }
        bindings.entry(state_edge.path.base.clone()).or_insert_with(|| state_edge.to_path.base.clone());
    }

    let mut outputs_by_type: HashMap<String, Vec<String>> = HashMap::new();
    for (name, binding) in action_output_binding_names(action) {
        if bindings.values().any(|bound_output| bound_output == &name) {
            continue;
        }
        outputs_by_type.entry(binding.type_name).or_default().push(name);
    }

    let mut inputs_by_type: HashMap<String, Vec<String>> = HashMap::new();
    for param in &action.params {
        if consumed.contains(&param.name) || bindings.contains_key(&param.name) {
            continue;
        }
        let Some(type_name) = action_param_owned_named_type(action, &param.name) else {
            continue;
        };
        inputs_by_type.entry(type_name.to_string()).or_default().push(param.name.clone());
    }

    for (type_name, inputs) in inputs_by_type {
        let Some(outputs) = outputs_by_type.get(&type_name) else {
            continue;
        };
        if inputs.len() == 1 && outputs.len() == 1 {
            bindings.insert(inputs[0].clone(), outputs[0].clone());
        }
    }

    bindings
}

fn action_consumed_bindings(action: &ActionDef) -> HashSet<String> {
    let mut bindings = HashSet::new();
    collect_consumed_bindings_from_stmts(&action.body, &mut bindings);
    bindings
}

fn collect_consumed_bindings_from_stmts(stmts: &[Stmt], bindings: &mut HashSet<String>) {
    for stmt in stmts {
        match stmt {
            Stmt::Let(let_stmt) => collect_consumed_bindings_from_expr(&let_stmt.value, bindings),
            Stmt::Expr(expr) | Stmt::Return(ReturnStmt { value: Some(expr), .. }) => {
                collect_consumed_bindings_from_expr(expr, bindings)
            }
            Stmt::Return(ReturnStmt { value: None, .. }) => {}
            Stmt::Break(_) | Stmt::Continue(_) => {}
            Stmt::If(if_stmt) => {
                collect_consumed_bindings_from_expr(&if_stmt.condition, bindings);
                collect_consumed_bindings_from_stmts(&if_stmt.then_branch, bindings);
                if let Some(else_branch) = &if_stmt.else_branch {
                    collect_consumed_bindings_from_stmts(else_branch, bindings);
                }
            }
            Stmt::For(for_stmt) => {
                collect_consumed_bindings_from_expr(&for_stmt.iterable, bindings);
                collect_consumed_bindings_from_stmts(&for_stmt.body, bindings);
            }
            Stmt::While(while_stmt) => {
                collect_consumed_bindings_from_expr(&while_stmt.condition, bindings);
                collect_consumed_bindings_from_stmts(&while_stmt.body, bindings);
            }
            Stmt::Borrow(borrow_stmt) => collect_consumed_bindings_from_stmts(&borrow_stmt.body, bindings),
        }
    }
}

fn collect_consumed_bindings_from_expr(expr: &Expr, bindings: &mut HashSet<String>) {
    match expr {
        Expr::Consume(consume) => {
            if let Expr::Identifier(name) = consume.expr.as_ref() {
                bindings.insert(name.clone());
            }
            collect_consumed_bindings_from_expr(&consume.expr, bindings);
        }
        Expr::Assign(assign) => {
            collect_consumed_bindings_from_expr(&assign.target, bindings);
            collect_consumed_bindings_from_expr(&assign.value, bindings);
        }
        Expr::Binary(binary) => {
            collect_consumed_bindings_from_expr(&binary.left, bindings);
            collect_consumed_bindings_from_expr(&binary.right, bindings);
        }
        Expr::Unary(unary) => collect_consumed_bindings_from_expr(&unary.expr, bindings),
        Expr::Call(call) => {
            collect_consumed_bindings_from_expr(&call.func, bindings);
            for arg in &call.args {
                collect_consumed_bindings_from_expr(arg, bindings);
            }
        }
        Expr::FieldAccess(field) => collect_consumed_bindings_from_expr(&field.expr, bindings),
        Expr::Index(index) => {
            collect_consumed_bindings_from_expr(&index.expr, bindings);
            collect_consumed_bindings_from_expr(&index.index, bindings);
        }
        Expr::Create(create) => {
            for (_, value) in &create.fields {
                collect_consumed_bindings_from_expr(value, bindings);
            }
            if let Some(lock) = &create.lock {
                collect_consumed_bindings_from_expr(lock, bindings);
            }
        }
        Expr::Destroy(destroy) => {
            if let Expr::Identifier(name) = destroy.expr.as_ref() {
                bindings.insert(name.clone());
            }
            collect_consumed_bindings_from_expr(&destroy.expr, bindings);
        }
        Expr::Claim(claim) => {
            if let Expr::Identifier(name) = claim.receipt.as_ref() {
                bindings.insert(name.clone());
            }
            collect_consumed_bindings_from_expr(&claim.receipt, bindings);
        }
        Expr::Settle(settle) => {
            if let Expr::Identifier(name) = settle.expr.as_ref() {
                bindings.insert(name.clone());
            }
            collect_consumed_bindings_from_expr(&settle.expr, bindings);
        }
        Expr::CreateUnique(create) => {
            for (_, value) in &create.fields {
                collect_consumed_bindings_from_expr(value, bindings);
            }
            if let Some(lock) = &create.lock {
                collect_consumed_bindings_from_expr(lock, bindings);
            }
        }
        Expr::ReplaceUnique(replace) => {
            if let Expr::Identifier(name) = replace.expr.as_ref() {
                bindings.insert(name.clone());
            }
            collect_consumed_bindings_from_expr(&replace.expr, bindings);
            for (_, value) in &replace.fields {
                collect_consumed_bindings_from_expr(value, bindings);
            }
        }
        Expr::Assert(assert_expr) => {
            collect_consumed_bindings_from_expr(&assert_expr.condition, bindings);
            collect_consumed_bindings_from_expr(&assert_expr.message, bindings);
        }
        Expr::Require(require_expr) => {
            collect_consumed_bindings_from_expr(&require_expr.condition, bindings);
            if let Some(message) = &require_expr.message {
                collect_consumed_bindings_from_expr(message, bindings);
            }
        }
        Expr::Block(stmts) => collect_consumed_bindings_from_stmts(stmts, bindings),
        Expr::Tuple(items) | Expr::Array(items) => {
            for item in items {
                collect_consumed_bindings_from_expr(item, bindings);
            }
        }
        Expr::If(if_expr) => {
            collect_consumed_bindings_from_expr(&if_expr.condition, bindings);
            collect_consumed_bindings_from_expr(&if_expr.then_branch, bindings);
            collect_consumed_bindings_from_expr(&if_expr.else_branch, bindings);
        }
        Expr::Cast(cast) => collect_consumed_bindings_from_expr(&cast.expr, bindings),
        Expr::Range(range) => {
            collect_consumed_bindings_from_expr(&range.start, bindings);
            collect_consumed_bindings_from_expr(&range.end, bindings);
        }
        Expr::StructInit(init) => {
            for (_, value) in &init.fields {
                collect_consumed_bindings_from_expr(value, bindings);
            }
        }
        Expr::Match(match_expr) => {
            collect_consumed_bindings_from_expr(&match_expr.expr, bindings);
            for arm in &match_expr.arms {
                collect_consumed_bindings_from_expr(&arm.value, bindings);
            }
        }
        Expr::Integer(_) | Expr::Bool(_) | Expr::String(_) | Expr::ByteString(_) | Expr::Identifier(_) | Expr::ReadRef(_) => {}
        Expr::StdlibCall(call) => {
            let qualified = format!("std::{}::{}", call.namespace, call.name);
            match qualified.as_str() {
                "std::lifecycle::transfer" | "std::receipt::claim" | "std::lifecycle::settle" => {
                    if !call.args.is_empty()
                        && let Expr::Identifier(name) = &call.args[0]
                    {
                        bindings.insert(name.clone());
                    }
                }
                _ => {}
            }
        }
        Expr::RequireBlock(require_block) => {
            for expr in &require_block.expressions {
                collect_consumed_bindings_from_expr(expr, bindings);
            }
        }
        Expr::Preserve(_) => {}
        Expr::ReplaceRelation(relation) => {
            bindings.insert(relation.before.clone());
        }
    }
}

fn direct_call_name(call: &CallExpr) -> Option<&str> {
    match call.func.as_ref() {
        Expr::Identifier(name) => Some(name.as_str()),
        _ => None,
    }
}

fn is_direct_call(expr: &Expr, expected: &str) -> bool {
    matches!(expr, Expr::Call(call) if direct_call_name(call) == Some(expected))
}

fn binding_pattern_name(pattern: &BindingPattern) -> Option<&str> {
    match pattern {
        BindingPattern::Name(name) => Some(name.as_str()),
        BindingPattern::Tuple(_) | BindingPattern::Wildcard => None,
    }
}

fn mutable_reference_root_names(expr: &Expr) -> Vec<&str> {
    let mut roots = Vec::new();
    collect_mutable_reference_root_names(expr, &mut roots);
    roots
}

fn collect_mutable_reference_root_names<'a>(expr: &'a Expr, roots: &mut Vec<&'a str>) {
    match expr {
        Expr::Identifier(name) => push_unique_root(roots, name.as_str()),
        Expr::FieldAccess(field) => collect_mutable_reference_root_names(&field.expr, roots),
        Expr::Index(index) => collect_mutable_reference_root_names(&index.expr, roots),
        Expr::Cast(cast) => collect_mutable_reference_root_names(&cast.expr, roots),
        Expr::If(if_expr) => {
            collect_mutable_reference_root_names(&if_expr.then_branch, roots);
            collect_mutable_reference_root_names(&if_expr.else_branch, roots);
        }
        Expr::Match(match_expr) => {
            for arm in &match_expr.arms {
                collect_mutable_reference_root_names(&arm.value, roots);
            }
        }
        Expr::Block(stmts) => collect_mutable_reference_root_names_from_tail_stmts(stmts, roots),
        _ => {}
    }
}

fn collect_mutable_reference_root_names_from_tail_stmts<'a>(stmts: &'a [Stmt], roots: &mut Vec<&'a str>) {
    let Some(last) = stmts.last() else {
        return;
    };
    match last {
        Stmt::Expr(expr) | Stmt::Return(ReturnStmt { value: Some(expr), .. }) => collect_mutable_reference_root_names(expr, roots),
        Stmt::If(if_stmt) => {
            collect_mutable_reference_root_names_from_tail_stmts(&if_stmt.then_branch, roots);
            if let Some(else_branch) = &if_stmt.else_branch {
                collect_mutable_reference_root_names_from_tail_stmts(else_branch, roots);
            }
        }
        _ => {}
    }
}

fn push_unique_root<'a>(roots: &mut Vec<&'a str>, root: &'a str) {
    if !roots.contains(&root) {
        roots.push(root);
    }
}

fn identity_condition(identity: &IdentityPolicy) -> String {
    match identity {
        IdentityPolicy::None => "identity(none)".to_string(),
        IdentityPolicy::CkbTypeId => "identity(ckb_type_id)".to_string(),
        IdentityPolicy::Field(field) => format!("identity(field({field}))"),
        IdentityPolicy::ScriptArgs => "identity(script_args)".to_string(),
        IdentityPolicy::SingletonType => "identity(singleton_type)".to_string(),
    }
}

fn is_state_storage_type(ty: &Type) -> bool {
    matches!(ty, Type::U8 | Type::U16 | Type::U32 | Type::U64)
}

pub fn check(module: &Module) -> Result<()> {
    let mut checker = TypeChecker::new();
    checker.check_module(module)
}

pub fn diagnostics(module: &Module) -> Vec<CompileError> {
    let mut checker = TypeChecker::new();
    checker.check_module_diagnostics(module)
}

pub fn check_with_resolver(module: &Module, resolver: &ModuleResolver, current_module: &str) -> Result<()> {
    let mut checker = TypeChecker::with_resolver(resolver, current_module);
    checker.check_module(module)
}

pub fn diagnostics_with_resolver(module: &Module, resolver: &ModuleResolver, current_module: &str) -> Vec<CompileError> {
    let mut checker = TypeChecker::with_resolver(resolver, current_module);
    checker.check_module_diagnostics(module)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{lexer, parser, resolve::ModuleResolver};
    use camino::Utf8PathBuf;

    fn example_module(name: &str) -> Module {
        let path = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples").join(name);
        let source = std::fs::read_to_string(path).unwrap();
        let tokens = lexer::lex(&source).unwrap();
        parser::parse(&tokens).unwrap()
    }

    fn source_module(source: &str) -> Module {
        let tokens = lexer::lex(source).unwrap();
        parser::parse(&tokens).unwrap()
    }

    #[test]
    fn diagnostics_collect_independent_callable_errors() {
        let module = source_module(
            r#"
module multi_errors

action bad_one() -> u64 {
    verification
        return true
}

action bad_two() -> bool {
    verification
        return 1
}
"#,
        );
        let diagnostics = super::diagnostics(&module);
        assert_eq!(diagnostics.len(), 2);
        assert!(diagnostics.iter().any(|error| error.message.contains("expected U64, found Bool")));
        assert!(diagnostics.iter().any(|error| error.message.contains("expected Bool, found U64")));
    }

    #[test]
    fn checked_casts_reject_cell_identity_erasure() {
        let module = source_module(
            r#"
module checked_casts

resource Token has store, create, consume {
    amount: u64
}

action erase(token: Token) -> u64 {
    verification
        let erased = token as u64
        consume token
        return erased
}
"#,
        );
        let error = super::check(&module).expect_err("cell-backed cast must fail");
        assert!(error.message.contains("casts cannot erase Cell identity"), "unexpected error: {}", error.message);
    }

    #[test]
    fn checked_casts_accept_unsigned_numeric_narrowing_for_runtime_guarding() {
        let module = source_module(
            r#"
module checked_casts

fn narrow(value: u64) -> u8 {
    return value as u8
}
"#,
        );
        super::check(&module).expect("numeric narrowing is checked during lowering");
    }

    #[test]
    fn diagnostics_collect_independent_statement_errors_in_callable() {
        let module = source_module(
            r#"
module multi_errors

action bad() -> bool {
    verification
        let first: u64 = true
        let second: bool = 1
        return true
}
"#,
        );
        let diagnostics = super::diagnostics(&module);
        assert_eq!(diagnostics.len(), 2);
        assert!(diagnostics.iter().any(|error| error.message.contains("expected U64, found Bool")));
        assert!(diagnostics.iter().any(|error| error.message.contains("expected Bool, found U64")));
    }

    #[test]
    fn diagnostics_collect_nested_statement_errors() {
        let module = source_module(
            r#"
module multi_errors

action bad() -> bool {
    verification
        if true {
            let first: u64 = true
            let second: bool = 1
        }
        return true
}
"#,
        );
        let diagnostics = super::diagnostics(&module);
        assert_eq!(diagnostics.len(), 2);
        assert!(diagnostics.iter().any(|error| error.message.contains("expected U64, found Bool")));
        assert!(diagnostics.iter().any(|error| error.message.contains("expected Bool, found U64")));
    }

    #[test]
    fn imported_token_type_is_treated_as_linear() {
        let token = example_module("token.cell");
        let launch = example_module("launch.cell");

        let mut resolver = ModuleResolver::new();
        resolver.register_module(token).unwrap();
        resolver.register_module(launch.clone()).unwrap();

        let checker = TypeChecker::with_resolver(&resolver, launch.name.clone());
        assert!(checker.is_linear_type(&Type::Named("Token".to_string())));
    }

    #[test]
    fn launch_module_type_checks_with_registered_imports() {
        let token = example_module("token.cell");
        let amm = example_module("amm_pool.cell");
        let launch = example_module("launch.cell");

        let mut resolver = ModuleResolver::new();
        resolver.register_module(token).unwrap();
        resolver.register_module(amm).unwrap();
        resolver.register_module(launch.clone()).unwrap();

        check_with_resolver(&launch, &resolver, &launch.name).unwrap();
    }

    #[test]
    fn imported_type_ids_must_not_collide_in_visible_module_scope() {
        let left = source_module(
            r#"
module cellscript::left

#[type_id("cellscript::asset::Token:v1")]
resource TokenA has store {
    amount: u64
}
"#,
        );
        let right = source_module(
            r#"
module cellscript::right

#[type_id("cellscript::asset::Token:v1")]
resource TokenB has store {
    amount: u64
}
"#,
        );
        let app = source_module(
            r#"
module app

use cellscript::left::TokenA
use cellscript::right::TokenB

action main(a: TokenA) -> u64 {
    verification
        return a.amount
}
"#,
        );

        let mut resolver = ModuleResolver::new();
        resolver.register_module(left).unwrap();
        resolver.register_module(right).unwrap();
        resolver.register_module(app.clone()).unwrap();

        let err = check_with_resolver(&app, &resolver, &app.name).unwrap_err();

        assert!(err.message.contains("duplicate type_id 'cellscript::asset::Token:v1'"), "unexpected error: {}", err.message);
    }

    #[test]
    fn imported_linear_argument_is_marked_consumed_after_call() {
        let token = example_module("token.cell");
        let amm = example_module("amm_pool.cell");
        let launch = example_module("launch.cell");

        let mut resolver = ModuleResolver::new();
        resolver.register_module(token).unwrap();
        resolver.register_module(amm).unwrap();
        resolver.register_module(launch.clone()).unwrap();

        let action = launch
            .items
            .iter()
            .find_map(|item| match item {
                Item::Action(action) if action.name == "launch_token" => Some(action.clone()),
                _ => None,
            })
            .unwrap();

        let mut checker = TypeChecker::with_resolver(&resolver, launch.name.clone());
        let mut env = checker.env.child();
        for param in &action.params {
            let is_linear = checker.is_linear_type(&param.ty);
            env.insert(param.name.clone(), param.ty.clone(), is_linear, param.is_mut);
        }
        checker.bind_action_outputs(&mut env, &action).unwrap();
        checker.current_callable = Some(CallableKind::Action);

        for stmt in &action.body {
            checker.check_stmt(&mut env, stmt).unwrap();
            if let Stmt::Let(let_stmt) = stmt
                && matches!(&let_stmt.pattern, BindingPattern::Tuple(_))
            {
                break;
            }
        }

        assert_eq!(env.linear_states.get("pool_paired_token"), Some(&LinearState::Consumed));
    }

    #[test]
    fn preserve_rejects_mismatched_field_types() {
        let module = source_module(
            r#"
module test

resource A has store, replace, relock, consume, burn {
    amount: u64
}

resource B has store, replace, relock, consume, burn {
    amount: bool
}

action bad_preserve(a: A) -> b: B {
    verification
        consume a
        preserve b from a { amount }
        create b = B { amount: true }
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(err.message.contains("preserve field 'amount' type mismatch"), "unexpected error: {}", err.message);
    }

    #[test]
    fn require_rejects_nested_cell_operation() {
        let module = source_module(
            r#"
module test

resource Coin has store, replace, relock, consume, burn {
    amount: u64
}

action hidden_consume(coin: Coin) {
    verification
        require (consume coin) == 0
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(err.message.contains("require condition contains cell/runtime operation"), "unexpected error: {}", err.message);
    }

    #[test]
    fn require_block_rejects_lifecycle_stdlib_call() {
        let module = source_module(
            r#"
module test

receipt Voucher has destroy {
    amount: u64
}

action hidden_claim(voucher: Voucher) {
    verification
        require {
            std::receipt::claim(voucher, voucher, voucher.amount)
        }
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(err.message.contains("require block contains verifier-boundary syntax"), "unexpected error: {}", err.message);
    }

    #[test]
    fn require_block_rejects_assignment_expression() {
        let module = source_module(
            r#"
module test

action hidden_mutation(flag: bool) {
    verification
        let mut ok = flag
        require {
            ok = false
        }
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(err.message.contains("require block contains assignment"), "unexpected error: {}", err.message);
    }

    #[test]
    fn numeric_equality_requires_exact_non_literal_types() {
        let module = source_module(
            r#"
module test

action compare(left: u8, right: u128) -> bool {
    verification
        return left == right
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(err.message.contains("comparison requires matching types"), "unexpected error: {}", err.message);
    }

    #[test]
    fn typed_integer_literals_keep_declared_numeric_widths() {
        let module = source_module(
            r#"
module test

const SMALL: u8 = 2

action literal_widths(flag: bool) -> u8 {
    verification
        let left: u8 = 1
        let right: u8 = if flag { SMALL } else { 3 }
        return left + right
}
"#,
        );

        check(&module).unwrap();
    }

    #[test]
    fn explicit_return_integer_literals_use_declared_return_widths() {
        let module = source_module(
            r#"
module test

fn as_u8() -> u8 {
    return 5
}

fn as_u32() -> u32 {
    return 5
}

fn as_i32() -> i32 {
    return 5
}

fn as_u128() -> u128 {
    return 5
}
"#,
        );

        check(&module).unwrap();
    }

    #[test]
    fn i32_arithmetic_accepts_matching_i32_values() {
        let module = source_module(
            r#"
module test

fn add(left: i32, right: i32) -> i32 {
    return left + right
}
"#,
        );

        check(&module).unwrap();
    }

    #[test]
    fn mixed_i32_u32_arithmetic_is_rejected() {
        let module = source_module(
            r#"
module test

fn add(left: i32, right: u32) -> i32 {
    return left + right
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(err.message.contains("arithmetic operations require matching numeric types"), "unexpected error: {}", err.message);
    }

    #[test]
    fn unsigned_arithmetic_widens_to_declared_result_type() {
        let module = source_module(
            r#"
module test

fn add(left: u8, right: u16) -> u16 {
    return left + right
}
"#,
        );

        check(&module).unwrap();
    }

    #[test]
    fn vec_push_integer_literal_uses_item_width() {
        let module = source_module(
            r#"
module test

action collect() -> u8 {
    verification
        let mut values: Vec<u8> = []
        values.push(5)
        return values.first()
}
"#,
        );

        check(&module).unwrap();
    }

    #[test]
    fn struct_field_integer_literal_uses_field_width() {
        let module = source_module(
            r#"
module test

struct Narrow {
    amount: u8,
}

action make() -> Narrow {
    verification
        return Narrow { amount: 5 }
}
"#,
        );

        check(&module).unwrap();
    }

    #[test]
    fn unsigned_ordering_comparison_accepts_widening() {
        let module = source_module(
            r#"
module test

action compare(left: u8, right: u16) -> bool {
    verification
        return left < right
}
"#,
        );

        check(&module).unwrap();
    }

    #[test]
    fn add_assign_integer_literal_uses_target_width() {
        let module = source_module(
            r#"
module test

action increment() -> u8 {
    verification
        let mut value: u8 = 1
        value += 2
        return value
}
"#,
        );

        check(&module).unwrap();
    }

    #[test]
    fn typed_integer_literals_must_fit_expected_numeric_type() {
        let module = source_module(
            r#"
module test

const TOO_BIG: u8 = 256

action bad() -> u8 {
    verification
        return TOO_BIG
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(err.message.contains("integer literal 256 does not fit expected type u8"), "unexpected error: {}", err.message);
    }

    #[test]
    fn byte_string_literal_infers_exact_fixed_array_length() {
        let module = source_module(
            r#"
module test

action symbol() -> [u8; 4]
{
    verification
        return b"TEST"
}
"#,
        );

        check(&module).unwrap();
    }

    #[test]
    fn match_wildcard_arm_must_be_last() {
        let module = source_module(
            r#"
module test

enum Flag {
    Off,
    On,
}

action bad(flag: Flag) -> u64
{
    verification
        return match flag {
            _ => { 1 },
            Flag::Off => { 2 },
        }
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(
            err.message.contains("wildcard pattern '_' or another irrefutable pattern must be the last match arm"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn stdlib_claim_rejects_non_receipt_input() {
        let module = source_module(
            r#"
module test

resource Coin has store, replace, relock, consume, burn {
    amount: u64
}

action bad_claim(coin: Coin, to: Address) -> next_coin: Coin {
    verification
        std::receipt::claim(coin, next_coin, to) { amount }
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(err.message.contains("std::receipt::claim requires a receipt cell input"), "unexpected error: {}", err.message);
    }

    #[test]
    fn stdlib_claim_rejects_declared_output_type_mismatch() {
        let module = source_module(
            r#"
module test

resource Coin has store, replace, relock, consume, burn {
    amount: u64
}

resource Badge has store, replace, relock, consume, burn {
    amount: u64
}

receipt Voucher -> Coin has destroy {
    amount: u64
}

action bad_claim(voucher: Voucher, to: Address) -> badge: Badge {
    verification
        std::receipt::claim(voucher, badge, to) { amount }
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(err.message.contains("std::receipt::claim output type mismatch"), "unexpected error: {}", err.message);
    }

    #[test]
    fn stdlib_claim_rejects_extra_arguments() {
        let module = source_module(
            r#"
module test

resource Coin has store, replace, relock, consume, burn {
    amount: u64
}

receipt Voucher has destroy {
    amount: u64
}

action bad_claim(voucher: Voucher) -> coin: Coin {
    verification
        std::receipt::claim(voucher, coin, coin, coin)
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(err.message.contains("std::receipt::claim expects 3 arguments"), "unexpected error: {}", err.message);
    }

    #[test]
    fn stdlib_claim_output_requires_declared_claim_output_type() {
        let module = source_module(
            r#"
module test

resource Coin has store, replace, relock, consume, burn {
    amount: u64
}

receipt Voucher has destroy {
    amount: u64
    owner: Address
}

action bad_claim(voucher: Voucher) -> coin: Coin {
    verification
        std::receipt::claim(voucher, coin, voucher.owner) { amount }
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(
            err.message.contains("std::receipt::claim with an output requires receipt 'Voucher' to declare a claim output type"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn stdlib_claim_requires_explicit_output_and_lock_arguments() {
        let module = source_module(
            r#"
module test

resource Coin has store, replace, relock, consume, burn {
    amount: u64
}

receipt Voucher -> Coin has destroy {
    amount: u64
}

action bad_claim(voucher: Voucher) -> coin: Coin {
    verification
        std::receipt::claim(voucher, coin) { amount }
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(err.message.contains("std::receipt::claim expects 3 arguments"), "unexpected error: {}", err.message);
    }

    #[test]
    fn stdlib_settle_requires_explicit_output_and_lock_arguments() {
        let module = source_module(
            r#"
module test

resource Coin has store, replace, relock, consume, burn {
    amount: u64
}

action bad_settle(coin: Coin) -> next_coin: Coin {
    verification
        std::lifecycle::settle(coin, next_coin) { amount }
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(err.message.contains("std::lifecycle::settle expects 3 arguments"), "unexpected error: {}", err.message);
    }

    #[test]
    fn stdlib_transfer_output_requires_complete_field_coverage() {
        let module = source_module(
            r#"
module test

resource Coin has store, replace, relock, consume, burn {
    amount: u64
    owner: Address
}

action bad_transfer(coin: Coin, to: Address) -> next_coin: Coin {
    verification
        std::lifecycle::transfer(coin, next_coin, to) { amount }
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(
            err.message.contains("std::lifecycle::transfer output construction must cover every 'Coin' field; missing owner"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn stdlib_claim_output_requires_complete_field_coverage() {
        let module = source_module(
            r#"
module test

resource Coin has store, replace, relock, consume, burn {
    amount: u64
    owner: Address
}

receipt Voucher -> Coin has destroy {
    amount: u64
    owner: Address
}

action bad_claim(voucher: Voucher) -> coin: Coin {
    verification
        std::receipt::claim(voucher, coin, voucher.owner) { amount }
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(
            err.message.contains("std::receipt::claim output construction must cover every 'Coin' field; missing owner"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn stdlib_transfer_rejects_extra_arguments() {
        let module = source_module(
            r#"
module test

resource Coin has store, replace, relock, consume, burn {
    amount: u64
}

action bad_transfer(coin: Coin, to: Address) -> next_coin: Coin {
    verification
        std::lifecycle::transfer(coin, next_coin, to, to) { amount }
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(err.message.contains("std::lifecycle::transfer expects 3 arguments"), "unexpected error: {}", err.message);
    }

    #[test]
    fn typed_transaction_views_are_source_specific_read_only_handles() {
        let module = source_module(
            r#"
module test

resource Token has store {
    amount: u64
}

action inspect() -> u64 {
    verification
        let input = ckb::input<Token>(0)
        let output = ckb::output<Token>(0)
        let dep = ckb::cell_dep(0)
        let header = ckb::header_dep(0)
        let witness_args = witness::args(0)
        let out_point = input.out_point
        let lock = input.lock
        require lock.args_empty || lock.hash_type <= 4
        require dep.data_hash == dep.data_hash
        return input.capacity + input.occupied_capacity + input.unoccupied_capacity + ckb::since_to_raw(input.since) + output.output_index + dep.data_size + witness_args.size + out_point.index + ckb::epoch_number_to_u64(header.epoch_number) + ckb::block_number_to_u64(header.epoch_start_block_number) + ckb::epoch_length_to_u64(header.epoch_length)
}
"#,
        );

        check(&module).unwrap();
    }

    #[test]
    fn script_view_hash_domains_are_not_interchangeable() {
        let module = source_module(
            r#"
module test

resource Token has store { amount: u64 }

action inspect() -> bool {
    verification
        let input = ckb::input<Token>(0)
        let script = input.lock
        let complete: ScriptHash = script.hash
        let code: Hash = script.code_hash
        let args: Hash = script.args_hash
        return complete.0 == code.0 || code == args
}
"#,
        );
        check(&module).unwrap();

        let confused = source_module(
            r#"
module test

resource Token has store { amount: u64 }

action inspect() -> ScriptHash {
    verification
        return ckb::input<Token>(0).lock.code_hash
}
"#,
        );
        let err = check(&confused).unwrap_err();
        assert!(err.message.contains("return type mismatch") && err.message.contains("Hash"), "unexpected error: {}", err.message);
    }

    #[test]
    fn ckb_temporal_domains_require_explicit_raw_conversion() {
        let valid = source_module(
            r#"
module test

resource Token has store { amount: u64 }

action inspect() -> bool {
    verification
        let header = ckb::header_dep(0)
        let absolute = ckb::since_absolute_epoch(42, 3, 10)
        let another_absolute = ckb::since_absolute_epoch(43, 0, 10)
        let encoded = ckb::input<Token>(0).since
        require absolute < another_absolute
        return ckb::epoch_number_to_u64(header.epoch_number) == 42
            && ckb::block_number_to_u64(header.epoch_start_block_number) == 97
            && ckb::epoch_length_to_u64(header.epoch_length) == 10
            && ckb::since_to_raw(encoded) >= 0
            && ckb::since_epoch_absolute(1, 0, 1) >= 0
            && ckb::input_since_at(source::input(0)) >= 0
}
"#,
        );
        check(&valid).unwrap();

        for (expression, expected) in [
            ("ckb::since_absolute_epoch(1, 0, 1) == ckb::since_relative_epoch(1, 0, 1)", "comparison requires matching types"),
            ("ckb::header_dep(0).epoch_number == ckb::header_dep(0).epoch_start_block_number", "comparison requires matching types"),
            ("ckb::input<Token>(0).since == 0", "comparison requires matching types"),
        ] {
            let invalid = source_module(&format!(
                "module test\nresource Token has store {{ amount: u64 }}\naction inspect() -> bool {{ verification return {expression} }}"
            ));
            let err = check(&invalid).unwrap_err();
            assert!(err.message.contains(expected), "unexpected error for {expression}: {}", err.message);
        }
    }

    #[test]
    fn typed_transaction_view_requires_a_cell_backed_type_argument() {
        let module = source_module(
            r#"
module test

action inspect() -> u64 {
    verification
        let input = ckb::input<u64>(0)
        return input.capacity
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(err.message.contains("type argument must be a named cell-backed type"), "unexpected error: {}", err.message);
    }

    #[test]
    fn typed_transaction_view_rejects_source_mismatch() {
        let module = source_module(
            r#"
module test

resource Token has store {
    amount: u64
}

action inspect() -> u64 {
    verification
        return dao::accumulated_rate(ckb::input<Token>(0))
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(err.message.contains("HeaderDep"), "unexpected error: {}", err.message);
    }

    #[test]
    fn typed_transaction_view_cannot_enter_linear_lifecycle_operations() {
        let module = source_module(
            r#"
module test

resource Token has store {
    amount: u64
}

action inspect() -> u64 {
    verification
        let input = ckb::input<Token>(0)
        consume input
        return 0
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(err.message.contains("consume requires a cell-backed linear value"), "unexpected error: {}", err.message);
    }

    #[test]
    fn bounded_cell_dep_scan_requires_a_small_literal_bound() {
        for (bound, expected) in [("0", "must be in 1..=64"), ("65", "must be in 1..=64"), ("max_deps", "must be an integer literal")]
        {
            let module = source_module(&format!(
                r#"
module test

action inspect(witness expected_hash: Hash, witness max_deps: u64) -> bool {{
    verification
        ckb::require_bounded_cell_dep_data_hash({bound}, expected_hash)
        true
}}
"#
            ));
            let err = check(&module).unwrap_err();
            assert!(err.message.contains(expected), "unexpected error for bound {bound}: {}", err.message);
        }
    }

    #[test]
    fn bounded_sha256d_merkle_requires_a_small_literal_depth() {
        for (depth, expected) in [("17", "must be in 0..=16"), ("runtime_depth", "must be an integer literal")] {
            let module = source_module(&format!(
                r#"
module test

action inspect(
    witness leaf: Hash,
    witness siblings: [Hash; 16],
    witness runtime_depth: u64,
    witness leaf_index: u64,
    witness expected_root: Hash,
) -> bool {{
    verification
        ckb::require_sha256d_merkle_root(leaf, siblings, {depth}, leaf_index, expected_root)
        true
}}
"#
            ));
            let err = check(&module).unwrap_err();
            assert!(err.message.contains(expected), "unexpected error for depth {depth}: {}", err.message);
        }
    }

    #[test]
    fn bip340_explicit_cell_dep_requires_a_small_literal_index() {
        for (dep_index, expected) in [("64", "must be in 0..=63"), ("runtime_index", "must be an integer literal")] {
            let module = source_module(&format!(
                r#"
module test

action inspect(
    witness runtime_index: u64,
    witness message_hash: Hash,
    witness xonly_pubkey: [u8; 32],
    witness signature: [u8; 64],
) -> bool {{
    verification
        verifier::btc::bip340::require_signature_from_cell_dep(
            {dep_index},
            message_hash,
            xonly_pubkey,
            signature,
        )
        true
}}
"#
            ));
            let err = check(&module).unwrap_err();
            assert!(err.message.contains(expected), "unexpected error for dep index {dep_index}: {}", err.message);
        }
    }

    #[test]
    fn bounded_quantifiers_type_check_finite_cell_sources() {
        let module = source_module(
            r#"
module test

resource Token {
    amount: u64
}

invariant positive_outputs {
    trigger: type_group
    scope: group
    reads: group_outputs<Token>.amount
    forall output token in group_outputs<Token> {
        require token.amount > 0
    }
}

invariant one_claim {
    trigger: explicit_entry
    scope: transaction
    reads: outputs<Token>.amount
    count(outputs<Token> where amount == 7) == 1
}
"#,
        );

        check(&module).unwrap();
    }

    #[test]
    fn bounded_quantifier_requires_declared_read_coverage() {
        let module = source_module(
            r#"
module test

resource Token {
    amount: u64
}

invariant bad {
    trigger: type_group
    scope: group
    reads: group_inputs<Token>.amount
    forall output token in group_outputs<Token> {
        require token.amount > 0
    }
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(
            err.message.contains("must be declared") && err.message.contains("reads metadata"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn bounded_quantifier_predicate_rejects_lifecycle_operations() {
        let module = source_module(
            r#"
module test

resource Token has consume {
    amount: u64
}

invariant bad {
    trigger: type_group
    scope: group
    reads: group_outputs<Token>.amount
    forall output token in group_outputs<Token> {
        require consume token > 0
    }
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(err.message.contains("contains cell/runtime operation"), "unexpected error: {}", err.message);
    }

    #[test]
    fn bounded_quantifier_predicate_rejects_non_pure_helper_effect() {
        let module = source_module(
            r#"
module test

resource Token {
    amount: u64
}

#[effect(ReadOnly)]
fn positive(amount: u64) -> bool {
    return amount > 0
}

invariant bad {
    trigger: type_group
    scope: group
    reads: group_outputs<Token>.amount
    forall output token in group_outputs<Token> {
        require positive(token.amount)
    }
}
"#,
        );

        let err = check(&module).unwrap_err();
        assert!(err.message.contains("only transitively Pure helpers are allowed"), "unexpected error: {}", err.message);
    }

    #[test]
    fn bounded_lifecycle_bodies_only_admit_outer_numeric_add_assign_accumulators() {
        let accepted = source_module(
            r#"
module test

resource Token has store, consume { amount: u64 }

action batch(input inputs: BoundedCellSet<Token, 4>) -> u64 {
    verification
        let mut total: u64 = 0
        consume_each token in inputs {
            require token.amount <= 100
            total += token.amount
        }
        require total <= 400
        return 0
}
"#,
        );
        check(&accepted).unwrap();

        let rejected = source_module(
            r#"
module test

resource Token has store, consume { amount: u64 }

action batch(input inputs: BoundedCellSet<Token, 4>) -> u64 {
    verification
        let mut total: u64 = 0
        consume_each token in inputs {
            total = token.amount
        }
        return 0
}
"#,
        );
        let err = check(&rejected).unwrap_err();
        assert!(
            err.message.contains("only permits '+=' updates to mutable outer numeric accumulators"),
            "unexpected error: {}",
            err.message
        );

        let impure_rhs = source_module(
            r#"
module test

resource Token has store, consume { amount: u64 }

#[effect(ReadOnly)]
fn observed_amount(amount: u64) -> u64 {
    return amount
}

action batch(input inputs: BoundedCellSet<Token, 4>) -> u64 {
    verification
        let mut total: u64 = 0
        consume_each token in inputs {
            total += observed_amount(token.amount)
        }
        return 0
}
"#,
        );
        let err = check(&impure_rhs).unwrap_err();
        assert!(err.message.contains("only transitively Pure helpers are allowed"), "unexpected error: {}", err.message);
    }
}
