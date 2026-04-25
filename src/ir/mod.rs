use crate::ast::*;
use crate::error::{CompileError, Result, Span};
use crate::resolve::{FunctionDef, ModuleResolver, TypeDef};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct IrModule {
    pub name: String,
    pub items: Vec<IrItem>,
    pub external_type_defs: Vec<IrTypeDef>,
    pub external_callable_abis: Vec<IrCallableAbi>,
    pub enum_fixed_sizes: HashMap<String, usize>,
}

#[derive(Debug, Clone)]
pub struct IrCallableAbi {
    pub name: String,
    pub params: Vec<IrParam>,
    pub type_hash_param_indices: BTreeSet<usize>,
}

#[derive(Debug, Clone)]
pub enum IrItem {
    TypeDef(IrTypeDef),
    Action(IrAction),
    PureFn(IrPureFn),
    Lock(IrLock),
}

#[derive(Debug, Clone)]
pub struct IrTypeDef {
    pub name: String,
    pub type_id: Option<String>,
    pub kind: IrTypeKind,
    pub fields: Vec<IrField>,
    pub capabilities: Vec<Capability>,
    pub claim_output: Option<IrType>,
    pub lifecycle_states: Option<Vec<String>>,
    pub lifecycle_rules: Vec<IrLifecycleRule>,
}

#[derive(Debug, Clone)]
pub struct IrLifecycleRule {
    pub from: String,
    pub to: String,
    pub from_index: usize,
    pub to_index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrTypeKind {
    Resource,
    Shared,
    Receipt,
    Struct,
}

#[derive(Debug, Clone)]
pub struct IrField {
    pub name: String,
    pub ty: IrType,
    pub offset: usize,
    pub fixed_size: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IrType {
    U8,
    U16,
    U32,
    U64,
    U128,
    Bool,
    Unit,
    Address,
    Hash,
    Array(Box<IrType>, usize),
    Tuple(Vec<IrType>),
    Named(String),
    Ref(Box<IrType>),
    MutRef(Box<IrType>),
}

/// IR Action
#[derive(Debug, Clone)]
pub struct IrAction {
    pub name: String,
    pub params: Vec<IrParam>,
    pub return_type: Option<IrType>,
    pub body: IrBody,
    pub effect_class: EffectClass,
    pub scheduler_hints: SchedulerHints,
}

/// IR pure helper function
#[derive(Debug, Clone)]
pub struct IrPureFn {
    pub name: String,
    pub params: Vec<IrParam>,
    pub return_type: Option<IrType>,
    pub body: IrBody,
}

/// IR Lock
#[derive(Debug, Clone)]
pub struct IrLock {
    pub name: String,
    pub params: Vec<IrParam>,
    pub body: IrBody,
}

#[derive(Debug, Clone)]
pub struct IrParam {
    pub name: String,
    pub ty: IrType,
    pub is_mut: bool,
    pub is_ref: bool,
    pub is_read_ref: bool,
    pub binding: IrVar,
}

#[derive(Debug, Clone)]
pub struct IrBody {
    pub consume_set: Vec<CellPattern>,
    pub read_refs: Vec<CellPattern>,
    pub create_set: Vec<CreatePattern>,
    pub mutate_set: Vec<MutatePattern>,
    pub write_intents: Vec<WriteIntent>,
    pub blocks: Vec<IrBlock>,
}

#[derive(Debug, Clone)]
pub struct CellPattern {
    pub operation: String,
    pub type_hash: Option<[u8; 32]>,
    pub binding: String,
    pub fields: Vec<(String, IrOperand)>,
}

#[derive(Debug, Clone)]
pub struct CreatePattern {
    pub operation: String,
    pub ty: String,
    pub binding: String,
    pub fields: Vec<(String, IrOperand)>,
    pub lock: Option<IrOperand>,
}

#[derive(Debug, Clone)]
pub struct MutatePattern {
    pub operation: String,
    pub ty: String,
    pub binding: String,
    pub fields: Vec<String>,
    pub preserved_fields: Vec<String>,
    pub transitions: Vec<MutateFieldTransition>,
    pub input_index: usize,
    pub output_index: usize,
    pub preserve_type_hash: bool,
    pub preserve_lock_hash: bool,
}

#[derive(Debug, Clone)]
pub struct WriteIntent {
    pub operation: String,
    pub ty: String,
    pub binding: String,
    pub source: WriteIntentSource,
    pub index: usize,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteIntentSource {
    Output,
    ReplacementOutput,
}

#[derive(Debug, Clone)]
pub struct MutateFieldTransition {
    pub field: String,
    pub op: MutateTransitionOp,
    pub operand: IrOperand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutateTransitionOp {
    Set,
    Add,
    Sub,
    Append,
}

#[derive(Debug, Clone)]
pub struct IrBlock {
    pub id: BlockId,
    pub instructions: Vec<IrInstruction>,
    pub terminator: IrTerminator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockId(pub usize);

#[derive(Debug, Clone)]
pub enum IrInstruction {
    LoadConst { dest: IrVar, value: IrConst },
    LoadVar { dest: IrVar, name: String },
    StoreVar { name: String, src: IrOperand },
    Binary { dest: IrVar, op: BinaryOp, left: IrOperand, right: IrOperand },
    Unary { dest: IrVar, op: UnaryOp, operand: IrOperand },
    FieldAccess { dest: IrVar, obj: IrOperand, field: String },
    Index { dest: IrVar, arr: IrOperand, idx: IrOperand },
    Length { dest: IrVar, operand: IrOperand },
    TypeHash { dest: IrVar, operand: IrOperand },
    CollectionNew { dest: IrVar, ty: String, capacity: Option<IrOperand> },
    CollectionPush { collection: IrOperand, value: IrOperand },
    CollectionExtend { collection: IrOperand, slice: IrOperand },
    CollectionClear { collection: IrOperand },
    CollectionContains { dest: IrVar, collection: IrOperand, value: IrOperand },
    CollectionRemove { dest: IrVar, collection: IrOperand, index: IrOperand },
    CollectionInsert { collection: IrOperand, index: IrOperand, value: IrOperand },
    CollectionPop { dest: IrVar, collection: IrOperand },
    Call { dest: Option<IrVar>, func: String, args: Vec<IrOperand> },
    ReadRef { dest: IrVar, ty: String },
    Move { dest: IrVar, src: IrOperand },
    Tuple { dest: IrVar, fields: Vec<IrOperand> },
    Consume { operand: IrOperand },
    Create { dest: IrVar, pattern: CreatePattern },
    Transfer { dest: IrVar, operand: IrOperand, to: IrOperand },
    Destroy { operand: IrOperand },
    Claim { dest: IrVar, receipt: IrOperand },
    Settle { dest: IrVar, operand: IrOperand },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IrVar {
    pub id: usize,
    pub name: String,
    pub ty: IrType,
}

#[derive(Debug, Clone)]
pub enum IrOperand {
    Var(IrVar),
    Const(IrConst),
}

#[derive(Debug, Clone)]
pub enum IrConst {
    Unit,
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    Bool(bool),
    Address([u8; 32]),
    Hash([u8; 32]),
    Array(Vec<IrConst>),
}

#[derive(Debug, Clone)]
pub enum IrTerminator {
    Return(Option<IrOperand>),
    Jump(BlockId),
    Branch { cond: IrOperand, then_block: BlockId, else_block: BlockId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectClass {
    Pure,
    ReadOnly,
    Mutating,
    Creating,
    Destroying,
}

#[derive(Debug, Clone)]
pub struct SchedulerHints {
    pub parallelizable: bool,
    pub touches_shared: Vec<[u8; 32]>,
    pub estimated_cycles: u64,
}

impl Default for SchedulerHints {
    fn default() -> Self {
        Self { parallelizable: true, touches_shared: Vec::new(), estimated_cycles: 1000 }
    }
}

#[derive(Default)]
struct EffectFootprint {
    has_read_ref: bool,
    has_consume: bool,
    has_create: bool,
}

pub struct IrGenerator {
    module: IrModule,
    var_counter: usize,
    block_counter: usize,
    aggregate_fields: HashMap<usize, HashMap<String, IrVar>>,
    schema_field_roots: HashMap<usize, (usize, String)>,
    aggregate_elements: HashMap<usize, Vec<IrVar>>,
    mutated_fields: HashMap<usize, BTreeSet<String>>,
    mutated_field_transitions: HashMap<usize, BTreeMap<String, MutateFieldTransition>>,
    transition_param_ids: HashSet<usize>,
    transition_coverable_value_ids: HashSet<usize>,
    type_fields: HashMap<String, HashMap<String, IrType>>,
    type_kinds: HashMap<String, IrTypeKind>,
    receipt_claim_outputs: HashMap<String, Option<IrType>>,
    enum_variants: HashMap<String, HashMap<String, u64>>,
    constants: HashMap<String, Expr>,
    function_effects: HashMap<String, EffectClass>,
    external_function_effects: HashMap<String, EffectClass>,
    function_return_types: HashMap<String, Option<IrType>>,
    external_function_return_types: HashMap<String, Option<IrType>>,
    errors: Vec<CompileError>,
}

struct LoweredExpr {
    operand: IrOperand,
    current: Option<BlockId>,
}

impl IrGenerator {
    pub fn new(module_name: String) -> Self {
        Self {
            module: IrModule {
                name: module_name,
                items: Vec::new(),
                external_type_defs: Vec::new(),
                external_callable_abis: Vec::new(),
                enum_fixed_sizes: HashMap::new(),
            },
            var_counter: 0,
            block_counter: 0,
            aggregate_fields: HashMap::new(),
            schema_field_roots: HashMap::new(),
            aggregate_elements: HashMap::new(),
            mutated_fields: HashMap::new(),
            mutated_field_transitions: HashMap::new(),
            transition_param_ids: HashSet::new(),
            transition_coverable_value_ids: HashSet::new(),
            type_fields: HashMap::new(),
            type_kinds: HashMap::new(),
            receipt_claim_outputs: HashMap::new(),
            enum_variants: HashMap::new(),
            constants: HashMap::new(),
            function_effects: HashMap::new(),
            external_function_effects: HashMap::new(),
            function_return_types: HashMap::new(),
            external_function_return_types: HashMap::new(),
            errors: Vec::new(),
        }
    }

    pub fn with_type_fields(module_name: String, type_fields: HashMap<String, HashMap<String, IrType>>) -> Self {
        let mut generator = Self::new(module_name);
        generator.type_fields = type_fields;
        generator
    }

    pub fn with_import_context(
        module_name: String,
        type_fields: HashMap<String, HashMap<String, IrType>>,
        type_kinds: HashMap<String, IrTypeKind>,
        receipt_claim_outputs: HashMap<String, Option<IrType>>,
        external_function_effects: HashMap<String, EffectClass>,
        external_function_return_types: HashMap<String, Option<IrType>>,
    ) -> Self {
        let mut generator = Self::with_type_fields(module_name, type_fields);
        generator.type_kinds.extend(type_kinds);
        generator.receipt_claim_outputs.extend(receipt_claim_outputs);
        generator.external_function_effects = external_function_effects;
        generator.external_function_return_types = external_function_return_types;
        generator
    }

    pub fn generate(mut self, ast: &Module) -> Result<IrModule> {
        for item in &ast.items {
            if let Item::Const(c) = item {
                self.constants.insert(c.name.clone(), c.value.clone());
            }
            match item {
                Item::Resource(r) => {
                    self.type_kinds.insert(r.name.clone(), IrTypeKind::Resource);
                    self.type_fields.insert(
                        r.name.clone(),
                        r.fields.iter().map(|field| (field.name.clone(), Self::convert_type(&field.ty))).collect(),
                    );
                }
                Item::Shared(s) => {
                    self.type_kinds.insert(s.name.clone(), IrTypeKind::Shared);
                    self.type_fields.insert(
                        s.name.clone(),
                        s.fields.iter().map(|field| (field.name.clone(), Self::convert_type(&field.ty))).collect(),
                    );
                }
                Item::Receipt(r) => {
                    self.type_kinds.insert(r.name.clone(), IrTypeKind::Receipt);
                    self.receipt_claim_outputs.insert(r.name.clone(), r.claim_output.as_ref().map(Self::convert_type));
                    self.type_fields.insert(
                        r.name.clone(),
                        r.fields.iter().map(|field| (field.name.clone(), Self::convert_type(&field.ty))).collect(),
                    );
                }
                Item::Struct(s) => {
                    self.type_kinds.insert(s.name.clone(), IrTypeKind::Struct);
                    self.type_fields.insert(
                        s.name.clone(),
                        s.fields.iter().map(|field| (field.name.clone(), Self::convert_type(&field.ty))).collect(),
                    );
                }
                Item::Enum(e) => {
                    self.enum_variants.insert(
                        e.name.clone(),
                        e.variants.iter().enumerate().map(|(index, variant)| (variant.name.clone(), index as u64)).collect(),
                    );
                    if e.variants.iter().all(|variant| variant.fields.is_empty()) && e.variants.len() <= u8::MAX as usize + 1 {
                        self.module.enum_fixed_sizes.insert(e.name.clone(), 1);
                    }
                }
                Item::Action(action) => {
                    let return_type = action.return_type.as_ref().map(ast_type_to_ir);
                    self.function_return_types.insert(action.name.clone(), return_type.clone());
                    self.function_return_types.insert(format!("{}::{}", self.module.name, action.name), return_type);
                }
                Item::Function(function) => {
                    let return_type = function.return_type.as_ref().map(ast_type_to_ir);
                    self.function_return_types.insert(function.name.clone(), return_type.clone());
                    self.function_return_types.insert(format!("{}::{}", self.module.name, function.name), return_type);
                }
                Item::Lock(lock) => {
                    self.function_return_types.insert(lock.name.clone(), Some(IrType::Bool));
                    self.function_return_types.insert(format!("{}::{}", self.module.name, lock.name), Some(IrType::Bool));
                }
                _ => {}
            }
        }

        self.infer_module_function_effects(&ast.items);

        for item in &ast.items {
            match item {
                Item::Resource(r) => {
                    let ir_item = IrItem::TypeDef(self.gen_resource(r));
                    self.module.items.push(ir_item);
                }
                Item::Shared(s) => {
                    let ir_item = IrItem::TypeDef(self.gen_shared(s));
                    self.module.items.push(ir_item);
                }
                Item::Receipt(r) => {
                    let ir_item = IrItem::TypeDef(self.gen_receipt(r));
                    self.module.items.push(ir_item);
                }
                Item::Struct(s) => {
                    let ir_item = IrItem::TypeDef(self.gen_struct(s));
                    self.module.items.push(ir_item);
                }
                Item::Const(_) | Item::Enum(_) => {}
                Item::Action(a) => {
                    let ir_item = IrItem::Action(self.gen_action(a));
                    self.module.items.push(ir_item);
                }
                Item::Function(f) => {
                    let inferred_effect = self.analyze_body_effect_class(&f.body);
                    if inferred_effect != EffectClass::Pure {
                        self.record_error(format!("fn '{}' must be pure; inferred effect is {:?}", f.name, inferred_effect), f.span);
                    }
                    let ir_item = IrItem::PureFn(self.gen_function(f));
                    self.module.items.push(ir_item);
                }
                Item::Lock(l) => {
                    let ir_item = IrItem::Lock(self.gen_lock(l));
                    self.module.items.push(ir_item);
                }
                Item::Use(_) => {}
            }
        }
        if let Some(error) = self.errors.into_iter().next() {
            Err(error)
        } else {
            Ok(self.module)
        }
    }

    fn gen_resource(&mut self, resource: &ResourceDef) -> IrTypeDef {
        IrTypeDef {
            name: resource.name.clone(),
            type_id: resource.type_id.as_ref().map(|type_id| type_id.value.clone()),
            kind: IrTypeKind::Resource,
            fields: self.layout_fields(&resource.fields),
            capabilities: resource.capabilities.clone(),
            claim_output: None,
            lifecycle_states: None,
            lifecycle_rules: Vec::new(),
        }
    }

    fn gen_shared(&mut self, shared: &SharedDef) -> IrTypeDef {
        IrTypeDef {
            name: shared.name.clone(),
            type_id: shared.type_id.as_ref().map(|type_id| type_id.value.clone()),
            kind: IrTypeKind::Shared,
            fields: self.layout_fields(&shared.fields),
            capabilities: shared.capabilities.clone(),
            claim_output: None,
            lifecycle_states: None,
            lifecycle_rules: Vec::new(),
        }
    }

    fn gen_receipt(&mut self, receipt: &ReceiptDef) -> IrTypeDef {
        IrTypeDef {
            name: receipt.name.clone(),
            type_id: receipt.type_id.as_ref().map(|type_id| type_id.value.clone()),
            kind: IrTypeKind::Receipt,
            fields: self.layout_fields(&receipt.fields),
            capabilities: receipt.capabilities.clone(),
            claim_output: receipt.claim_output.as_ref().map(Self::convert_type),
            lifecycle_states: receipt.lifecycle.as_ref().map(|lifecycle| lifecycle.states.clone()),
            lifecycle_rules: receipt
                .lifecycle
                .as_ref()
                .map(|lifecycle| Self::lifecycle_rules_from_states(&lifecycle.states))
                .unwrap_or_default(),
        }
    }

    fn gen_struct(&mut self, struct_def: &StructDef) -> IrTypeDef {
        IrTypeDef {
            name: struct_def.name.clone(),
            type_id: struct_def.type_id.as_ref().map(|type_id| type_id.value.clone()),
            kind: IrTypeKind::Struct,
            fields: self.layout_fields(&struct_def.fields),
            capabilities: Vec::new(),
            claim_output: None,
            lifecycle_states: None,
            lifecycle_rules: Vec::new(),
        }
    }

    fn lifecycle_rules_from_states(states: &[String]) -> Vec<IrLifecycleRule> {
        states
            .windows(2)
            .enumerate()
            .map(|(index, window)| IrLifecycleRule {
                from: window[0].clone(),
                to: window[1].clone(),
                from_index: index,
                to_index: index + 1,
            })
            .collect()
    }

    fn infer_module_function_effects(&mut self, items: &[Item]) {
        for item in items {
            match item {
                Item::Action(action) => {
                    self.function_effects.insert(action.name.clone(), EffectClass::Pure);
                    self.function_effects.insert(format!("{}::{}", self.module.name, action.name), EffectClass::Pure);
                }
                Item::Function(function) => {
                    self.function_effects.insert(function.name.clone(), EffectClass::Pure);
                    self.function_effects.insert(format!("{}::{}", self.module.name, function.name), EffectClass::Pure);
                }
                _ => {}
            }
        }

        for _ in 0..items.len().saturating_add(1) {
            let mut changed = false;
            for item in items {
                match item {
                    Item::Action(action) => {
                        let inferred = self.analyze_effect_class(action);
                        let declared = self.convert_effect_class(action.effect);
                        let effective =
                            if action.effect_declared && self.effect_covers(declared, inferred) { declared } else { inferred };
                        if self.function_effects.get(&action.name).copied() != Some(effective) {
                            self.function_effects.insert(action.name.clone(), effective);
                            self.function_effects.insert(format!("{}::{}", self.module.name, action.name), effective);
                            changed = true;
                        }
                    }
                    Item::Function(function) => {
                        let inferred = self.analyze_body_effect_class(&function.body);
                        if self.function_effects.get(&function.name).copied() != Some(inferred) {
                            self.function_effects.insert(function.name.clone(), inferred);
                            self.function_effects.insert(format!("{}::{}", self.module.name, function.name), inferred);
                            changed = true;
                        }
                    }
                    _ => {}
                }
            }
            if !changed {
                break;
            }
        }
    }

    fn gen_function(&mut self, function: &FnDef) -> IrPureFn {
        self.var_counter = 0;
        self.block_counter = 0;
        self.aggregate_fields.clear();
        self.schema_field_roots.clear();
        self.aggregate_elements.clear();
        self.mutated_fields.clear();
        self.mutated_field_transitions.clear();
        self.transition_param_ids.clear();
        self.transition_coverable_value_ids.clear();
        let (params, body) = self.lower_signature_and_body(&function.params, &function.body, function.return_type.is_some());

        IrPureFn { name: function.name.clone(), params, return_type: function.return_type.as_ref().map(Self::convert_type), body }
    }

    fn layout_fields(&self, fields: &[Field]) -> Vec<IrField> {
        let mut next_offset = Some(0usize);
        fields
            .iter()
            .map(|field| {
                let ty = Self::convert_type(&field.ty);
                let fixed_size = self.fixed_encoded_size(&ty);
                let offset = next_offset.unwrap_or(0);
                next_offset = next_offset.and_then(|current| fixed_size.map(|size| current + size));
                IrField { name: field.name.clone(), ty, offset, fixed_size }
            })
            .collect()
    }

    fn fixed_encoded_size(&self, ty: &IrType) -> Option<usize> {
        self.fixed_encoded_size_with_seen(ty, &mut HashSet::new())
    }

    fn fixed_encoded_size_with_seen(&self, ty: &IrType, seen: &mut HashSet<String>) -> Option<usize> {
        match ty {
            IrType::U8 | IrType::Bool => Some(1),
            IrType::U16 => Some(2),
            IrType::U32 => Some(4),
            IrType::U64 => Some(8),
            IrType::U128 => Some(16),
            IrType::Address | IrType::Hash => Some(32),
            IrType::Array(inner, len) => self.fixed_encoded_size_with_seen(inner, seen).map(|inner_size| inner_size * len),
            IrType::Tuple(items) => {
                items.iter().try_fold(0usize, |acc, item| self.fixed_encoded_size_with_seen(item, seen).map(|size| acc + size))
            }
            IrType::Unit => Some(0),
            IrType::Named(name) => {
                let base_name = name.split('<').next().unwrap_or(name.as_str());
                if let Some(size) = self.module.enum_fixed_sizes.get(base_name).copied() {
                    return Some(size);
                }
                if !seen.insert(base_name.to_string()) {
                    return None;
                }
                let size = self.type_fields.get(base_name).and_then(|fields| {
                    fields.values().try_fold(0usize, |acc, field_ty| {
                        self.fixed_encoded_size_with_seen(field_ty, seen).map(|field_size| acc + field_size)
                    })
                });
                seen.remove(base_name);
                size
            }
            IrType::Ref(_) | IrType::MutRef(_) => None,
        }
    }

    fn gen_action(&mut self, action: &ActionDef) -> IrAction {
        self.var_counter = 0;
        self.block_counter = 0;
        self.aggregate_fields.clear();
        self.schema_field_roots.clear();
        self.aggregate_elements.clear();
        self.mutated_fields.clear();
        self.mutated_field_transitions.clear();
        self.transition_param_ids.clear();
        self.transition_coverable_value_ids.clear();
        let (params, body) = self.lower_signature_and_body(&action.params, &action.body, action.return_type.is_some());

        let mut effect_class = self.analyze_effect_class(action);
        if params.iter().any(|param| param.is_read_ref) && effect_class == EffectClass::Pure {
            effect_class = EffectClass::ReadOnly;
        }
        if params.iter().any(|param| self.param_mutates_shared_state(param)) {
            effect_class = EffectClass::Mutating;
        }
        let declared_effect_class = self.convert_effect_class(action.effect);
        if action.effect_declared && !self.effect_covers(declared_effect_class, effect_class) {
            self.record_error(
                format!(
                    "declared effect {:?} is too weak for action '{}'; inferred effect is {:?}",
                    declared_effect_class, action.name, effect_class
                ),
                action.span,
            );
        }
        let touches_shared = self.infer_touches_shared(&params, &body);
        let estimated_cycles = self.estimate_cycles(&body);

        IrAction {
            name: action.name.clone(),
            params,
            return_type: action.return_type.as_ref().map(Self::convert_type),
            body,
            effect_class: if action.effect_declared { declared_effect_class } else { effect_class },
            scheduler_hints: action
                .scheduler_hint
                .as_ref()
                .map(|hint| SchedulerHints {
                    parallelizable: hint.parallelizable,
                    touches_shared: touches_shared.clone(),
                    estimated_cycles: hint.estimated_cycles.max(estimated_cycles),
                })
                .unwrap_or(SchedulerHints { parallelizable: touches_shared.is_empty(), touches_shared, estimated_cycles }),
        }
    }

    fn gen_lock(&mut self, lock: &LockDef) -> IrLock {
        self.var_counter = 0;
        self.block_counter = 0;
        self.aggregate_fields.clear();
        self.schema_field_roots.clear();
        self.aggregate_elements.clear();
        self.mutated_fields.clear();
        self.mutated_field_transitions.clear();
        self.transition_param_ids.clear();
        self.transition_coverable_value_ids.clear();
        let (params, body) = self.lower_signature_and_body(&lock.params, &lock.body, false);

        IrLock { name: lock.name.clone(), params, body }
    }

    fn convert_type(ty: &Type) -> IrType {
        match ty {
            Type::U8 => IrType::U8,
            Type::U16 => IrType::U16,
            Type::U32 => IrType::U32,
            Type::U64 => IrType::U64,
            Type::U128 => IrType::U128,
            Type::Bool => IrType::Bool,
            Type::Unit => IrType::Unit,
            Type::Address => IrType::Address,
            Type::Hash => IrType::Hash,
            Type::Array(elem, size) => IrType::Array(Box::new(Self::convert_type(elem)), *size),
            Type::Tuple(types) => IrType::Tuple(types.iter().map(Self::convert_type).collect()),
            Type::Named(name) => IrType::Named(name.clone()),
            Type::Ref(inner) => IrType::Ref(Box::new(Self::convert_type(inner))),
            Type::MutRef(inner) => IrType::MutRef(Box::new(Self::convert_type(inner))),
        }
    }

    fn analyze_effect_class(&self, action: &ActionDef) -> EffectClass {
        self.analyze_body_effect_class(&action.body)
    }

    fn analyze_body_effect_class(&self, body: &[Stmt]) -> EffectClass {
        let mut footprint = EffectFootprint::default();

        for stmt in body {
            self.check_stmt_effects(stmt, &mut footprint);
        }

        match (footprint.has_consume, footprint.has_create, footprint.has_read_ref) {
            (true, true, _) => EffectClass::Mutating,
            (true, false, _) => EffectClass::Destroying,
            (false, true, _) => EffectClass::Creating,
            (false, false, true) => EffectClass::ReadOnly,
            (false, false, false) => EffectClass::Pure,
        }
    }

    fn effect_covers(&self, declared: EffectClass, inferred: EffectClass) -> bool {
        matches!(
            (declared, inferred),
            (EffectClass::Pure, EffectClass::Pure)
                | (EffectClass::ReadOnly, EffectClass::Pure | EffectClass::ReadOnly)
                | (EffectClass::Creating, EffectClass::Pure | EffectClass::ReadOnly | EffectClass::Creating)
                | (EffectClass::Destroying, EffectClass::Pure | EffectClass::ReadOnly | EffectClass::Destroying)
                | (EffectClass::Mutating, _)
        )
    }

    fn check_stmt_effects(&self, stmt: &Stmt, footprint: &mut EffectFootprint) {
        match stmt {
            Stmt::Expr(expr) | Stmt::Let(LetStmt { value: expr, .. }) => {
                self.check_expr_effects(expr, footprint);
            }
            Stmt::Return(Some(expr)) => {
                self.check_expr_effects(expr, footprint);
            }
            Stmt::If(if_stmt) => {
                self.check_expr_effects(&if_stmt.condition, footprint);
                for stmt in &if_stmt.then_branch {
                    self.check_stmt_effects(stmt, footprint);
                }
                if let Some(ref else_branch) = if_stmt.else_branch {
                    for stmt in else_branch {
                        self.check_stmt_effects(stmt, footprint);
                    }
                }
            }
            Stmt::For(for_stmt) => {
                self.check_expr_effects(&for_stmt.iterable, footprint);
                for stmt in &for_stmt.body {
                    self.check_stmt_effects(stmt, footprint);
                }
            }
            Stmt::While(while_stmt) => {
                self.check_expr_effects(&while_stmt.condition, footprint);
                for stmt in &while_stmt.body {
                    self.check_stmt_effects(stmt, footprint);
                }
            }
            _ => {}
        }
    }

    fn check_expr_effects(&self, expr: &Expr, footprint: &mut EffectFootprint) {
        match expr {
            Expr::Consume(consume) => {
                footprint.has_consume = true;
                self.check_expr_effects(&consume.expr, footprint);
            }
            Expr::Create(create) => {
                footprint.has_create = true;
                for (_, value) in &create.fields {
                    self.check_expr_effects(value, footprint);
                }
                if let Some(lock) = &create.lock {
                    self.check_expr_effects(lock, footprint);
                }
            }
            Expr::Transfer(transfer) => {
                footprint.has_consume = true;
                footprint.has_create = true;
                self.check_expr_effects(&transfer.expr, footprint);
                self.check_expr_effects(&transfer.to, footprint);
            }
            Expr::Destroy(destroy) => {
                footprint.has_consume = true;
                self.check_expr_effects(&destroy.expr, footprint);
            }
            Expr::ReadRef(_) => {
                footprint.has_read_ref = true;
            }
            Expr::Claim(claim) => {
                footprint.has_consume = true;
                footprint.has_create = true;
                self.check_expr_effects(&claim.receipt, footprint);
            }
            Expr::Settle(settle) => {
                footprint.has_consume = true;
                footprint.has_create = true;
                self.check_expr_effects(&settle.expr, footprint);
            }
            Expr::Assert(assert_expr) => {
                self.check_expr_effects(&assert_expr.condition, footprint);
            }
            Expr::Assign(assign) => {
                self.check_expr_effects(&assign.target, footprint);
                self.check_expr_effects(&assign.value, footprint);
            }
            Expr::Binary(bin) => {
                self.check_expr_effects(&bin.left, footprint);
                self.check_expr_effects(&bin.right, footprint);
            }
            Expr::Unary(unary) => {
                self.check_expr_effects(&unary.expr, footprint);
            }
            Expr::Call(call) => {
                if let Expr::Identifier(name) = call.func.as_ref() {
                    if let Some(effect) = self.function_effects.get(name).copied() {
                        self.apply_effect_to_footprint(effect, footprint);
                    } else if let Some(effect) = self.external_function_effects.get(name).copied() {
                        self.apply_effect_to_footprint(effect, footprint);
                    }
                }
                for arg in &call.args {
                    self.check_expr_effects(arg, footprint);
                }
            }
            Expr::FieldAccess(field) => {
                self.check_expr_effects(&field.expr, footprint);
            }
            Expr::Index(index) => {
                self.check_expr_effects(&index.expr, footprint);
                self.check_expr_effects(&index.index, footprint);
            }
            Expr::If(if_expr) => {
                self.check_expr_effects(&if_expr.condition, footprint);
                self.check_expr_effects(&if_expr.then_branch, footprint);
                self.check_expr_effects(&if_expr.else_branch, footprint);
            }
            Expr::Cast(cast) => {
                self.check_expr_effects(&cast.expr, footprint);
            }
            Expr::Range(range) => {
                self.check_expr_effects(&range.start, footprint);
                self.check_expr_effects(&range.end, footprint);
            }
            Expr::StructInit(init) => {
                for (_, value) in &init.fields {
                    self.check_expr_effects(value, footprint);
                }
            }
            Expr::Match(match_expr) => {
                self.check_expr_effects(&match_expr.expr, footprint);
                for arm in &match_expr.arms {
                    self.check_expr_effects(&arm.value, footprint);
                }
            }
            Expr::Block(stmts) => {
                for stmt in stmts {
                    self.check_stmt_effects(stmt, footprint);
                }
            }
            Expr::Tuple(elems) | Expr::Array(elems) => {
                for elem in elems {
                    self.check_expr_effects(elem, footprint);
                }
            }
            _ => {}
        }
    }

    fn apply_effect_to_footprint(&self, effect: EffectClass, footprint: &mut EffectFootprint) {
        match effect {
            EffectClass::Pure => {}
            EffectClass::ReadOnly => footprint.has_read_ref = true,
            EffectClass::Creating => footprint.has_create = true,
            EffectClass::Destroying => footprint.has_consume = true,
            EffectClass::Mutating => {
                footprint.has_consume = true;
                footprint.has_create = true;
            }
        }
    }

    fn convert_effect_class(&self, effect: crate::ast::EffectClass) -> EffectClass {
        match effect {
            crate::ast::EffectClass::Pure => EffectClass::Pure,
            crate::ast::EffectClass::ReadOnly => EffectClass::ReadOnly,
            crate::ast::EffectClass::Mutating => EffectClass::Mutating,
            crate::ast::EffectClass::Creating => EffectClass::Creating,
            crate::ast::EffectClass::Destroying => EffectClass::Destroying,
        }
    }

    fn lower_signature_and_body(&mut self, params: &[Param], stmts: &[Stmt], tail_expr_returns: bool) -> (Vec<IrParam>, IrBody) {
        let mut vars = HashMap::new();
        let ir_params = params
            .iter()
            .map(|param| {
                let binding = self.new_var(param.name.clone(), Self::convert_type(&param.ty));
                vars.insert(param.name.clone(), binding.clone());
                IrParam {
                    name: param.name.clone(),
                    ty: Self::convert_type(&param.ty),
                    is_mut: param.is_mut,
                    is_ref: param.is_ref,
                    is_read_ref: param.is_read_ref,
                    binding,
                }
            })
            .collect::<Vec<_>>();
        self.transition_param_ids = ir_params.iter().map(|param| param.binding.id).collect();
        let mut blocks = Vec::new();
        let entry = self.push_block(&mut blocks);
        let _ = self.lower_stmts(stmts, entry, &mut blocks, &mut vars, tail_expr_returns);
        let consume_set = self.collect_consume_patterns(&blocks);
        let mut read_refs = self.collect_read_ref_param_patterns(&ir_params);
        read_refs.extend(self.collect_read_ref_patterns(&blocks));
        let create_set = self.collect_create_patterns(&blocks);
        let mutate_set = self.collect_mutate_param_patterns(&ir_params, consume_set.len(), create_set.len());
        let write_intents = Self::collect_write_intents(&create_set, &mutate_set);
        self.transition_param_ids.clear();
        self.transition_coverable_value_ids.clear();

        (ir_params, IrBody { consume_set, read_refs, create_set, mutate_set, write_intents, blocks })
    }

    fn collect_write_intents(create_set: &[CreatePattern], mutate_set: &[MutatePattern]) -> Vec<WriteIntent> {
        let create_intents = create_set.iter().enumerate().map(|(index, pattern)| WriteIntent {
            operation: pattern.operation.clone(),
            ty: pattern.ty.clone(),
            binding: pattern.binding.clone(),
            source: WriteIntentSource::Output,
            index,
            fields: pattern.fields.iter().map(|(field, _)| field.clone()).collect(),
        });
        let mutate_intents = mutate_set.iter().map(|pattern| WriteIntent {
            operation: pattern.operation.clone(),
            ty: pattern.ty.clone(),
            binding: pattern.binding.clone(),
            source: WriteIntentSource::ReplacementOutput,
            index: pattern.output_index,
            fields: pattern.fields.clone(),
        });

        create_intents.chain(mutate_intents).collect()
    }

    fn collect_consume_patterns(&self, blocks: &[IrBlock]) -> Vec<CellPattern> {
        let mut patterns = Vec::new();
        for block in blocks {
            for instruction in &block.instructions {
                if let IrInstruction::Consume { operand } = instruction {
                    if let Some(pattern) = self.cell_pattern_from_operand(operand, "consume") {
                        patterns.push(pattern);
                    }
                } else if let IrInstruction::Transfer { operand, .. } = instruction {
                    if let Some(pattern) = self.cell_pattern_from_operand(operand, "transfer") {
                        patterns.push(pattern);
                    }
                } else if let IrInstruction::Destroy { operand } = instruction {
                    if let Some(pattern) = self.cell_pattern_from_operand(operand, "destroy") {
                        patterns.push(pattern);
                    }
                } else if let IrInstruction::Claim { receipt, .. } = instruction {
                    if let Some(pattern) = self.cell_pattern_from_operand(receipt, "claim") {
                        patterns.push(pattern);
                    }
                } else if let IrInstruction::Settle { operand, .. } = instruction {
                    if let Some(pattern) = self.cell_pattern_from_operand(operand, "settle") {
                        patterns.push(pattern);
                    }
                }
            }
        }
        patterns
    }

    fn collect_read_ref_patterns(&self, blocks: &[IrBlock]) -> Vec<CellPattern> {
        let mut patterns = Vec::new();
        for block in blocks {
            for instruction in &block.instructions {
                if let IrInstruction::ReadRef { dest, ty } = instruction {
                    patterns.push(CellPattern {
                        operation: "read_ref".to_string(),
                        type_hash: Some(type_hash_for_name(ty)),
                        binding: dest.name.clone(),
                        fields: Vec::new(),
                    });
                }
            }
        }
        patterns
    }

    fn collect_read_ref_param_patterns(&self, params: &[IrParam]) -> Vec<CellPattern> {
        params
            .iter()
            .filter(|param| param.is_read_ref)
            .filter_map(|param| {
                Self::named_type_name_from_ir_type(&param.ty).map(|type_name| CellPattern {
                    operation: "read_ref".to_string(),
                    type_hash: Some(type_hash_for_name(type_name)),
                    binding: param.name.clone(),
                    fields: Vec::new(),
                })
            })
            .collect()
    }

    fn collect_create_patterns(&self, blocks: &[IrBlock]) -> Vec<CreatePattern> {
        let mut patterns = Vec::new();
        for block in blocks {
            for instruction in &block.instructions {
                if let IrInstruction::Create { pattern, .. } = instruction {
                    patterns.push(pattern.clone());
                } else if let IrInstruction::Transfer { dest, to, .. } = instruction {
                    if let Some(pattern) = self.create_pattern_from_var_with_lock(dest, "transfer", Some(to.clone())) {
                        patterns.push(pattern);
                    }
                } else if let IrInstruction::Claim { dest, .. } = instruction {
                    if let Some(pattern) = self.create_pattern_from_var(dest, "claim") {
                        patterns.push(pattern);
                    }
                } else if let IrInstruction::Settle { dest, .. } = instruction {
                    if let Some(pattern) = self.create_pattern_from_var(dest, "settle") {
                        patterns.push(pattern);
                    }
                }
            }
        }
        patterns
    }

    fn collect_mutate_param_patterns(&self, params: &[IrParam], consume_count: usize, create_count: usize) -> Vec<MutatePattern> {
        let mut patterns = Vec::new();
        for param in params {
            if !(param.is_mut || matches!(param.ty, IrType::MutRef(_))) {
                continue;
            }
            let Some(type_name) = Self::named_type_name_from_ir_type(&param.ty) else {
                continue;
            };
            if !matches!(self.type_kinds.get(type_name), Some(IrTypeKind::Resource | IrTypeKind::Shared | IrTypeKind::Receipt)) {
                continue;
            }
            let fields = self
                .mutated_fields
                .get(&param.binding.id)
                .map(|fields| fields.iter().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            let mutated = fields.iter().cloned().collect::<BTreeSet<_>>();
            let preserved_fields = self
                .type_fields
                .get(type_name)
                .map(|fields| {
                    fields
                        .keys()
                        .filter(|field| !mutated.contains(*field))
                        .cloned()
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let transitions = self
                .mutated_field_transitions
                .get(&param.binding.id)
                .map(|fields| fields.values().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            let mutation_index = patterns.len();
            patterns.push(MutatePattern {
                operation: "mutate".to_string(),
                ty: type_name.to_string(),
                binding: param.name.clone(),
                fields,
                preserved_fields,
                transitions,
                input_index: consume_count + mutation_index,
                output_index: create_count + mutation_index,
                preserve_type_hash: true,
                preserve_lock_hash: true,
            });
        }
        patterns
    }

    fn cell_pattern_from_operand(&self, operand: &IrOperand, operation: &str) -> Option<CellPattern> {
        let IrOperand::Var(var) = operand else {
            return None;
        };
        let type_name = match &var.ty {
            IrType::Named(name) => Some(name.as_str()),
            IrType::Ref(inner) | IrType::MutRef(inner) => match inner.as_ref() {
                IrType::Named(name) => Some(name.as_str()),
                _ => None,
            },
            _ => None,
        }?;
        Some(CellPattern {
            operation: operation.to_string(),
            type_hash: Some(type_hash_for_name(type_name)),
            binding: var.name.clone(),
            fields: Vec::new(),
        })
    }

    fn create_pattern_from_var(&self, var: &IrVar, operation: &str) -> Option<CreatePattern> {
        self.create_pattern_from_var_with_lock(var, operation, None)
    }

    fn create_pattern_from_var_with_lock(&self, var: &IrVar, operation: &str, lock: Option<IrOperand>) -> Option<CreatePattern> {
        let type_name = match &var.ty {
            IrType::Named(name) => Some(name.as_str()),
            IrType::Ref(inner) | IrType::MutRef(inner) => match inner.as_ref() {
                IrType::Named(name) => Some(name.as_str()),
                _ => None,
            },
            _ => None,
        }?;
        let fields = self
            .aggregate_fields
            .get(&var.id)
            .map(|field_vars| {
                let mut fields =
                    field_vars.iter().map(|(field, var)| (field.clone(), IrOperand::Var(var.clone()))).collect::<Vec<_>>();
                fields.sort_by(|(left, _), (right, _)| left.cmp(right));
                fields
            })
            .unwrap_or_default();
        Some(CreatePattern { operation: operation.to_string(), ty: type_name.to_string(), binding: var.name.clone(), fields, lock })
    }

    fn named_type_name_from_ir_type(ty: &IrType) -> Option<&str> {
        match ty {
            IrType::Named(name) => Some(name.as_str()),
            IrType::Ref(inner) | IrType::MutRef(inner) => Self::named_type_name_from_ir_type(inner),
            _ => None,
        }
    }

    fn claim_output_type_for_operand(&self, operand: &IrOperand) -> IrType {
        let ty = self.operand_type(operand);
        Self::named_type_name_from_ir_type(&ty)
            .and_then(|name| self.receipt_claim_outputs.get(name))
            .and_then(Clone::clone)
            .unwrap_or(IrType::U64)
    }

    fn materialize_matching_output_fields(
        &mut self,
        source: &IrOperand,
        output_ty: &IrType,
        active: BlockId,
        blocks: &mut Vec<IrBlock>,
    ) -> HashMap<String, IrVar> {
        let (IrOperand::Var(source_var), Some(output_type_name)) = (source, Self::named_type_name_from_ir_type(output_ty)) else {
            return HashMap::new();
        };
        let Some(output_fields) = self.type_fields.get(output_type_name).cloned() else {
            return HashMap::new();
        };

        let mut field_names = output_fields.keys().cloned().collect::<Vec<_>>();
        field_names.sort();
        let mut field_vars = HashMap::new();
        for field_name in field_names {
            let Some(output_field_ty) = output_fields.get(&field_name) else {
                continue;
            };
            let Some(source_field_ty) = self.lookup_field_ir_type(&source_var.ty, &field_name) else {
                continue;
            };
            if &source_field_ty != output_field_ty {
                continue;
            }
            if !is_verifier_coverable_output_field_type(output_field_ty) {
                continue;
            }
            if let Some(field_var) = self.materialize_schema_field(source_var, &field_name, active, blocks) {
                field_vars.insert(field_name, field_var);
            }
        }
        field_vars
    }

    fn infer_touches_shared(&self, params: &[IrParam], body: &IrBody) -> Vec<[u8; 32]> {
        let shared_hashes = self
            .type_kinds
            .iter()
            .filter_map(|(name, kind)| (*kind == IrTypeKind::Shared).then_some(type_hash_for_name(name)))
            .collect::<Vec<_>>();
        let mut hashes = Vec::new();
        for param in params {
            if let Some(type_name) = self.param_shared_type_name(param) {
                hashes.push(type_hash_for_name(type_name));
            }
        }
        for pattern in body.read_refs.iter().chain(body.consume_set.iter()) {
            if let Some(type_hash) = pattern.type_hash {
                if shared_hashes.contains(&type_hash) {
                    hashes.push(type_hash);
                }
            }
        }
        for pattern in &body.create_set {
            if self.type_kinds.get(&pattern.ty) == Some(&IrTypeKind::Shared) {
                hashes.push(type_hash_for_name(&pattern.ty));
            }
        }
        for block in &body.blocks {
            for instruction in &block.instructions {
                if let IrInstruction::Call { dest: Some(dest), .. } = instruction {
                    self.collect_shared_type_hashes_from_type(&dest.ty, &mut hashes);
                }
            }
        }
        hashes.sort();
        hashes.dedup();
        hashes
    }

    fn param_shared_type_name<'a>(&self, param: &'a IrParam) -> Option<&'a str> {
        let type_name = Self::named_type_name_from_ir_type(&param.ty)?;
        (self.type_kinds.get(type_name) == Some(&IrTypeKind::Shared)).then_some(type_name)
    }

    fn param_mutates_shared_state(&self, param: &IrParam) -> bool {
        if self.param_shared_type_name(param).is_none() {
            return false;
        }
        param.is_mut || matches!(param.ty, IrType::MutRef(_))
    }

    fn collect_shared_type_hashes_from_type(&self, ty: &IrType, hashes: &mut Vec<[u8; 32]>) {
        match ty {
            IrType::Named(name) if self.type_kinds.get(name) == Some(&IrTypeKind::Shared) => {
                hashes.push(type_hash_for_name(name));
            }
            IrType::Ref(inner) | IrType::MutRef(inner) | IrType::Array(inner, _) => {
                self.collect_shared_type_hashes_from_type(inner, hashes);
            }
            IrType::Tuple(items) => {
                for item in items {
                    self.collect_shared_type_hashes_from_type(item, hashes);
                }
            }
            _ => {}
        }
    }

    fn estimate_cycles(&self, body: &IrBody) -> u64 {
        let instruction_count = body.blocks.iter().map(|block| block.instructions.len() as u64).sum::<u64>();
        let branch_count =
            body.blocks.iter().filter(|block| matches!(block.terminator, IrTerminator::Jump(_) | IrTerminator::Branch { .. })).count()
                as u64;
        let cell_ops = (body.consume_set.len() + body.read_refs.len() + body.create_set.len()) as u64;
        (instruction_count * 8) + (branch_count * 4) + (cell_ops * 128) + 32
    }

    fn lower_stmts(
        &mut self,
        stmts: &[Stmt],
        mut current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
        tail_expr_returns: bool,
    ) -> Option<BlockId> {
        for (index, stmt) in stmts.iter().enumerate() {
            if tail_expr_returns && index + 1 == stmts.len() {
                if let Stmt::Expr(expr) = stmt {
                    let lowered = self.lower_expr(expr, current, blocks, vars);
                    let active = lowered.current?;
                    self.block_mut(blocks, active).terminator = IrTerminator::Return(Some(lowered.operand));
                    return None;
                }
                if let Stmt::If(if_stmt) = stmt {
                    return self.lower_if_stmt(if_stmt, current, blocks, vars, true);
                }
            }
            let next = self.lower_stmt(stmt, current, blocks, vars)?;
            current = next;
        }

        Some(current)
    }

    fn lower_stmt(
        &mut self,
        stmt: &Stmt,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> Option<BlockId> {
        match stmt {
            Stmt::Let(let_stmt) => {
                let transition_coverable = matches!(let_stmt.pattern, BindingPattern::Name(_))
                    && self.transition_expr_is_coverable_u64(&let_stmt.value, vars);
                let lowered = match (&let_stmt.value, &let_stmt.ty) {
                    (Expr::Array(items), Some(declared_ty)) if items.is_empty() => {
                        self.lower_empty_array_expr_with_type(declared_ty, current, blocks)
                    }
                    _ => self.lower_expr(&let_stmt.value, current, blocks, vars),
                };
                let active = lowered.current?;
                let block = self.block_mut(blocks, active);
                if let (BindingPattern::Name(name), Some(declared_ty)) = (&let_stmt.pattern, &let_stmt.ty) {
                    let declared_ty = Self::convert_type(declared_ty);
                    let var = if let_stmt.is_mut {
                        let owned = self.materialize_owned_operand(name, lowered.operand, block);
                        if owned.ty == declared_ty {
                            owned
                        } else {
                            self.materialize_operand_with_type(name, IrOperand::Var(owned), declared_ty, block)
                        }
                    } else {
                        self.materialize_operand_with_type(name, lowered.operand, declared_ty, block)
                    };
                    if transition_coverable && var.ty == IrType::U64 {
                        self.transition_coverable_value_ids.insert(var.id);
                    }
                    vars.insert(name.clone(), var);
                    return Some(active);
                }
                if let (BindingPattern::Name(name), true) = (&let_stmt.pattern, let_stmt.is_mut) {
                    let var = self.materialize_owned_operand(name, lowered.operand, block);
                    if transition_coverable && var.ty == IrType::U64 {
                        self.transition_coverable_value_ids.insert(var.id);
                    }
                    vars.insert(name.clone(), var);
                    return Some(active);
                }
                let bound = self.bind_pattern(&let_stmt.pattern, lowered.operand, block, vars);
                if transition_coverable && bound.as_ref().is_some_and(|var| var.ty == IrType::U64) {
                    let bound = bound.expect("checked above");
                    self.transition_coverable_value_ids.insert(bound.id);
                }
                Some(active)
            }
            Stmt::Expr(expr) => self.lower_expr(expr, current, blocks, vars).current,
            Stmt::Return(None) => {
                self.block_mut(blocks, current).terminator = IrTerminator::Return(None);
                None
            }
            Stmt::Return(Some(expr)) => {
                let lowered = self.lower_expr(expr, current, blocks, vars);
                let active = lowered.current?;
                self.block_mut(blocks, active).terminator = IrTerminator::Return(Some(lowered.operand));
                None
            }
            Stmt::If(if_stmt) => self.lower_if_stmt(if_stmt, current, blocks, vars, false),
            Stmt::For(for_stmt) => self.lower_for_stmt(for_stmt, current, blocks, vars),
            Stmt::While(while_stmt) => self.lower_while_stmt(while_stmt, current, blocks, vars),
        }
    }

    fn bind_pattern(
        &mut self,
        pattern: &BindingPattern,
        value: IrOperand,
        block: &mut IrBlock,
        vars: &mut HashMap<String, IrVar>,
    ) -> Option<IrVar> {
        match pattern {
            BindingPattern::Name(name) => {
                let var = self.materialize_operand(name, value, block);
                vars.insert(name.clone(), var.clone());
                Some(var)
            }
            BindingPattern::Tuple(items) => {
                let base_var = match &value {
                    IrOperand::Var(var) => Some(var.clone()),
                    IrOperand::Const(_) => None,
                };
                for (index, item) in items.iter().enumerate() {
                    if matches!(item, BindingPattern::Wildcard) {
                        continue;
                    }
                    let field = index.to_string();
                    let tuple_name = format!("{}_{}", binding_pattern_label(item), index);
                    let projected = base_var
                        .as_ref()
                        .and_then(|var| self.aggregate_fields.get(&var.id).and_then(|fields| fields.get(&field)).cloned())
                        .map(IrOperand::Var)
                        .or_else(|| {
                            let base_var = base_var.as_ref()?;
                            let field_ty = self.lookup_field_ir_type(&base_var.ty, &field)?;
                            let field_var = self.new_var(tuple_name, field_ty);
                            block.instructions.push(IrInstruction::FieldAccess {
                                dest: field_var.clone(),
                                obj: IrOperand::Var(base_var.clone()),
                                field,
                            });
                            Some(IrOperand::Var(field_var))
                        });

                    if let Some(projected) = projected {
                        self.bind_pattern(item, projected, block, vars);
                    } else {
                        self.record_error("tuple binding requires a lowered tuple aggregate", Span::default());
                    }
                }
                base_var
            }
            BindingPattern::Wildcard => None,
        }
    }

    fn materialize_operand(&mut self, name: &str, operand: IrOperand, block: &mut IrBlock) -> IrVar {
        match operand {
            IrOperand::Var(var) => var,
            IrOperand::Const(value) => {
                let ty = self.const_type(&value);
                let var = self.new_var(name.to_string(), ty);
                block.instructions.push(IrInstruction::LoadConst { dest: var.clone(), value });
                var
            }
        }
    }

    fn materialize_operand_with_type(&mut self, name: &str, operand: IrOperand, ty: IrType, block: &mut IrBlock) -> IrVar {
        match operand {
            IrOperand::Var(var) if var.ty == ty => var,
            IrOperand::Var(var) => {
                let dest = self.new_var(name.to_string(), ty);
                let source = IrOperand::Var(var);
                block.instructions.push(IrInstruction::Move { dest: dest.clone(), src: source.clone() });
                self.copy_aggregate_metadata(&source, dest.id);
                dest
            }
            IrOperand::Const(value) => {
                let dest = self.new_var(name.to_string(), ty);
                block.instructions.push(IrInstruction::LoadConst { dest: dest.clone(), value });
                dest
            }
        }
    }

    fn materialize_owned_operand(&mut self, name: &str, operand: IrOperand, block: &mut IrBlock) -> IrVar {
        match operand {
            IrOperand::Var(var) => {
                let dest = self.new_var(name.to_string(), var.ty.clone());
                let source = IrOperand::Var(var);
                block.instructions.push(IrInstruction::Move { dest: dest.clone(), src: source.clone() });
                self.copy_aggregate_metadata(&source, dest.id);
                dest
            }
            IrOperand::Const(value) => {
                let ty = self.const_type(&value);
                let dest = self.new_var(name.to_string(), ty);
                block.instructions.push(IrInstruction::LoadConst { dest: dest.clone(), value });
                dest
            }
        }
    }

    fn lower_expr(
        &mut self,
        expr: &Expr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        match expr {
            Expr::Integer(value) => LoweredExpr { operand: IrOperand::Const(IrConst::U64(*value)), current: Some(current) },
            Expr::Bool(value) => LoweredExpr { operand: IrOperand::Const(IrConst::Bool(*value)), current: Some(current) },
            Expr::Identifier(name) => {
                if let Some(var) = vars.get(name).cloned() {
                    LoweredExpr { operand: IrOperand::Var(var), current: Some(current) }
                } else if let Some(constant) = self.lower_constant(name, Span::default()) {
                    LoweredExpr { operand: constant, current: Some(current) }
                } else if let Some(zero) = self.lower_zero_value(name) {
                    LoweredExpr { operand: zero, current: Some(current) }
                } else if let Some(enum_variant) = self.lower_enum_variant(name) {
                    LoweredExpr { operand: enum_variant, current: Some(current) }
                } else {
                    self.record_error(format!("IR lowering encountered unresolved identifier '{}'", name), Span::default());
                    LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(current) }
                }
            }
            Expr::Assign(assign) => self.lower_assign_expr(assign, current, blocks, vars),
            Expr::Binary(binary) => {
                let left = self.lower_expr(&binary.left, current, blocks, vars);
                let Some(active) = left.current else {
                    return left;
                };
                let right = self.lower_expr(&binary.right, active, blocks, vars);
                let Some(active) = right.current else {
                    return right;
                };
                let dest = self.new_var("tmp", self.binary_result_type(binary.op));
                let block = self.block_mut(blocks, active);
                block.instructions.push(IrInstruction::Binary {
                    dest: dest.clone(),
                    op: binary.op,
                    left: left.operand,
                    right: right.operand,
                });
                LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) }
            }
            Expr::Unary(unary) => {
                let operand = self.lower_expr(&unary.expr, current, blocks, vars);
                let Some(active) = operand.current else {
                    return operand;
                };
                let dest = self.new_var("tmp", self.unary_result_type(unary.op, &operand.operand));
                let block = self.block_mut(blocks, active);
                block.instructions.push(IrInstruction::Unary { dest: dest.clone(), op: unary.op, operand: operand.operand });
                LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) }
            }
            Expr::Call(call) => {
                if let Some(lowered) = self.try_lower_builtin_call(call, current, blocks, vars) {
                    return lowered;
                }
                let mut active = current;
                let mut args = Vec::with_capacity(call.args.len());
                for arg in &call.args {
                    let lowered = self.lower_expr(arg, active, blocks, vars);
                    let Some(next) = lowered.current else {
                        return lowered;
                    };
                    active = next;
                    args.push(lowered.operand);
                }
                let func = match call.func.as_ref() {
                    Expr::Identifier(name) => self.lower_call_target_name(name),
                    Expr::FieldAccess(field) => field.field.clone(),
                    _ => "__expr_call".to_string(),
                };
                let source_func = match call.func.as_ref() {
                    Expr::Identifier(name) => name.as_str(),
                    Expr::FieldAccess(field) => field.field.as_str(),
                    _ => "__expr_call",
                };
                match self.call_return_type(source_func, &func) {
                    Some(Some(return_type)) => {
                        let dest = self.new_var("call_tmp", return_type);
                        self.block_mut(blocks, active).instructions.push(IrInstruction::Call { dest: Some(dest.clone()), func, args });
                        LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) }
                    }
                    Some(None) => {
                        self.block_mut(blocks, active).instructions.push(IrInstruction::Call { dest: None, func, args });
                        LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: Some(active) }
                    }
                    None => {
                        self.record_error(format!("call '{}' has no known return type during IR lowering", source_func), call.span);
                        LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(active) }
                    }
                }
            }
            Expr::ReadRef(read_ref) => self.lower_read_ref_expr(read_ref, current, blocks),
            Expr::Create(create) => self.lower_create_expr(create, current, blocks, vars),
            Expr::Consume(consume) => self.lower_consume_expr(consume, current, blocks, vars),
            Expr::Transfer(transfer) => self.lower_transfer_expr(transfer, current, blocks, vars),
            Expr::Destroy(destroy) => self.lower_destroy_expr(destroy, current, blocks, vars),
            Expr::Claim(claim) => self.lower_claim_expr(claim, current, blocks, vars),
            Expr::Settle(settle) => self.lower_settle_expr(settle, current, blocks, vars),
            Expr::Assert(assert_expr) => self.lower_assert_expr(assert_expr, current, blocks, vars),
            Expr::StructInit(init) => self.lower_struct_init(init, current, blocks, vars),
            Expr::FieldAccess(field) => self.lower_field_access(field, current, blocks, vars),
            Expr::Index(index) => self.lower_index_expr(index, current, blocks, vars),
            Expr::Block(stmts) => self.lower_tail_block_value(stmts, current, blocks, vars),
            Expr::If(if_expr) => self.lower_if_expr(if_expr, current, blocks, vars),
            Expr::Match(match_expr) => self.lower_match_expr(match_expr, current, blocks, vars),
            Expr::Cast(cast) => self.lower_expr(&cast.expr, current, blocks, vars),
            Expr::Array(items) => self.lower_array_expr(items, current, blocks, vars),
            Expr::Tuple(items) => self.lower_tuple_expr(items, current, blocks, vars),
            Expr::String(_) => {
                self.record_error("string literals are only supported in metadata positions such as assert messages", Span::default());
                LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(current) }
            }
            Expr::ByteString(_) => {
                self.record_error("byte string literals require an explicit lowered byte-array context", Span::default());
                LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(current) }
            }
            Expr::Range(_) => {
                self.record_error("range expressions are only supported as for-loop iterables", Span::default());
                LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(current) }
            }
        }
    }

    fn lower_tail_block_value(
        &mut self,
        stmts: &[Stmt],
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let Some((last, prefix)) = stmts.split_last() else {
            return LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: Some(current) };
        };

        let mut active = current;
        for stmt in prefix {
            let Some(next) = self.lower_stmt(stmt, active, blocks, vars) else {
                return LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: None };
            };
            active = next;
        }

        match last {
            Stmt::Expr(expr) => self.lower_expr(expr, active, blocks, vars),
            Stmt::If(if_stmt) if if_stmt.else_branch.is_some() => self.lower_if_stmt_value(if_stmt, active, blocks, vars),
            stmt => {
                let next = self.lower_stmt(stmt, active, blocks, vars);
                LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: next }
            }
        }
    }

    fn const_type(&self, value: &IrConst) -> IrType {
        match value {
            IrConst::U8(_) => IrType::U8,
            IrConst::U16(_) => IrType::U16,
            IrConst::U32(_) => IrType::U32,
            IrConst::U64(_) => IrType::U64,
            IrConst::U128(_) => IrType::U128,
            IrConst::Unit => IrType::Unit,
            IrConst::Bool(_) => IrType::Bool,
            IrConst::Address(_) => IrType::Address,
            IrConst::Hash(_) => IrType::Hash,
            IrConst::Array(_) => IrType::Array(Box::new(IrType::U8), 0),
        }
    }

    fn binary_result_type(&self, op: BinaryOp) -> IrType {
        match op {
            BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => IrType::Bool,
            BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod | BinaryOp::And | BinaryOp::Or => {
                IrType::U64
            }
        }
    }

    fn unary_result_type(&self, op: UnaryOp, operand: &IrOperand) -> IrType {
        match op {
            UnaryOp::Not => IrType::Bool,
            UnaryOp::Neg => IrType::U64,
            UnaryOp::Ref | UnaryOp::Deref => match operand {
                IrOperand::Var(var) => var.ty.clone(),
                IrOperand::Const(value) => self.const_type(value),
            },
        }
    }

    fn new_var(&mut self, name: impl Into<String>, ty: IrType) -> IrVar {
        let id = self.var_counter;
        self.var_counter += 1;
        IrVar { id, name: name.into(), ty }
    }

    fn new_block(&mut self) -> BlockId {
        let id = BlockId(self.block_counter);
        self.block_counter += 1;
        id
    }

    fn push_block(&mut self, blocks: &mut Vec<IrBlock>) -> BlockId {
        let id = self.new_block();
        blocks.push(IrBlock { id, instructions: Vec::new(), terminator: IrTerminator::Return(None) });
        id
    }

    fn block_mut<'a>(&self, blocks: &'a mut [IrBlock], id: BlockId) -> &'a mut IrBlock {
        &mut blocks[id.0]
    }

    fn lower_if_stmt(
        &mut self,
        if_stmt: &IfStmt,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
        tail_expr_returns: bool,
    ) -> Option<BlockId> {
        let lowered_cond = self.lower_expr(&if_stmt.condition, current, blocks, vars);
        let cond = lowered_cond.operand;
        let current = lowered_cond.current?;

        let then_block = self.push_block(blocks);
        let else_block = self.push_block(blocks);
        self.block_mut(blocks, current).terminator = IrTerminator::Branch { cond, then_block, else_block };

        let mut then_vars = vars.clone();
        let then_exit = self.lower_stmts(&if_stmt.then_branch, then_block, blocks, &mut then_vars, tail_expr_returns);

        let mut else_vars = vars.clone();
        let else_exit = if let Some(else_branch) = &if_stmt.else_branch {
            self.lower_stmts(else_branch, else_block, blocks, &mut else_vars, tail_expr_returns)
        } else {
            Some(else_block)
        };

        if then_exit.is_none() && else_exit.is_none() {
            return None;
        }

        let join = self.push_block(blocks);
        if let Some(exit) = then_exit {
            self.block_mut(blocks, exit).terminator = IrTerminator::Jump(join);
        }
        if let Some(exit) = else_exit {
            self.block_mut(blocks, exit).terminator = IrTerminator::Jump(join);
        }
        Some(join)
    }

    fn lower_if_stmt_value(
        &mut self,
        if_stmt: &IfStmt,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let lowered_cond = self.lower_expr(&if_stmt.condition, current, blocks, vars);
        let cond = lowered_cond.operand;
        let Some(current) = lowered_cond.current else {
            return LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: None };
        };
        let Some(else_branch) = &if_stmt.else_branch else {
            let next = self.lower_if_stmt(if_stmt, current, blocks, vars, false);
            return LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: next };
        };

        let then_block = self.push_block(blocks);
        let else_block = self.push_block(blocks);
        self.block_mut(blocks, current).terminator = IrTerminator::Branch { cond, then_block, else_block };

        let mut then_vars = vars.clone();
        let then_lowered = self.lower_tail_block_value(&if_stmt.then_branch, then_block, blocks, &mut then_vars);
        let mut else_vars = vars.clone();
        let else_lowered = self.lower_tail_block_value(else_branch, else_block, blocks, &mut else_vars);

        if then_lowered.current.is_none() && else_lowered.current.is_none() {
            return LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: None };
        }

        let result_ty = match (then_lowered.current.is_some(), else_lowered.current.is_some()) {
            (true, _) => self.operand_type(&then_lowered.operand),
            (false, true) => self.operand_type(&else_lowered.operand),
            (false, false) => return LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: None },
        };
        let dest = self.new_var("if_tmp", result_ty);
        let join = self.push_block(blocks);

        if let Some(exit) = then_lowered.current {
            let block = self.block_mut(blocks, exit);
            block.instructions.push(IrInstruction::Move { dest: dest.clone(), src: then_lowered.operand });
            block.terminator = IrTerminator::Jump(join);
        }

        if let Some(exit) = else_lowered.current {
            let block = self.block_mut(blocks, exit);
            block.instructions.push(IrInstruction::Move { dest: dest.clone(), src: else_lowered.operand });
            block.terminator = IrTerminator::Jump(join);
        }

        LoweredExpr { operand: IrOperand::Var(dest), current: Some(join) }
    }

    fn lower_while_stmt(
        &mut self,
        while_stmt: &WhileStmt,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> Option<BlockId> {
        let cond_entry = self.push_block(blocks);
        self.block_mut(blocks, current).terminator = IrTerminator::Jump(cond_entry);

        let lowered_cond = self.lower_expr(&while_stmt.condition, cond_entry, blocks, vars);
        let cond = lowered_cond.operand;
        let cond_exit = lowered_cond.current?;

        let body_block = self.push_block(blocks);
        let exit_block = self.push_block(blocks);
        self.block_mut(blocks, cond_exit).terminator = IrTerminator::Branch { cond, then_block: body_block, else_block: exit_block };

        let mut body_vars = vars.clone();
        let body_exit = self.lower_stmts(&while_stmt.body, body_block, blocks, &mut body_vars, false);
        if let Some(exit) = body_exit {
            self.block_mut(blocks, exit).terminator = IrTerminator::Jump(cond_entry);
        }

        Some(exit_block)
    }

    fn lower_for_stmt(
        &mut self,
        for_stmt: &ForStmt,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> Option<BlockId> {
        match &for_stmt.iterable {
            Expr::Range(range) => self.lower_for_range_stmt(for_stmt, range, current, blocks, vars),
            _ => {
                let lowered = self.lower_expr(&for_stmt.iterable, current, blocks, vars);
                let active = lowered.current?;
                self.lower_for_iterable_stmt(for_stmt, lowered.operand, active, blocks, vars)
            }
        }
    }

    fn lower_for_iterable_stmt(
        &mut self,
        for_stmt: &ForStmt,
        iterable: IrOperand,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> Option<BlockId> {
        if let IrOperand::Var(iterable_var) = &iterable {
            if let Some(elements) = self.aggregate_elements.get(&iterable_var.id).cloned() {
                return self.lower_for_local_fixed_array_stmt(for_stmt, elements, current, blocks, vars);
            }
            if let IrType::Array(_, len) = &iterable_var.ty {
                let len = *len;
                return self.lower_for_static_array_pointer_stmt(for_stmt, iterable, len, current, blocks, vars);
            }
        }

        let Some(item_ty) = self.iter_item_type(&iterable) else {
            self.record_error("for-loop iterable has no lowered item type", for_stmt.span);
            return Some(current);
        };

        let index_var = self.new_var("iter_index", IrType::U64);
        let length_var = self.new_var("iter_len", IrType::U64);
        {
            let block = self.block_mut(blocks, current);
            block.instructions.push(IrInstruction::Move { dest: index_var.clone(), src: IrOperand::Const(IrConst::U64(0)) });
            block.instructions.push(IrInstruction::Length { dest: length_var.clone(), operand: iterable.clone() });
        }

        let cond_block = self.push_block(blocks);
        self.block_mut(blocks, current).terminator = IrTerminator::Jump(cond_block);

        let cond_var = self.new_var("iter_cond", IrType::Bool);
        {
            let block = self.block_mut(blocks, cond_block);
            block.instructions.push(IrInstruction::Binary {
                dest: cond_var.clone(),
                op: BinaryOp::Lt,
                left: IrOperand::Var(index_var.clone()),
                right: IrOperand::Var(length_var.clone()),
            });
        }

        let body_block = self.push_block(blocks);
        let exit_block = self.push_block(blocks);
        self.block_mut(blocks, cond_block).terminator =
            IrTerminator::Branch { cond: IrOperand::Var(cond_var), then_block: body_block, else_block: exit_block };

        let item_var = self.new_var("iter_item", item_ty);
        self.block_mut(blocks, body_block).instructions.push(IrInstruction::Index {
            dest: item_var.clone(),
            arr: iterable,
            idx: IrOperand::Var(index_var.clone()),
        });

        let mut body_vars = vars.clone();
        self.bind_pattern(&for_stmt.pattern, IrOperand::Var(item_var), self.block_mut(blocks, body_block), &mut body_vars);
        let body_exit = self.lower_stmts(&for_stmt.body, body_block, blocks, &mut body_vars, false);
        if let Some(exit) = body_exit {
            let next_index = self.new_var("iter_next", IrType::U64);
            let block = self.block_mut(blocks, exit);
            block.instructions.push(IrInstruction::Binary {
                dest: next_index.clone(),
                op: BinaryOp::Add,
                left: IrOperand::Var(index_var.clone()),
                right: IrOperand::Const(IrConst::U64(1)),
            });
            block.instructions.push(IrInstruction::Move { dest: index_var, src: IrOperand::Var(next_index) });
            block.terminator = IrTerminator::Jump(cond_block);
        }

        Some(exit_block)
    }

    fn lower_for_static_array_pointer_stmt(
        &mut self,
        for_stmt: &ForStmt,
        iterable: IrOperand,
        len: usize,
        mut current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> Option<BlockId> {
        let Some(item_ty) = self.iter_item_type(&iterable) else {
            self.record_error("for-loop iterable has no lowered item type", for_stmt.span);
            return Some(current);
        };

        for index in 0..len {
            let item_var = self.new_var(format!("iter_item_{}", index), item_ty.clone());
            self.block_mut(blocks, current).instructions.push(IrInstruction::Index {
                dest: item_var.clone(),
                arr: iterable.clone(),
                idx: IrOperand::Const(IrConst::U64(index as u64)),
            });

            let mut body_vars = vars.clone();
            self.bind_pattern(&for_stmt.pattern, IrOperand::Var(item_var), self.block_mut(blocks, current), &mut body_vars);
            current = self.lower_stmts(&for_stmt.body, current, blocks, &mut body_vars, false)?;
        }

        Some(current)
    }

    fn lower_for_local_fixed_array_stmt(
        &mut self,
        for_stmt: &ForStmt,
        elements: Vec<IrVar>,
        mut current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> Option<BlockId> {
        for (index, element_var) in elements.into_iter().enumerate() {
            let item_var = self.new_var(format!("iter_item_{}", index), element_var.ty.clone());
            self.block_mut(blocks, current)
                .instructions
                .push(IrInstruction::Move { dest: item_var.clone(), src: IrOperand::Var(element_var.clone()) });
            self.copy_aggregate_metadata(&IrOperand::Var(element_var), item_var.id);

            let mut body_vars = vars.clone();
            self.bind_pattern(&for_stmt.pattern, IrOperand::Var(item_var), self.block_mut(blocks, current), &mut body_vars);
            current = self.lower_stmts(&for_stmt.body, current, blocks, &mut body_vars, false)?;
        }

        Some(current)
    }

    fn lower_for_range_stmt(
        &mut self,
        for_stmt: &ForStmt,
        range: &RangeExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> Option<BlockId> {
        let lowered_start = self.lower_expr(&range.start, current, blocks, vars);
        let start = lowered_start.operand;
        let active = lowered_start.current?;

        let lowered_end = self.lower_expr(&range.end, active, blocks, vars);
        let end = lowered_end.operand;
        let active = lowered_end.current?;

        let index_var = self.new_var("for_index", IrType::U64);
        let end_var = self.new_var("for_end", IrType::U64);
        {
            let block = self.block_mut(blocks, active);
            block.instructions.push(IrInstruction::Move { dest: index_var.clone(), src: start });
            block.instructions.push(IrInstruction::Move { dest: end_var.clone(), src: end });
        }

        let cond_block = self.push_block(blocks);
        self.block_mut(blocks, active).terminator = IrTerminator::Jump(cond_block);

        let cond_var = self.new_var("for_cond", IrType::Bool);
        {
            let block = self.block_mut(blocks, cond_block);
            block.instructions.push(IrInstruction::Binary {
                dest: cond_var.clone(),
                op: BinaryOp::Lt,
                left: IrOperand::Var(index_var.clone()),
                right: IrOperand::Var(end_var.clone()),
            });
        }

        let body_block = self.push_block(blocks);
        let exit_block = self.push_block(blocks);
        self.block_mut(blocks, cond_block).terminator =
            IrTerminator::Branch { cond: IrOperand::Var(cond_var), then_block: body_block, else_block: exit_block };

        let mut body_vars = vars.clone();
        self.bind_pattern(&for_stmt.pattern, IrOperand::Var(index_var.clone()), self.block_mut(blocks, body_block), &mut body_vars);
        let body_exit = self.lower_stmts(&for_stmt.body, body_block, blocks, &mut body_vars, false);
        if let Some(exit) = body_exit {
            let next_index = self.new_var("for_next", IrType::U64);
            let block = self.block_mut(blocks, exit);
            block.instructions.push(IrInstruction::Binary {
                dest: next_index.clone(),
                op: BinaryOp::Add,
                left: IrOperand::Var(index_var.clone()),
                right: IrOperand::Const(IrConst::U64(1)),
            });
            block.instructions.push(IrInstruction::Move { dest: index_var, src: IrOperand::Var(next_index) });
            block.terminator = IrTerminator::Jump(cond_block);
        }

        Some(exit_block)
    }

    fn lower_assert_expr(
        &mut self,
        assert_expr: &AssertExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let lowered_cond = self.lower_expr(&assert_expr.condition, current, blocks, vars);
        let Some(active) = lowered_cond.current else {
            return lowered_cond;
        };
        let cond = lowered_cond.operand;

        let ok_block = self.push_block(blocks);
        let fail_block = self.push_block(blocks);
        self.block_mut(blocks, active).terminator = IrTerminator::Branch { cond, then_block: ok_block, else_block: fail_block };
        self.block_mut(blocks, fail_block).terminator = IrTerminator::Return(Some(IrOperand::Const(IrConst::U64(7))));

        LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: Some(ok_block) }
    }

    fn lower_assign_expr(
        &mut self,
        assign: &AssignExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let lowered_value = self.lower_expr(&assign.value, current, blocks, vars);
        let Some(active) = lowered_value.current else {
            return lowered_value;
        };

        match assign.target.as_ref() {
            Expr::Identifier(name) => {
                let Some(target_var) = vars.get(name).cloned() else {
                    self.record_error(format!("assignment target '{}' is not bound in IR lowering", name), assign.span);
                    return LoweredExpr { operand: lowered_value.operand, current: Some(active) };
                };
                match assign.op {
                    AssignOp::Assign => {
                        self.block_mut(blocks, active)
                            .instructions
                            .push(IrInstruction::Move { dest: target_var.clone(), src: lowered_value.operand });
                    }
                    AssignOp::AddAssign => {
                        let tmp = self.new_var("assign_tmp", target_var.ty.clone());
                        let block = self.block_mut(blocks, active);
                        block.instructions.push(IrInstruction::Binary {
                            dest: tmp.clone(),
                            op: BinaryOp::Add,
                            left: IrOperand::Var(target_var.clone()),
                            right: lowered_value.operand,
                        });
                        block.instructions.push(IrInstruction::Move { dest: target_var.clone(), src: IrOperand::Var(tmp) });
                    }
                }
                LoweredExpr { operand: IrOperand::Var(target_var), current: Some(active) }
            }
            Expr::FieldAccess(field) => {
                self.lower_field_assign(field, assign.op, &assign.value, lowered_value.operand, active, blocks, vars)
            }
            Expr::Index(index) => self.lower_index_assign(index, assign.op, lowered_value.operand, active, blocks, vars),
            _ => {
                self.record_error("invalid assignment target reached IR lowering", assign.span);
                LoweredExpr { operand: lowered_value.operand, current: Some(active) }
            }
        }
    }

    fn lower_create_expr(
        &mut self,
        create: &CreateExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let dest = self.new_var(format!("create_{}", create.ty), IrType::Named(create.ty.clone()));
        let mut active = current;
        let mut lowered_fields = Vec::with_capacity(create.fields.len());
        let mut field_vars = HashMap::new();

        for (field_name, field_expr) in &create.fields {
            let lowered = self.lower_expr(field_expr, active, blocks, vars);
            let Some(next) = lowered.current else {
                return lowered;
            };
            active = next;
            lowered_fields.push((field_name.clone(), lowered.operand.clone()));

            let field_ty = match &lowered.operand {
                IrOperand::Var(var) => var.ty.clone(),
                IrOperand::Const(value) => self.const_type(value),
            };
            let field_var = self.new_var(format!("{}_{}", create.ty, field_name), field_ty);
            self.block_mut(blocks, active).instructions.push(IrInstruction::Move { dest: field_var.clone(), src: lowered.operand });
            field_vars.insert(field_name.clone(), field_var);
        }

        let lowered_lock = if let Some(lock_expr) = &create.lock {
            let lowered = self.lower_expr(lock_expr, active, blocks, vars);
            let Some(next) = lowered.current else {
                return lowered;
            };
            active = next;
            Some(lowered.operand)
        } else {
            None
        };

        let pattern = CreatePattern {
            operation: "create".to_string(),
            ty: create.ty.clone(),
            binding: dest.name.clone(),
            fields: lowered_fields,
            lock: lowered_lock,
        };
        self.block_mut(blocks, active).instructions.push(IrInstruction::Create { dest: dest.clone(), pattern });
        self.aggregate_fields.insert(dest.id, field_vars);
        LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) }
    }

    fn lower_consume_expr(
        &mut self,
        consume: &ConsumeExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let lowered = self.lower_expr(&consume.expr, current, blocks, vars);
        let Some(active) = lowered.current else {
            return lowered;
        };
        self.block_mut(blocks, active).instructions.push(IrInstruction::Consume { operand: lowered.operand.clone() });
        LoweredExpr { operand: lowered.operand, current: Some(active) }
    }

    fn lower_destroy_expr(
        &mut self,
        destroy: &DestroyExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let lowered = self.lower_expr(&destroy.expr, current, blocks, vars);
        let Some(active) = lowered.current else {
            return lowered;
        };
        self.block_mut(blocks, active).instructions.push(IrInstruction::Destroy { operand: lowered.operand.clone() });
        LoweredExpr { operand: lowered.operand, current: Some(active) }
    }

    fn lower_transfer_expr(
        &mut self,
        transfer: &TransferExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let lowered_expr = self.lower_expr(&transfer.expr, current, blocks, vars);
        let Some(active) = lowered_expr.current else {
            return lowered_expr;
        };
        let lowered_to = self.lower_expr(&transfer.to, active, blocks, vars);
        let Some(active) = lowered_to.current else {
            return lowered_to;
        };

        let dest_ty = self.operand_type(&lowered_expr.operand);
        let dest = self.new_var("transfer_tmp", dest_ty);
        let transfer_output_fields = self.materialize_matching_output_fields(&lowered_expr.operand, &dest.ty, active, blocks);
        self.block_mut(blocks, active).instructions.push(IrInstruction::Transfer {
            dest: dest.clone(),
            operand: lowered_expr.operand,
            to: lowered_to.operand,
        });
        if !transfer_output_fields.is_empty() {
            self.aggregate_fields.insert(dest.id, transfer_output_fields);
        }
        LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) }
    }

    fn lower_read_ref_expr(&mut self, read_ref: &ReadRefExpr, current: BlockId, blocks: &mut Vec<IrBlock>) -> LoweredExpr {
        let dest = self.new_var(format!("read_ref_{}", read_ref.ty), IrType::Ref(Box::new(IrType::Named(read_ref.ty.clone()))));
        self.block_mut(blocks, current).instructions.push(IrInstruction::ReadRef { dest: dest.clone(), ty: read_ref.ty.clone() });
        LoweredExpr { operand: IrOperand::Var(dest), current: Some(current) }
    }

    fn lower_claim_expr(
        &mut self,
        claim: &ClaimExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let lowered_receipt = self.lower_expr(&claim.receipt, current, blocks, vars);
        let Some(active) = lowered_receipt.current else {
            return lowered_receipt;
        };
        let dest_ty = self.claim_output_type_for_operand(&lowered_receipt.operand);
        let dest = self.new_var("claim_tmp", dest_ty);
        let claim_output_fields = self.materialize_matching_output_fields(&lowered_receipt.operand, &dest.ty, active, blocks);
        self.block_mut(blocks, active)
            .instructions
            .push(IrInstruction::Claim { dest: dest.clone(), receipt: lowered_receipt.operand });
        if !claim_output_fields.is_empty() {
            self.aggregate_fields.insert(dest.id, claim_output_fields);
        }
        LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) }
    }

    fn lower_settle_expr(
        &mut self,
        settle: &SettleExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let lowered = self.lower_expr(&settle.expr, current, blocks, vars);
        let Some(active) = lowered.current else {
            return lowered;
        };
        let dest_ty = self.operand_type(&lowered.operand);
        let dest = self.new_var("settle_tmp", dest_ty);
        let settle_output_fields = self.materialize_matching_output_fields(&lowered.operand, &dest.ty, active, blocks);
        self.block_mut(blocks, active).instructions.push(IrInstruction::Settle { dest: dest.clone(), operand: lowered.operand });
        if !settle_output_fields.is_empty() {
            self.aggregate_fields.insert(dest.id, settle_output_fields);
        }
        LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) }
    }

    fn lower_index_expr(
        &mut self,
        index: &IndexExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let lowered_arr = self.lower_expr(&index.expr, current, blocks, vars);
        let Some(active) = lowered_arr.current else {
            return lowered_arr;
        };
        let lowered_idx = self.lower_expr(&index.index, active, blocks, vars);
        let Some(active) = lowered_idx.current else {
            return lowered_idx;
        };

        if let IrOperand::Var(arr_var) = &lowered_arr.operand {
            if let Some(elements) = self.aggregate_elements.get(&arr_var.id) {
                let Some(index_value) = const_usize_operand(&lowered_idx.operand) else {
                    self.record_error("local fixed-array indexing requires a compile-time constant index", index.span);
                    return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(active) };
                };
                let Some(element_var) = elements.get(index_value).cloned() else {
                    self.record_error(
                        format!("array index {} is out of bounds for local fixed array of length {}", index_value, elements.len()),
                        index.span,
                    );
                    return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(active) };
                };
                return LoweredExpr { operand: IrOperand::Var(element_var), current: Some(active) };
            }
        }

        let Some(result_ty) = self.index_result_type(&lowered_arr.operand) else {
            self.record_error("index expression has no lowered element type", index.span);
            return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(active) };
        };

        let dest = self.new_var("index_tmp", result_ty);
        self.block_mut(blocks, active).instructions.push(IrInstruction::Index {
            dest: dest.clone(),
            arr: lowered_arr.operand,
            idx: lowered_idx.operand,
        });
        LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) }
    }

    fn lower_array_expr(
        &mut self,
        items: &[Expr],
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        if items.is_empty() {
            self.record_error("empty array literal reached IR lowering without a declared array type", Span::default());
            return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(current) };
        }

        let mut active = current;
        let mut elements = Vec::with_capacity(items.len());
        let mut element_ty = None;

        for (index, item) in items.iter().enumerate() {
            let lowered = self.lower_expr(item, active, blocks, vars);
            let Some(next) = lowered.current else {
                return lowered;
            };
            active = next;

            let ty = match &lowered.operand {
                IrOperand::Var(var) => var.ty.clone(),
                IrOperand::Const(value) => self.const_type(value),
            };
            element_ty.get_or_insert_with(|| ty.clone());
            let element_var = self.new_var(format!("array_elem_{}", index), ty);
            self.block_mut(blocks, active)
                .instructions
                .push(IrInstruction::Move { dest: element_var.clone(), src: lowered.operand.clone() });
            self.copy_aggregate_metadata(&lowered.operand, element_var.id);
            elements.push(element_var);
        }

        let Some(element_ty) = element_ty else {
            self.record_error("non-empty array literal did not produce an element type during IR lowering", Span::default());
            return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(active) };
        };
        let array_ty = IrType::Array(Box::new(element_ty), items.len());
        let aggregate = self.new_var("array_tmp", array_ty);
        self.block_mut(blocks, active)
            .instructions
            .push(IrInstruction::Move { dest: aggregate.clone(), src: IrOperand::Const(IrConst::U64(0)) });
        self.aggregate_elements.insert(aggregate.id, elements);
        LoweredExpr { operand: IrOperand::Var(aggregate), current: Some(active) }
    }

    fn lower_empty_array_expr_with_type(&mut self, declared_ty: &Type, current: BlockId, blocks: &mut Vec<IrBlock>) -> LoweredExpr {
        let ir_ty = Self::convert_type(declared_ty);
        if !matches!(ir_ty, IrType::Array(_, 0)) {
            self.record_error("empty array literal requires a zero-length declared array type", Span::default());
            return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(current) };
        }

        let aggregate = self.new_var("array_tmp", ir_ty);
        self.block_mut(blocks, current)
            .instructions
            .push(IrInstruction::Move { dest: aggregate.clone(), src: IrOperand::Const(IrConst::U64(0)) });
        self.aggregate_elements.insert(aggregate.id, Vec::new());
        LoweredExpr { operand: IrOperand::Var(aggregate), current: Some(current) }
    }

    fn lower_tuple_expr(
        &mut self,
        items: &[Expr],
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let mut active = current;
        let mut fields = HashMap::new();
        let mut types = Vec::with_capacity(items.len());

        for (index, item) in items.iter().enumerate() {
            let lowered = self.lower_expr(item, active, blocks, vars);
            let Some(next) = lowered.current else {
                return lowered;
            };
            active = next;

            let ty = match &lowered.operand {
                IrOperand::Var(var) => var.ty.clone(),
                IrOperand::Const(value) => self.const_type(value),
            };
            let field_var = self.new_var(format!("tuple_{}", index), ty.clone());
            self.block_mut(blocks, active)
                .instructions
                .push(IrInstruction::Move { dest: field_var.clone(), src: lowered.operand.clone() });
            self.copy_aggregate_metadata(&lowered.operand, field_var.id);
            fields.insert(index.to_string(), field_var);
            types.push(ty);
        }

        let aggregate = self.new_var("tuple_tmp", IrType::Tuple(types));
        let fields_for_instruction =
            (0..items.len()).filter_map(|index| fields.get(&index.to_string()).cloned().map(IrOperand::Var)).collect::<Vec<_>>();
        self.block_mut(blocks, active)
            .instructions
            .push(IrInstruction::Tuple { dest: aggregate.clone(), fields: fields_for_instruction });
        self.aggregate_fields.insert(aggregate.id, fields);
        LoweredExpr { operand: IrOperand::Var(aggregate), current: Some(active) }
    }

    fn lower_struct_init(
        &mut self,
        init: &StructInitExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let aggregate = self.new_var("struct_tmp", IrType::Named(init.ty.clone()));
        let mut field_map = HashMap::new();
        let mut tuple_operands = Vec::new();
        let mut active = current;

        for (field_name, field_expr) in &init.fields {
            let lowered = self.lower_expr(field_expr, active, blocks, vars);
            let Some(next) = lowered.current else {
                return lowered;
            };
            active = next;

            let field_ty = match &lowered.operand {
                IrOperand::Var(var) => var.ty.clone(),
                IrOperand::Const(value) => self.const_type(value),
            };
            let field_var = self.new_var(format!("{}_{}", init.ty, field_name), field_ty);
            tuple_operands.push(lowered.operand.clone());
            self.block_mut(blocks, active).instructions.push(IrInstruction::Move { dest: field_var.clone(), src: lowered.operand });
            field_map.insert(field_name.clone(), field_var);
        }

        self.block_mut(blocks, active).instructions.push(IrInstruction::Tuple { dest: aggregate.clone(), fields: tuple_operands });
        self.aggregate_fields.insert(aggregate.id, field_map);
        LoweredExpr { operand: IrOperand::Var(aggregate), current: Some(active) }
    }

    fn lower_field_access(
        &mut self,
        field: &FieldAccessExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let lowered_base = self.lower_expr(&field.expr, current, blocks, vars);
        let Some(active) = lowered_base.current else {
            return lowered_base;
        };

        if let IrOperand::Var(base_var) = &lowered_base.operand {
            if let Some(fields) = self.aggregate_fields.get(&base_var.id) {
                if let Some(field_var) = fields.get(&field.field) {
                    return LoweredExpr { operand: IrOperand::Var(field_var.clone()), current: Some(active) };
                }
            }

            if let Some(field_var) = self.materialize_schema_field(base_var, &field.field, active, blocks) {
                return LoweredExpr { operand: IrOperand::Var(field_var), current: Some(active) };
            }
        }

        self.record_error(format!("field access '.{}' has no lowered schema-backed representation", field.field), field.span);
        LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(active) }
    }

    fn lower_field_assign(
        &mut self,
        field: &FieldAccessExpr,
        op: AssignOp,
        value_expr: &Expr,
        value: IrOperand,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let lowered_base = self.lower_expr(&field.expr, current, blocks, vars);
        let Some(active) = lowered_base.current else {
            return lowered_base;
        };

        let Some(base_var) = (match lowered_base.operand {
            IrOperand::Var(var) => Some(var),
            IrOperand::Const(_) => None,
        }) else {
            return LoweredExpr { operand: value, current: Some(active) };
        };

        let field_var = self
            .aggregate_fields
            .get(&base_var.id)
            .and_then(|fields| fields.get(&field.field))
            .cloned()
            .or_else(|| self.materialize_schema_field(&base_var, &field.field, active, blocks));
        let Some(field_var) = field_var else {
            self.record_error(format!("field assignment '.{}' has no lowered schema-backed representation", field.field), field.span);
            return LoweredExpr { operand: value, current: Some(active) };
        };
        self.mutated_fields.entry(base_var.id).or_default().insert(field.field.clone());
        if let Some(transition) = self.mutate_transition_from_assignment(field, op, value_expr, &value, vars) {
            self.mutated_field_transitions.entry(base_var.id).or_default().insert(field.field.clone(), transition);
        }

        match op {
            AssignOp::Assign => {
                self.block_mut(blocks, active).instructions.push(IrInstruction::Move { dest: field_var.clone(), src: value });
            }
            AssignOp::AddAssign => {
                let tmp = self.new_var("field_assign_tmp", field_var.ty.clone());
                let block = self.block_mut(blocks, active);
                block.instructions.push(IrInstruction::Binary {
                    dest: tmp.clone(),
                    op: BinaryOp::Add,
                    left: IrOperand::Var(field_var.clone()),
                    right: value,
                });
                block.instructions.push(IrInstruction::Move { dest: field_var.clone(), src: IrOperand::Var(tmp) });
            }
        }

        LoweredExpr { operand: IrOperand::Var(field_var), current: Some(active) }
    }

    fn mutate_transition_from_assignment(
        &self,
        target: &FieldAccessExpr,
        assign_op: AssignOp,
        value_expr: &Expr,
        value_operand: &IrOperand,
        vars: &HashMap<String, IrVar>,
    ) -> Option<MutateFieldTransition> {
        let (target_root, target_field) = direct_field_access_root(target)?;
        let (op, operand) = match assign_op {
            AssignOp::AddAssign => (
                MutateTransitionOp::Add,
                self.transition_operand_from_expr(value_expr, vars)
                    .or_else(|| self.transition_expr_is_coverable_u64(value_expr, vars).then_some(value_operand.clone()))?,
            ),
            AssignOp::Assign => match value_expr {
                Expr::Binary(binary) if matches!(binary.op, BinaryOp::Add | BinaryOp::Sub) => {
                    let left_is_old = same_direct_field_access(&binary.left, target_root, target_field);
                    let right_is_old = same_direct_field_access(&binary.right, target_root, target_field);
                    match (binary.op, left_is_old, right_is_old) {
                        (BinaryOp::Add, true, false) => {
                            (MutateTransitionOp::Add, self.transition_operand_from_expr(&binary.right, vars)?)
                        }
                        (BinaryOp::Add, false, true) => {
                            (MutateTransitionOp::Add, self.transition_operand_from_expr(&binary.left, vars)?)
                        }
                        (BinaryOp::Sub, true, false) => {
                            (MutateTransitionOp::Sub, self.transition_operand_from_expr(&binary.right, vars)?)
                        }
                        _ => return None,
                    }
                }
                _ => (MutateTransitionOp::Set, self.transition_operand_from_expr(value_expr, vars)?),
            },
        };
        Some(MutateFieldTransition { field: target_field.to_string(), op, operand })
    }

    fn transition_operand_from_expr(&self, expr: &Expr, vars: &HashMap<String, IrVar>) -> Option<IrOperand> {
        match expr {
            Expr::Identifier(name) => vars
                .get(name)
                .filter(|var| self.transition_param_ids.contains(&var.id) || self.transition_coverable_value_ids.contains(&var.id))
                .cloned()
                .map(IrOperand::Var),
            Expr::Integer(value) => Some(IrOperand::Const(IrConst::U64(*value))),
            Expr::FieldAccess(field) => {
                let (root, field_name) = direct_field_access_root(field)?;
                let root_var = vars.get(root)?;
                if !self.transition_param_ids.contains(&root_var.id) {
                    return None;
                }
                self.aggregate_fields.get(&root_var.id)?.get(field_name).cloned().map(IrOperand::Var)
            }
            Expr::Cast(cast) => self.transition_operand_from_expr(&cast.expr, vars),
            _ => None,
        }
    }

    fn transition_expr_is_coverable_u64(&self, expr: &Expr, vars: &HashMap<String, IrVar>) -> bool {
        match expr {
            Expr::Identifier(name) => vars.get(name).is_some_and(|var| {
                var.ty == IrType::U64
                    && (self.transition_param_ids.contains(&var.id) || self.transition_coverable_value_ids.contains(&var.id))
            }),
            Expr::Integer(_) => true,
            Expr::FieldAccess(field) => {
                let Some((root, field_name)) = direct_field_access_root(field) else {
                    return false;
                };
                let Some(root_var) = vars.get(root) else {
                    return false;
                };
                self.transition_param_ids.contains(&root_var.id)
                    && self
                        .lookup_field_ir_type(&root_var.ty, field_name)
                        .is_some_and(|ty| matches!(ty, IrType::U8 | IrType::U16 | IrType::U32 | IrType::U64))
            }
            Expr::Cast(cast) => self.transition_expr_is_coverable_u64(&cast.expr, vars),
            Expr::Call(call) if call.args.is_empty() => match call.func.as_ref() {
                Expr::FieldAccess(field) if field.field == "len" => match field.expr.as_ref() {
                    Expr::Identifier(name) => vars.get(name).is_some_and(|var| {
                        (matches!(&var.ty, IrType::Named(type_name) if type_name == "String" || type_name.starts_with("Vec<"))
                            || matches!(&var.ty, IrType::Array(_, _)))
                            && (self.transition_param_ids.contains(&var.id) || self.transition_coverable_value_ids.contains(&var.id))
                    }),
                    _ => false,
                },
                _ => false,
            },
            Expr::Binary(binary) if matches!(binary.op, BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div) => {
                self.transition_expr_is_coverable_u64(&binary.left, vars) && self.transition_expr_is_coverable_u64(&binary.right, vars)
            }
            Expr::Call(call) if call.args.len() == 2 && call_target_is_min(call.func.as_ref()) => {
                call.args.iter().all(|arg| self.transition_expr_is_coverable_u64(arg, vars))
            }
            _ => false,
        }
    }

    fn lower_index_assign(
        &mut self,
        index: &IndexExpr,
        op: AssignOp,
        value: IrOperand,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let lowered_arr = self.lower_expr(&index.expr, current, blocks, vars);
        let Some(active) = lowered_arr.current else {
            return lowered_arr;
        };
        let lowered_idx = self.lower_expr(&index.index, active, blocks, vars);
        let Some(active) = lowered_idx.current else {
            return lowered_idx;
        };

        let Some(arr_var) = (match lowered_arr.operand {
            IrOperand::Var(var) => Some(var),
            IrOperand::Const(_) => None,
        }) else {
            self.record_error("index assignment requires a local fixed-array value", index.span);
            return LoweredExpr { operand: value, current: Some(active) };
        };
        let Some(index_value) = const_usize_operand(&lowered_idx.operand) else {
            self.record_error("local fixed-array assignment requires a compile-time constant index", index.span);
            return LoweredExpr { operand: value, current: Some(active) };
        };
        let Some(elements) = self.aggregate_elements.get(&arr_var.id) else {
            self.record_error("index assignment requires a local fixed-array value with lowered element slots", index.span);
            return LoweredExpr { operand: value, current: Some(active) };
        };
        let Some(element_var) = elements.get(index_value).cloned() else {
            self.record_error(
                format!("array index {} is out of bounds for local fixed array of length {}", index_value, elements.len()),
                index.span,
            );
            return LoweredExpr { operand: value, current: Some(active) };
        };

        match op {
            AssignOp::Assign => {
                self.block_mut(blocks, active).instructions.push(IrInstruction::Move { dest: element_var.clone(), src: value });
            }
            AssignOp::AddAssign => {
                let tmp = self.new_var("index_assign_tmp", element_var.ty.clone());
                let block = self.block_mut(blocks, active);
                block.instructions.push(IrInstruction::Binary {
                    dest: tmp.clone(),
                    op: BinaryOp::Add,
                    left: IrOperand::Var(element_var.clone()),
                    right: value,
                });
                block.instructions.push(IrInstruction::Move { dest: element_var.clone(), src: IrOperand::Var(tmp) });
            }
        }

        LoweredExpr { operand: IrOperand::Var(element_var), current: Some(active) }
    }

    fn lower_if_expr(
        &mut self,
        if_expr: &IfExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let lowered_cond = self.lower_expr(&if_expr.condition, current, blocks, vars);
        let cond = lowered_cond.operand;
        let Some(current) = lowered_cond.current else {
            return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: None };
        };

        let then_block = self.push_block(blocks);
        let else_block = self.push_block(blocks);
        self.block_mut(blocks, current).terminator = IrTerminator::Branch { cond, then_block, else_block };

        let mut then_vars = vars.clone();
        let then_lowered = self.lower_expr(&if_expr.then_branch, then_block, blocks, &mut then_vars);
        let mut else_vars = vars.clone();
        let else_lowered = self.lower_expr(&if_expr.else_branch, else_block, blocks, &mut else_vars);

        if then_lowered.current.is_none() && else_lowered.current.is_none() {
            return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: None };
        }

        let result_ty = match (then_lowered.current.is_some(), else_lowered.current.is_some()) {
            (true, _) => self.operand_type(&then_lowered.operand),
            (false, true) => self.operand_type(&else_lowered.operand),
            (false, false) => return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: None },
        };
        let dest = self.new_var("if_tmp", result_ty);
        let join = self.push_block(blocks);

        if let Some(exit) = then_lowered.current {
            let block = self.block_mut(blocks, exit);
            block.instructions.push(IrInstruction::Move { dest: dest.clone(), src: then_lowered.operand });
            block.terminator = IrTerminator::Jump(join);
        }

        if let Some(exit) = else_lowered.current {
            let block = self.block_mut(blocks, exit);
            block.instructions.push(IrInstruction::Move { dest: dest.clone(), src: else_lowered.operand });
            block.terminator = IrTerminator::Jump(join);
        }

        LoweredExpr { operand: IrOperand::Var(dest), current: Some(join) }
    }

    fn lower_match_expr(
        &mut self,
        match_expr: &MatchExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let lowered_scrutinee = self.lower_expr(&match_expr.expr, current, blocks, vars);
        let Some(mut check_block) = lowered_scrutinee.current else {
            return lowered_scrutinee;
        };

        if match_expr.arms.is_empty() {
            self.record_error("match expression reached IR lowering without arms", match_expr.span);
            return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(check_block) };
        }

        let mut arm_entries = Vec::with_capacity(match_expr.arms.len());
        for _ in &match_expr.arms {
            arm_entries.push(self.push_block(blocks));
        }
        let join = self.push_block(blocks);
        let mut result_dest: Option<IrVar> = None;

        for (index, arm) in match_expr.arms.iter().enumerate() {
            let arm_entry = arm_entries[index];
            if arm.pattern == "_" {
                self.block_mut(blocks, check_block).terminator = IrTerminator::Jump(arm_entry);
            } else {
                let Some(pattern_operand) = self.lower_match_pattern_operand(&arm.pattern, arm.span) else {
                    return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(check_block) };
                };

                let cond_var = self.new_var("match_cond", IrType::Bool);
                {
                    let block = self.block_mut(blocks, check_block);
                    block.instructions.push(IrInstruction::Binary {
                        dest: cond_var.clone(),
                        op: BinaryOp::Eq,
                        left: lowered_scrutinee.operand.clone(),
                        right: pattern_operand,
                    });
                }

                let else_block = if index + 1 < match_expr.arms.len() {
                    self.push_block(blocks)
                } else {
                    let fail_block = self.push_block(blocks);
                    self.block_mut(blocks, fail_block).terminator = IrTerminator::Return(Some(IrOperand::Const(IrConst::U64(8))));
                    fail_block
                };
                self.block_mut(blocks, check_block).terminator =
                    IrTerminator::Branch { cond: IrOperand::Var(cond_var), then_block: arm_entry, else_block };
                check_block = else_block;
            }

            let mut arm_vars = vars.clone();
            let lowered_value = self.lower_expr(&arm.value, arm_entry, blocks, &mut arm_vars);
            let Some(arm_exit) = lowered_value.current else {
                continue;
            };

            if result_dest.is_none() {
                let ty = self.operand_type(&lowered_value.operand);
                result_dest = Some(self.new_var("match_tmp", ty));
            }
            let dest = result_dest.as_ref().expect("match result destination must be initialized");
            let block = self.block_mut(blocks, arm_exit);
            block.instructions.push(IrInstruction::Move { dest: dest.clone(), src: lowered_value.operand });
            block.terminator = IrTerminator::Jump(join);
        }

        let Some(dest) = result_dest else {
            return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(join) };
        };
        LoweredExpr { operand: IrOperand::Var(dest), current: Some(join) }
    }

    fn operand_type(&self, operand: &IrOperand) -> IrType {
        match operand {
            IrOperand::Var(var) => var.ty.clone(),
            IrOperand::Const(value) => self.const_type(value),
        }
    }

    fn try_lower_builtin_call(
        &mut self,
        call: &CallExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> Option<LoweredExpr> {
        match call.func.as_ref() {
            Expr::Identifier(name) => match name.as_str() {
                "Address::zero" if call.args.is_empty() => {
                    Some(LoweredExpr { operand: IrOperand::Const(IrConst::Address([0; 32])), current: Some(current) })
                }
                "Hash::zero" if call.args.is_empty() => {
                    Some(LoweredExpr { operand: IrOperand::Const(IrConst::Hash([0; 32])), current: Some(current) })
                }
                "env::current_daa_score" if call.args.is_empty() => {
                    let dest = self.new_var("current_daa_score", IrType::U64);
                    self.block_mut(blocks, current).instructions.push(IrInstruction::Call {
                        dest: Some(dest.clone()),
                        func: "__env_current_daa_score".to_string(),
                        args: Vec::new(),
                    });
                    Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(current) })
                }
                "env::current_timepoint" if call.args.is_empty() => {
                    let dest = self.new_var("current_timepoint", IrType::U64);
                    self.block_mut(blocks, current).instructions.push(IrInstruction::Call {
                        dest: Some(dest.clone()),
                        func: "__env_current_timepoint".to_string(),
                        args: Vec::new(),
                    });
                    Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(current) })
                }
                "ckb::header_epoch_number" if call.args.is_empty() => {
                    let dest = self.new_var("ckb_header_epoch_number", IrType::U64);
                    self.block_mut(blocks, current).instructions.push(IrInstruction::Call {
                        dest: Some(dest.clone()),
                        func: "__ckb_header_epoch_number".to_string(),
                        args: Vec::new(),
                    });
                    Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(current) })
                }
                "ckb::header_epoch_start_block_number" if call.args.is_empty() => {
                    let dest = self.new_var("ckb_header_epoch_start_block_number", IrType::U64);
                    self.block_mut(blocks, current).instructions.push(IrInstruction::Call {
                        dest: Some(dest.clone()),
                        func: "__ckb_header_epoch_start_block_number".to_string(),
                        args: Vec::new(),
                    });
                    Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(current) })
                }
                "ckb::header_epoch_length" if call.args.is_empty() => {
                    let dest = self.new_var("ckb_header_epoch_length", IrType::U64);
                    self.block_mut(blocks, current).instructions.push(IrInstruction::Call {
                        dest: Some(dest.clone()),
                        func: "__ckb_header_epoch_length".to_string(),
                        args: Vec::new(),
                    });
                    Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(current) })
                }
                "ckb::input_since" if call.args.is_empty() => {
                    let dest = self.new_var("ckb_input_since", IrType::U64);
                    self.block_mut(blocks, current).instructions.push(IrInstruction::Call {
                        dest: Some(dest.clone()),
                        func: "__ckb_input_since".to_string(),
                        args: Vec::new(),
                    });
                    Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(current) })
                }
                "Vec::new" if call.args.is_empty() => {
                    let dest = self.new_var("vec_new_tmp", IrType::Named("Vec".to_string()));
                    self.block_mut(blocks, current).instructions.push(IrInstruction::CollectionNew {
                        dest: dest.clone(),
                        ty: "Vec".to_string(),
                        capacity: None,
                    });
                    Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(current) })
                }
                "Vec::with_capacity" if call.args.len() == 1 => {
                    let lowered_capacity = self.lower_expr(&call.args[0], current, blocks, vars);
                    let active = lowered_capacity.current?;
                    let dest = self.new_var("vec_with_capacity_tmp", IrType::Named("Vec".to_string()));
                    self.block_mut(blocks, active).instructions.push(IrInstruction::CollectionNew {
                        dest: dest.clone(),
                        ty: "Vec".to_string(),
                        capacity: Some(lowered_capacity.operand),
                    });
                    Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) })
                }
                _ => None,
            },
            Expr::FieldAccess(field) => match field.field.as_str() {
                "len" if call.args.is_empty() => {
                    let lowered = self.lower_expr(&field.expr, current, blocks, vars);
                    let active = lowered.current?;
                    if let IrOperand::Var(var) = &lowered.operand {
                        if let Some(elements) = self.aggregate_elements.get(&var.id) {
                            return Some(LoweredExpr {
                                operand: IrOperand::Const(IrConst::U64(elements.len() as u64)),
                                current: Some(active),
                            });
                        }
                    }
                    let dest = self.new_var("len_tmp", IrType::U64);
                    self.block_mut(blocks, active)
                        .instructions
                        .push(IrInstruction::Length { dest: dest.clone(), operand: lowered.operand });
                    Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) })
                }
                "is_empty" if call.args.is_empty() => {
                    let lowered = self.lower_expr(&field.expr, current, blocks, vars);
                    let active = lowered.current?;
                    if let IrOperand::Var(var) = &lowered.operand {
                        if let Some(elements) = self.aggregate_elements.get(&var.id) {
                            return Some(LoweredExpr {
                                operand: IrOperand::Const(IrConst::Bool(elements.is_empty())),
                                current: Some(active),
                            });
                        }
                    }
                    let len_dest = self.new_var("is_empty_len_tmp", IrType::U64);
                    let dest = self.new_var("is_empty_tmp", IrType::Bool);
                    let block = self.block_mut(blocks, active);
                    block.instructions.push(IrInstruction::Length { dest: len_dest.clone(), operand: lowered.operand });
                    block.instructions.push(IrInstruction::Binary {
                        dest: dest.clone(),
                        op: BinaryOp::Eq,
                        left: IrOperand::Var(len_dest),
                        right: IrOperand::Const(IrConst::U64(0)),
                    });
                    Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) })
                }
                "type_hash" if call.args.is_empty() => {
                    let lowered = self.lower_expr(&field.expr, current, blocks, vars);
                    let active = lowered.current?;
                    let dest = self.new_var("type_hash_tmp", IrType::Hash);
                    self.block_mut(blocks, active)
                        .instructions
                        .push(IrInstruction::TypeHash { dest: dest.clone(), operand: lowered.operand });
                    Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) })
                }
                "push" if call.args.len() == 1 => {
                    let lowered_collection = self.lower_expr(&field.expr, current, blocks, vars);
                    let active = lowered_collection.current?;
                    let lowered_value = self.lower_expr(&call.args[0], active, blocks, vars);
                    let active = lowered_value.current?;
                    let collection_operand = lowered_collection.operand;
                    if let (Expr::Identifier(receiver_name), IrOperand::Var(collection_var)) =
                        (field.expr.as_ref(), &collection_operand)
                    {
                        if matches!(&collection_var.ty, IrType::Named(name) if name == "Vec") {
                            if let (Some(item_ty), Some(receiver_var)) =
                                (inline_ir_type_repr(&self.operand_type(&lowered_value.operand)), vars.get_mut(receiver_name))
                            {
                                if receiver_var.id == collection_var.id {
                                    receiver_var.ty = IrType::Named(format!("Vec<{}>", item_ty));
                                }
                            }
                        }
                    }
                    let block = self.block_mut(blocks, active);
                    block.instructions.push(IrInstruction::CollectionPush {
                        collection: collection_operand.clone(),
                        value: lowered_value.operand.clone(),
                    });
                    if let IrOperand::Var(collection_var) = &collection_operand {
                        if let Some((root_id, field_name)) = self.schema_field_roots.get(&collection_var.id).cloned() {
                            self.mutated_fields.entry(root_id).or_default().insert(field_name.clone());
                            self.mutated_field_transitions.entry(root_id).or_default().insert(
                                field_name.clone(),
                                MutateFieldTransition {
                                    field: field_name,
                                    op: MutateTransitionOp::Append,
                                    operand: lowered_value.operand,
                                },
                            );
                        }
                    }
                    Some(LoweredExpr { operand: IrOperand::Const(IrConst::Bool(true)), current: Some(active) })
                }
                "clear" if call.args.is_empty() => {
                    let lowered_collection = self.lower_expr(&field.expr, current, blocks, vars);
                    let active = lowered_collection.current?;
                    self.block_mut(blocks, active)
                        .instructions
                        .push(IrInstruction::CollectionClear { collection: lowered_collection.operand });
                    Some(LoweredExpr { operand: IrOperand::Const(IrConst::Bool(true)), current: Some(active) })
                }
                "contains" if call.args.len() == 1 => {
                    let lowered_collection = self.lower_expr(&field.expr, current, blocks, vars);
                    let active = lowered_collection.current?;
                    let lowered_value = self.lower_expr(&call.args[0], active, blocks, vars);
                    let active = lowered_value.current?;
                    let collection_operand = lowered_collection.operand;
                    if let (Expr::Identifier(receiver_name), IrOperand::Var(collection_var)) =
                        (field.expr.as_ref(), &collection_operand)
                    {
                        if matches!(&collection_var.ty, IrType::Named(name) if name == "Vec") {
                            if let (Some(item_ty), Some(receiver_var)) =
                                (inline_ir_type_repr(&self.operand_type(&lowered_value.operand)), vars.get_mut(receiver_name))
                            {
                                if receiver_var.id == collection_var.id {
                                    receiver_var.ty = IrType::Named(format!("Vec<{}>", item_ty));
                                }
                            }
                        }
                    }
                    let dest = self.new_var("contains_tmp", IrType::Bool);
                    self.block_mut(blocks, active).instructions.push(IrInstruction::CollectionContains {
                        dest: dest.clone(),
                        collection: collection_operand,
                        value: lowered_value.operand,
                    });
                    Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) })
                }
                "remove" if call.args.len() == 1 => {
                    let lowered_collection = self.lower_expr(&field.expr, current, blocks, vars);
                    let active = lowered_collection.current?;
                    let lowered_index = self.lower_expr(&call.args[0], active, blocks, vars);
                    let active = lowered_index.current?;
                    let item_ty = collection_item_ir_type(&self.operand_type(&lowered_collection.operand)).unwrap_or(IrType::U64);
                    let dest = self.new_var("remove_tmp", item_ty);
                    self.block_mut(blocks, active).instructions.push(IrInstruction::CollectionRemove {
                        dest: dest.clone(),
                        collection: lowered_collection.operand,
                        index: lowered_index.operand,
                    });
                    Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) })
                }
                "pop" if call.args.is_empty() => {
                    let lowered_collection = self.lower_expr(&field.expr, current, blocks, vars);
                    let active = lowered_collection.current?;
                    let item_ty = collection_item_ir_type(&self.operand_type(&lowered_collection.operand)).unwrap_or(IrType::U64);
                    let dest = self.new_var("pop_tmp", item_ty);
                    self.block_mut(blocks, active)
                        .instructions
                        .push(IrInstruction::CollectionPop { dest: dest.clone(), collection: lowered_collection.operand });
                    Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) })
                }
                "insert" if call.args.len() == 2 => {
                    let lowered_collection = self.lower_expr(&field.expr, current, blocks, vars);
                    let active = lowered_collection.current?;
                    let lowered_index = self.lower_expr(&call.args[0], active, blocks, vars);
                    let active = lowered_index.current?;
                    let lowered_value = self.lower_expr(&call.args[1], active, blocks, vars);
                    let active = lowered_value.current?;
                    let collection_operand = lowered_collection.operand;
                    if let (Expr::Identifier(receiver_name), IrOperand::Var(collection_var)) =
                        (field.expr.as_ref(), &collection_operand)
                    {
                        if matches!(&collection_var.ty, IrType::Named(name) if name == "Vec") {
                            if let (Some(item_ty), Some(receiver_var)) =
                                (inline_ir_type_repr(&self.operand_type(&lowered_value.operand)), vars.get_mut(receiver_name))
                            {
                                if receiver_var.id == collection_var.id {
                                    receiver_var.ty = IrType::Named(format!("Vec<{}>", item_ty));
                                }
                            }
                        }
                    }
                    self.block_mut(blocks, active).instructions.push(IrInstruction::CollectionInsert {
                        collection: collection_operand,
                        index: lowered_index.operand,
                        value: lowered_value.operand,
                    });
                    Some(LoweredExpr { operand: IrOperand::Const(IrConst::Bool(true)), current: Some(active) })
                }
                "extend_from_slice" if call.args.len() == 1 => {
                    let lowered_collection = self.lower_expr(&field.expr, current, blocks, vars);
                    let active = lowered_collection.current?;
                    let lowered_slice = self.lower_expr(&call.args[0], active, blocks, vars);
                    let active = lowered_slice.current?;
                    let collection_operand = lowered_collection.operand;
                    if let (Expr::Identifier(receiver_name), IrOperand::Var(collection_var)) =
                        (field.expr.as_ref(), &collection_operand)
                    {
                        if matches!(&collection_var.ty, IrType::Named(name) if name == "Vec") {
                            if let (IrType::Array(inner, _), Some(receiver_var)) =
                                (self.operand_type(&lowered_slice.operand), vars.get_mut(receiver_name))
                            {
                                if receiver_var.id == collection_var.id {
                                    if let Some(item_ty) = inline_ir_type_repr(inner.as_ref()) {
                                        receiver_var.ty = IrType::Named(format!("Vec<{}>", item_ty));
                                    }
                                }
                            }
                        }
                    }
                    let block = self.block_mut(blocks, active);
                    block
                        .instructions
                        .push(IrInstruction::CollectionExtend { collection: collection_operand, slice: lowered_slice.operand });
                    Some(LoweredExpr { operand: IrOperand::Const(IrConst::Bool(true)), current: Some(active) })
                }
                _ => None,
            },
            _ => None,
        }
    }

    fn lower_match_pattern_operand(&mut self, pattern: &str, span: Span) -> Option<IrOperand> {
        if pattern == "_" {
            return Some(IrOperand::Const(IrConst::U64(0)));
        }
        if let Some(variant) = self.lower_enum_variant(pattern) {
            return Some(variant);
        }
        if let Some(constant) = self.lower_constant(pattern, span) {
            return Some(constant);
        }
        self.record_error(format!("match pattern '{}' is not supported by IR lowering", pattern), span);
        None
    }

    fn record_error(&mut self, message: impl Into<String>, span: Span) {
        self.errors.push(CompileError::new(message, span));
    }

    fn lower_constant(&mut self, name: &str, span: Span) -> Option<IrOperand> {
        let value = self.constants.get(name)?;
        match value {
            Expr::Integer(n) => Some(IrOperand::Const(IrConst::U64(*n))),
            Expr::Bool(b) => Some(IrOperand::Const(IrConst::Bool(*b))),
            Expr::ByteString(bytes) => {
                let items = bytes.iter().copied().map(IrConst::U8).collect::<Vec<_>>();
                Some(IrOperand::Const(IrConst::Array(items)))
            }
            _ => {
                self.record_error(format!("constant '{}' uses an expression IR lowering does not support", name), span);
                None
            }
        }
    }

    fn lower_zero_value(&self, name: &str) -> Option<IrOperand> {
        match name {
            "Address::zero" => Some(IrOperand::Const(IrConst::Address([0; 32]))),
            "Hash::zero" => Some(IrOperand::Const(IrConst::Hash([0; 32]))),
            _ => None,
        }
    }

    fn lower_enum_variant(&self, name: &str) -> Option<IrOperand> {
        let (enum_name, variant_name) = name.rsplit_once("::")?;
        let ordinal = self.enum_variants.get(enum_name)?.get(variant_name).copied()?;
        Some(IrOperand::Const(IrConst::U64(ordinal)))
    }

    fn lookup_field_ir_type(&self, ty: &IrType, field: &str) -> Option<IrType> {
        match ty {
            IrType::Tuple(items) => field.parse::<usize>().ok().and_then(|index| items.get(index)).cloned(),
            IrType::Named(name) => self.type_fields.get(name).and_then(|fields| fields.get(field)).cloned(),
            IrType::Ref(inner) | IrType::MutRef(inner) => self.lookup_field_ir_type(inner, field),
            IrType::Address | IrType::Hash if field == "0" => Some(IrType::Array(Box::new(IrType::U8), 32)),
            _ => None,
        }
    }

    fn index_result_type(&self, operand: &IrOperand) -> Option<IrType> {
        match operand {
            IrOperand::Var(var) => self.index_result_type_from_ir_type(&var.ty),
            IrOperand::Const(IrConst::Array(items)) => items.first().map(|item| self.const_type(item)),
            _ => None,
        }
    }

    fn index_result_type_from_ir_type(&self, ty: &IrType) -> Option<IrType> {
        match ty {
            IrType::Array(inner, _) => Some((**inner).clone()),
            IrType::Ref(inner) | IrType::MutRef(inner) => self.index_result_type_from_ir_type(inner),
            IrType::Named(name) => self.named_vec_item_type(name),
            _ => None,
        }
    }

    fn iter_item_type(&self, operand: &IrOperand) -> Option<IrType> {
        match operand {
            IrOperand::Var(var) => self.index_result_type_from_ir_type(&var.ty),
            IrOperand::Const(IrConst::Array(items)) => items.first().map(|item| self.const_type(item)),
            _ => None,
        }
    }

    fn named_vec_item_type(&self, name: &str) -> Option<IrType> {
        let inner = name.strip_prefix("Vec<")?.strip_suffix('>')?;
        Some(self.parse_inline_ir_type(inner))
    }

    fn parse_inline_ir_type(&self, ty: &str) -> IrType {
        match ty {
            "u8" => IrType::U8,
            "u16" => IrType::U16,
            "u32" => IrType::U32,
            "u64" => IrType::U64,
            "u128" => IrType::U128,
            "bool" => IrType::Bool,
            "Address" => IrType::Address,
            "Hash" => IrType::Hash,
            other => IrType::Named(other.to_string()),
        }
    }

    fn lower_call_target_name(&self, name: &str) -> String {
        if let Some((module, symbol)) = name.rsplit_once("::") {
            if module == self.module.name {
                return symbol.to_string();
            }
        }
        name.to_string()
    }

    fn call_return_type(&self, source_name: &str, lowered_name: &str) -> Option<Option<IrType>> {
        self.function_return_types
            .get(source_name)
            .or_else(|| self.function_return_types.get(lowered_name))
            .or_else(|| self.external_function_return_types.get(source_name))
            .or_else(|| self.external_function_return_types.get(lowered_name))
            .cloned()
    }

    fn materialize_schema_field(
        &mut self,
        base_var: &IrVar,
        field: &str,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
    ) -> Option<IrVar> {
        let field_ty = self.lookup_field_ir_type(&base_var.ty, field)?;
        let field_var = self.new_var(format!("{}_{}", base_var.name, field), field_ty);
        self.block_mut(blocks, current).instructions.push(IrInstruction::FieldAccess {
            dest: field_var.clone(),
            obj: IrOperand::Var(base_var.clone()),
            field: field.to_string(),
        });
        self.aggregate_fields.entry(base_var.id).or_default().insert(field.to_string(), field_var.clone());
        self.schema_field_roots.insert(field_var.id, (base_var.id, field.to_string()));
        Some(field_var)
    }

    fn copy_aggregate_metadata(&mut self, source: &IrOperand, dest_id: usize) {
        let IrOperand::Var(source_var) = source else {
            return;
        };
        if let Some(fields) = self.aggregate_fields.get(&source_var.id).cloned() {
            self.aggregate_fields.insert(dest_id, fields);
        }
        if let Some(root) = self.schema_field_roots.get(&source_var.id).cloned() {
            self.schema_field_roots.insert(dest_id, root);
        }
        if let Some(elements) = self.aggregate_elements.get(&source_var.id).cloned() {
            self.aggregate_elements.insert(dest_id, elements);
        }
    }
}

fn inline_ir_type_repr(ty: &IrType) -> Option<String> {
    match ty {
        IrType::U8 => Some("u8".to_string()),
        IrType::U16 => Some("u16".to_string()),
        IrType::U32 => Some("u32".to_string()),
        IrType::U64 => Some("u64".to_string()),
        IrType::U128 => Some("u128".to_string()),
        IrType::Bool => Some("bool".to_string()),
        IrType::Address => Some("Address".to_string()),
        IrType::Hash => Some("Hash".to_string()),
        IrType::Named(name) => Some(name.clone()),
        IrType::Unit | IrType::Array(_, _) | IrType::Tuple(_) | IrType::Ref(_) | IrType::MutRef(_) => None,
    }
}

fn collection_item_ir_type(ty: &IrType) -> Option<IrType> {
    let IrType::Named(name) = ty else {
        return None;
    };
    let inner = name.strip_prefix("Vec<")?.strip_suffix('>')?;
    Some(parse_inline_ir_type_repr(inner))
}

fn parse_inline_ir_type_repr(repr: &str) -> IrType {
    match repr.trim() {
        "u8" => IrType::U8,
        "u16" => IrType::U16,
        "u32" => IrType::U32,
        "u64" => IrType::U64,
        "u128" => IrType::U128,
        "bool" => IrType::Bool,
        "Address" => IrType::Address,
        "Hash" => IrType::Hash,
        other => IrType::Named(other.to_string()),
    }
}

pub fn generate(ast: &Module) -> Result<IrModule> {
    let generator = IrGenerator::new(ast.name.clone());
    generator.generate(ast)
}

pub fn generate_with_resolver(ast: &Module, resolver: &ModuleResolver, module_name: &str) -> Result<IrModule> {
    generate_with_resolver_inner(ast, resolver, module_name, true)
}

fn generate_with_resolver_inner(
    ast: &Module,
    resolver: &ModuleResolver,
    module_name: &str,
    include_external_callables: bool,
) -> Result<IrModule> {
    let mut type_fields = HashMap::new();
    let mut type_kinds = HashMap::new();
    let mut receipt_claim_outputs = HashMap::new();
    let mut external_type_defs = Vec::new();
    let mut external_type_names = HashSet::new();
    let mut external_callable_abis = Vec::new();
    let mut external_callable_names = HashSet::new();
    let mut external_function_effects = HashMap::new();
    let mut external_function_return_types = HashMap::new();

    for item in &ast.items {
        let Item::Use(use_stmt) = item else {
            continue;
        };

        for import in &use_stmt.imports {
            let local_name = import.alias.clone().unwrap_or_else(|| import.name.clone());
            if let Some(type_def) = resolver.resolve_type(module_name, &local_name) {
                if let Some(kind) = resolver_type_kind(&type_def) {
                    type_kinds.insert(local_name.clone(), kind);
                }
                if let Some(output) = resolver_receipt_claim_output_to_ir(&type_def) {
                    receipt_claim_outputs.insert(local_name.clone(), output);
                }
                if let Some(fields) = resolver_type_fields_to_ir(&type_def) {
                    type_fields.insert(local_name.clone(), fields);
                }
                if external_type_names.insert(local_name.clone()) {
                    if let Some(ir_type_def) = resolver_type_def_to_ir(&local_name, &type_def) {
                        external_type_defs.push(ir_type_def);
                    }
                }
            }
            if let Some(function) = resolver.resolve_function(module_name, &local_name) {
                external_function_effects.insert(local_name.clone(), function_def_effect_class(&function));
                external_function_return_types.insert(local_name.clone(), function_def_return_type(&function));
                push_external_callable_abi(&mut external_callable_abis, &mut external_callable_names, local_name, &function);
            }
        }
    }
    for call_name in collect_call_names(ast) {
        if let Some(function) = resolver.resolve_function(module_name, &call_name) {
            external_function_effects.insert(call_name.clone(), function_def_effect_class(&function));
            external_function_return_types.insert(call_name.clone(), function_def_return_type(&function));
            push_external_callable_abi(&mut external_callable_abis, &mut external_callable_names, call_name, &function);
        }
    }

    let generator = IrGenerator::with_import_context(
        ast.name.clone(),
        type_fields,
        type_kinds,
        receipt_claim_outputs,
        external_function_effects,
        external_function_return_types,
    );
    let mut ir = generator.generate(ast)?;
    ir.external_type_defs = external_type_defs;
    ir.external_callable_abis = external_callable_abis;
    if include_external_callables {
        append_external_callable_bodies(&mut ir, ast, resolver, module_name)?;
    }
    Ok(ir)
}

fn append_external_callable_bodies(ir: &mut IrModule, ast: &Module, resolver: &ModuleResolver, module_name: &str) -> Result<()> {
    let mut known_callables = ir_callable_names(ir);
    let mut imported_callables = HashSet::new();
    let mut pending = collect_call_names(ast).into_iter().collect::<Vec<_>>();

    while let Some(call_name) = pending.pop() {
        let symbol = call_name.rsplit("::").next().unwrap_or(&call_name).to_string();
        if known_callables.contains(&symbol) {
            continue;
        }

        let Some((owner_module, _)) = resolver.resolve_function_with_module(module_name, &call_name) else {
            continue;
        };
        let import_key = format!("{}::{}", owner_module, symbol);
        if owner_module == module_name || !imported_callables.insert(import_key) {
            continue;
        }

        let Some(owner_ast) = resolver.module(&owner_module) else {
            continue;
        };
        let external_ir = generate_with_resolver_inner(owner_ast, resolver, &owner_module, false)?;
        merge_external_type_defs(ir, &external_ir);
        merge_external_callable_abis(ir, &external_ir);
        for (name, size) in external_ir.enum_fixed_sizes {
            ir.enum_fixed_sizes.entry(name).or_insert(size);
        }

        if let Some(item) = external_ir.items.into_iter().find(|item| ir_item_callable_name(item).is_some_and(|name| name == symbol)) {
            if known_callables.insert(symbol) {
                collect_ir_item_call_names(&item, &mut pending);
                ir.items.push(item);
            }
        }
    }

    Ok(())
}

fn ir_callable_names(ir: &IrModule) -> HashSet<String> {
    ir.items.iter().filter_map(ir_item_callable_name).map(str::to_string).collect()
}

fn ir_item_callable_name(item: &IrItem) -> Option<&str> {
    match item {
        IrItem::Action(action) => Some(&action.name),
        IrItem::PureFn(function) => Some(&function.name),
        IrItem::Lock(lock) => Some(&lock.name),
        IrItem::TypeDef(_) => None,
    }
}

fn merge_external_type_defs(ir: &mut IrModule, external_ir: &IrModule) {
    let mut names = ir.external_type_defs.iter().map(|type_def| type_def.name.clone()).collect::<HashSet<_>>();
    for type_def in &external_ir.external_type_defs {
        if names.insert(type_def.name.clone()) {
            ir.external_type_defs.push(type_def.clone());
        }
    }
    for item in &external_ir.items {
        let IrItem::TypeDef(type_def) = item else {
            continue;
        };
        if names.insert(type_def.name.clone()) {
            ir.external_type_defs.push(type_def.clone());
        }
    }
}

fn merge_external_callable_abis(ir: &mut IrModule, external_ir: &IrModule) {
    let mut names = ir.external_callable_abis.iter().map(|abi| abi.name.clone()).collect::<HashSet<_>>();
    for abi in &external_ir.external_callable_abis {
        if names.insert(abi.name.clone()) {
            ir.external_callable_abis.push(abi.clone());
        }
    }
}

fn collect_ir_item_call_names(item: &IrItem, pending: &mut Vec<String>) {
    match item {
        IrItem::Action(action) => collect_ir_body_call_names(&action.body, pending),
        IrItem::PureFn(function) => collect_ir_body_call_names(&function.body, pending),
        IrItem::Lock(lock) => collect_ir_body_call_names(&lock.body, pending),
        IrItem::TypeDef(_) => {}
    }
}

fn collect_ir_body_call_names(body: &IrBody, pending: &mut Vec<String>) {
    for block in &body.blocks {
        for instruction in &block.instructions {
            if let IrInstruction::Call { func, .. } = instruction {
                pending.push(func.clone());
            }
        }
    }
}

fn push_external_callable_abi(
    external_callable_abis: &mut Vec<IrCallableAbi>,
    external_callable_names: &mut HashSet<String>,
    name: String,
    function: &FunctionDef,
) {
    if !external_callable_names.insert(name.clone()) {
        return;
    }
    external_callable_abis.push(IrCallableAbi {
        name,
        params: function_def_params(function),
        type_hash_param_indices: BTreeSet::new(),
    });
}

fn function_def_params(function: &FunctionDef) -> Vec<IrParam> {
    let params = match function {
        FunctionDef::Action(action) => &action.params,
        FunctionDef::Function(function) => &function.params,
        FunctionDef::Lock(lock) => &lock.params,
    };
    params
        .iter()
        .enumerate()
        .map(|(index, param)| {
            let ty = ast_type_to_ir(&param.ty);
            IrParam {
                name: param.name.clone(),
                ty: ty.clone(),
                is_mut: param.is_mut,
                is_ref: param.is_ref,
                is_read_ref: param.is_read_ref,
                binding: IrVar { id: index, name: param.name.clone(), ty },
            }
        })
        .collect()
}

fn collect_call_names(ast: &Module) -> HashSet<String> {
    let mut names = HashSet::new();
    for item in &ast.items {
        match item {
            Item::Action(action) => collect_call_names_from_stmts(&action.body, &mut names),
            Item::Function(function) => collect_call_names_from_stmts(&function.body, &mut names),
            Item::Lock(lock) => collect_call_names_from_stmts(&lock.body, &mut names),
            _ => {}
        }
    }
    names
}

fn collect_call_names_from_stmts(stmts: &[Stmt], names: &mut HashSet<String>) {
    for stmt in stmts {
        collect_call_names_from_stmt(stmt, names);
    }
}

fn collect_call_names_from_stmt(stmt: &Stmt, names: &mut HashSet<String>) {
    match stmt {
        Stmt::Expr(expr) | Stmt::Let(LetStmt { value: expr, .. }) | Stmt::Return(Some(expr)) => {
            collect_call_names_from_expr(expr, names);
        }
        Stmt::If(if_stmt) => {
            collect_call_names_from_expr(&if_stmt.condition, names);
            collect_call_names_from_stmts(&if_stmt.then_branch, names);
            if let Some(else_branch) = &if_stmt.else_branch {
                collect_call_names_from_stmts(else_branch, names);
            }
        }
        Stmt::For(for_stmt) => {
            collect_call_names_from_expr(&for_stmt.iterable, names);
            collect_call_names_from_stmts(&for_stmt.body, names);
        }
        Stmt::While(while_stmt) => {
            collect_call_names_from_expr(&while_stmt.condition, names);
            collect_call_names_from_stmts(&while_stmt.body, names);
        }
        Stmt::Return(None) => {}
    }
}

fn collect_call_names_from_expr(expr: &Expr, names: &mut HashSet<String>) {
    match expr {
        Expr::Call(call) => {
            if let Expr::Identifier(name) = call.func.as_ref() {
                names.insert(name.clone());
            }
            collect_call_names_from_expr(&call.func, names);
            for arg in &call.args {
                collect_call_names_from_expr(arg, names);
            }
        }
        Expr::Assign(assign) => {
            collect_call_names_from_expr(&assign.target, names);
            collect_call_names_from_expr(&assign.value, names);
        }
        Expr::Binary(binary) => {
            collect_call_names_from_expr(&binary.left, names);
            collect_call_names_from_expr(&binary.right, names);
        }
        Expr::Unary(unary) => collect_call_names_from_expr(&unary.expr, names),
        Expr::FieldAccess(field) => collect_call_names_from_expr(&field.expr, names),
        Expr::Index(index) => {
            collect_call_names_from_expr(&index.expr, names);
            collect_call_names_from_expr(&index.index, names);
        }
        Expr::Create(create) => {
            for (_, value) in &create.fields {
                collect_call_names_from_expr(value, names);
            }
            if let Some(lock) = &create.lock {
                collect_call_names_from_expr(lock, names);
            }
        }
        Expr::Consume(consume) => collect_call_names_from_expr(&consume.expr, names),
        Expr::Transfer(transfer) => {
            collect_call_names_from_expr(&transfer.expr, names);
            collect_call_names_from_expr(&transfer.to, names);
        }
        Expr::Destroy(destroy) => collect_call_names_from_expr(&destroy.expr, names),
        Expr::Claim(claim) => collect_call_names_from_expr(&claim.receipt, names),
        Expr::Settle(settle) => collect_call_names_from_expr(&settle.expr, names),
        Expr::Assert(assert_expr) => {
            collect_call_names_from_expr(&assert_expr.condition, names);
        }
        Expr::Block(stmts) => collect_call_names_from_stmts(stmts, names),
        Expr::Tuple(items) | Expr::Array(items) => {
            for item in items {
                collect_call_names_from_expr(item, names);
            }
        }
        Expr::If(if_expr) => {
            collect_call_names_from_expr(&if_expr.condition, names);
            collect_call_names_from_expr(&if_expr.then_branch, names);
            collect_call_names_from_expr(&if_expr.else_branch, names);
        }
        Expr::Cast(cast) => collect_call_names_from_expr(&cast.expr, names),
        Expr::Range(range) => {
            collect_call_names_from_expr(&range.start, names);
            collect_call_names_from_expr(&range.end, names);
        }
        Expr::StructInit(init) => {
            for (_, value) in &init.fields {
                collect_call_names_from_expr(value, names);
            }
        }
        Expr::Match(match_expr) => {
            collect_call_names_from_expr(&match_expr.expr, names);
            for arm in &match_expr.arms {
                collect_call_names_from_expr(&arm.value, names);
            }
        }
        Expr::Integer(_) | Expr::Bool(_) | Expr::String(_) | Expr::ByteString(_) | Expr::Identifier(_) | Expr::ReadRef(_) => {}
    }
}

fn function_def_effect_class(function: &FunctionDef) -> EffectClass {
    match function {
        FunctionDef::Action(action) => {
            if action.effect_declared {
                ast_effect_to_ir(action.effect)
            } else {
                infer_action_effect_without_call_graph(action)
            }
        }
        FunctionDef::Function(function) => infer_fn_effect_without_call_graph(function),
        FunctionDef::Lock(_) => EffectClass::ReadOnly,
    }
}

fn function_def_return_type(function: &FunctionDef) -> Option<IrType> {
    match function {
        FunctionDef::Action(action) => action.return_type.as_ref().map(ast_type_to_ir),
        FunctionDef::Function(function) => function.return_type.as_ref().map(ast_type_to_ir),
        FunctionDef::Lock(_) => Some(IrType::Bool),
    }
}

fn ast_type_to_ir(ty: &Type) -> IrType {
    match ty {
        Type::U8 => IrType::U8,
        Type::U16 => IrType::U16,
        Type::U32 => IrType::U32,
        Type::U64 => IrType::U64,
        Type::U128 => IrType::U128,
        Type::Bool => IrType::Bool,
        Type::Unit => IrType::Unit,
        Type::Address => IrType::Address,
        Type::Hash => IrType::Hash,
        Type::Array(elem, size) => IrType::Array(Box::new(ast_type_to_ir(elem)), *size),
        Type::Tuple(types) => IrType::Tuple(types.iter().map(ast_type_to_ir).collect()),
        Type::Named(name) => IrType::Named(name.clone()),
        Type::Ref(inner) => IrType::Ref(Box::new(ast_type_to_ir(inner))),
        Type::MutRef(inner) => IrType::MutRef(Box::new(ast_type_to_ir(inner))),
    }
}

fn infer_action_effect_without_call_graph(action: &ActionDef) -> EffectClass {
    let mut footprint = EffectFootprint::default();
    for stmt in &action.body {
        collect_ast_stmt_effects(stmt, &mut footprint);
    }
    effect_from_footprint(&footprint)
}

fn infer_fn_effect_without_call_graph(function: &FnDef) -> EffectClass {
    let mut footprint = EffectFootprint::default();
    for stmt in &function.body {
        collect_ast_stmt_effects(stmt, &mut footprint);
    }
    effect_from_footprint(&footprint)
}

fn collect_ast_stmt_effects(stmt: &Stmt, footprint: &mut EffectFootprint) {
    match stmt {
        Stmt::Expr(expr) | Stmt::Let(LetStmt { value: expr, .. }) | Stmt::Return(Some(expr)) => {
            collect_ast_expr_effects(expr, footprint);
        }
        Stmt::If(if_stmt) => {
            collect_ast_expr_effects(&if_stmt.condition, footprint);
            for stmt in &if_stmt.then_branch {
                collect_ast_stmt_effects(stmt, footprint);
            }
            if let Some(else_branch) = &if_stmt.else_branch {
                for stmt in else_branch {
                    collect_ast_stmt_effects(stmt, footprint);
                }
            }
        }
        Stmt::For(for_stmt) => {
            collect_ast_expr_effects(&for_stmt.iterable, footprint);
            for stmt in &for_stmt.body {
                collect_ast_stmt_effects(stmt, footprint);
            }
        }
        Stmt::While(while_stmt) => {
            collect_ast_expr_effects(&while_stmt.condition, footprint);
            for stmt in &while_stmt.body {
                collect_ast_stmt_effects(stmt, footprint);
            }
        }
        _ => {}
    }
}

fn collect_ast_expr_effects(expr: &Expr, footprint: &mut EffectFootprint) {
    match expr {
        Expr::Consume(consume) => {
            footprint.has_consume = true;
            collect_ast_expr_effects(&consume.expr, footprint);
        }
        Expr::Create(create) => {
            footprint.has_create = true;
            for (_, value) in &create.fields {
                collect_ast_expr_effects(value, footprint);
            }
            if let Some(lock) = &create.lock {
                collect_ast_expr_effects(lock, footprint);
            }
        }
        Expr::Transfer(transfer) => {
            footprint.has_consume = true;
            footprint.has_create = true;
            collect_ast_expr_effects(&transfer.expr, footprint);
            collect_ast_expr_effects(&transfer.to, footprint);
        }
        Expr::Destroy(destroy) => {
            footprint.has_consume = true;
            collect_ast_expr_effects(&destroy.expr, footprint);
        }
        Expr::ReadRef(_) => footprint.has_read_ref = true,
        Expr::Claim(claim) => {
            footprint.has_consume = true;
            footprint.has_create = true;
            collect_ast_expr_effects(&claim.receipt, footprint);
        }
        Expr::Settle(settle) => {
            footprint.has_consume = true;
            footprint.has_create = true;
            collect_ast_expr_effects(&settle.expr, footprint);
        }
        Expr::Assert(assert_expr) => {
            collect_ast_expr_effects(&assert_expr.condition, footprint);
        }
        Expr::Assign(assign) => {
            collect_ast_expr_effects(&assign.target, footprint);
            collect_ast_expr_effects(&assign.value, footprint);
        }
        Expr::Binary(binary) => {
            collect_ast_expr_effects(&binary.left, footprint);
            collect_ast_expr_effects(&binary.right, footprint);
        }
        Expr::Unary(unary) => collect_ast_expr_effects(&unary.expr, footprint),
        Expr::Call(call) => {
            for arg in &call.args {
                collect_ast_expr_effects(arg, footprint);
            }
        }
        Expr::FieldAccess(field) => collect_ast_expr_effects(&field.expr, footprint),
        Expr::Index(index) => {
            collect_ast_expr_effects(&index.expr, footprint);
            collect_ast_expr_effects(&index.index, footprint);
        }
        Expr::If(if_expr) => {
            collect_ast_expr_effects(&if_expr.condition, footprint);
            collect_ast_expr_effects(&if_expr.then_branch, footprint);
            collect_ast_expr_effects(&if_expr.else_branch, footprint);
        }
        Expr::Cast(cast) => collect_ast_expr_effects(&cast.expr, footprint),
        Expr::Range(range) => {
            collect_ast_expr_effects(&range.start, footprint);
            collect_ast_expr_effects(&range.end, footprint);
        }
        Expr::StructInit(init) => {
            for (_, value) in &init.fields {
                collect_ast_expr_effects(value, footprint);
            }
        }
        Expr::Match(match_expr) => {
            collect_ast_expr_effects(&match_expr.expr, footprint);
            for arm in &match_expr.arms {
                collect_ast_expr_effects(&arm.value, footprint);
            }
        }
        Expr::Block(stmts) => {
            for stmt in stmts {
                collect_ast_stmt_effects(stmt, footprint);
            }
        }
        Expr::Tuple(items) | Expr::Array(items) => {
            for item in items {
                collect_ast_expr_effects(item, footprint);
            }
        }
        _ => {}
    }
}

fn effect_from_footprint(footprint: &EffectFootprint) -> EffectClass {
    match (footprint.has_consume, footprint.has_create, footprint.has_read_ref) {
        (true, true, _) => EffectClass::Mutating,
        (true, false, _) => EffectClass::Destroying,
        (false, true, _) => EffectClass::Creating,
        (false, false, true) => EffectClass::ReadOnly,
        (false, false, false) => EffectClass::Pure,
    }
}

fn ast_effect_to_ir(effect: crate::ast::EffectClass) -> EffectClass {
    match effect {
        crate::ast::EffectClass::Pure => EffectClass::Pure,
        crate::ast::EffectClass::ReadOnly => EffectClass::ReadOnly,
        crate::ast::EffectClass::Mutating => EffectClass::Mutating,
        crate::ast::EffectClass::Creating => EffectClass::Creating,
        crate::ast::EffectClass::Destroying => EffectClass::Destroying,
    }
}

fn resolver_type_fields_to_ir(type_def: &TypeDef) -> Option<HashMap<String, IrType>> {
    let fields = match type_def {
        TypeDef::Resource(resource) => &resource.fields,
        TypeDef::Shared(shared) => &shared.fields,
        TypeDef::Receipt(receipt) => &receipt.fields,
        TypeDef::Struct(struct_def) => &struct_def.fields,
        TypeDef::Enum(_) => return None,
    };

    Some(fields.iter().map(|field| (field.name.clone(), ast_type_to_ir_type(&field.ty))).collect())
}

fn lifecycle_states_to_rules(states: &[String]) -> Vec<IrLifecycleRule> {
    states
        .windows(2)
        .enumerate()
        .map(|(index, window)| IrLifecycleRule {
            from: window[0].clone(),
            to: window[1].clone(),
            from_index: index,
            to_index: index + 1,
        })
        .collect()
}

fn resolver_type_def_to_ir(local_name: &str, type_def: &TypeDef) -> Option<IrTypeDef> {
    match type_def {
        TypeDef::Resource(resource) => Some(IrTypeDef {
            name: local_name.to_string(),
            type_id: resource.type_id.as_ref().map(|type_id| type_id.value.clone()),
            kind: IrTypeKind::Resource,
            fields: layout_resolver_fields(&resource.fields),
            capabilities: resource.capabilities.clone(),
            claim_output: None,
            lifecycle_states: None,
            lifecycle_rules: Vec::new(),
        }),
        TypeDef::Shared(shared) => Some(IrTypeDef {
            name: local_name.to_string(),
            type_id: shared.type_id.as_ref().map(|type_id| type_id.value.clone()),
            kind: IrTypeKind::Shared,
            fields: layout_resolver_fields(&shared.fields),
            capabilities: shared.capabilities.clone(),
            claim_output: None,
            lifecycle_states: None,
            lifecycle_rules: Vec::new(),
        }),
        TypeDef::Receipt(receipt) => Some(IrTypeDef {
            name: local_name.to_string(),
            type_id: receipt.type_id.as_ref().map(|type_id| type_id.value.clone()),
            kind: IrTypeKind::Receipt,
            fields: layout_resolver_fields(&receipt.fields),
            capabilities: receipt.capabilities.clone(),
            claim_output: receipt.claim_output.as_ref().map(ast_type_to_ir_type),
            lifecycle_states: receipt.lifecycle.as_ref().map(|lifecycle| lifecycle.states.clone()),
            lifecycle_rules: receipt
                .lifecycle
                .as_ref()
                .map(|lifecycle| lifecycle_states_to_rules(&lifecycle.states))
                .unwrap_or_default(),
        }),
        TypeDef::Struct(struct_def) => Some(IrTypeDef {
            name: local_name.to_string(),
            type_id: struct_def.type_id.as_ref().map(|type_id| type_id.value.clone()),
            kind: IrTypeKind::Struct,
            fields: layout_resolver_fields(&struct_def.fields),
            capabilities: Vec::new(),
            claim_output: None,
            lifecycle_states: None,
            lifecycle_rules: Vec::new(),
        }),
        TypeDef::Enum(_) => None,
    }
}

fn layout_resolver_fields(fields: &[Field]) -> Vec<IrField> {
    let mut next_offset = Some(0usize);
    fields
        .iter()
        .map(|field| {
            let ty = ast_type_to_ir_type(&field.ty);
            let fixed_size = fixed_encoded_size_for_ir_type(&ty);
            let offset = next_offset.unwrap_or(0);
            next_offset = next_offset.and_then(|current| fixed_size.map(|size| current + size));
            IrField { name: field.name.clone(), ty, offset, fixed_size }
        })
        .collect()
}

fn fixed_encoded_size_for_ir_type(ty: &IrType) -> Option<usize> {
    match ty {
        IrType::U8 | IrType::Bool => Some(1),
        IrType::U16 => Some(2),
        IrType::U32 => Some(4),
        IrType::U64 => Some(8),
        IrType::U128 => Some(16),
        IrType::Address | IrType::Hash => Some(32),
        IrType::Array(inner, len) => fixed_encoded_size_for_ir_type(inner).map(|inner_size| inner_size * len),
        IrType::Tuple(items) => items.iter().try_fold(0usize, |acc, item| fixed_encoded_size_for_ir_type(item).map(|size| acc + size)),
        IrType::Unit => Some(0),
        IrType::Named(_) | IrType::Ref(_) | IrType::MutRef(_) => None,
    }
}

fn resolver_type_kind(type_def: &TypeDef) -> Option<IrTypeKind> {
    match type_def {
        TypeDef::Resource(_) => Some(IrTypeKind::Resource),
        TypeDef::Shared(_) => Some(IrTypeKind::Shared),
        TypeDef::Receipt(_) => Some(IrTypeKind::Receipt),
        TypeDef::Struct(_) => Some(IrTypeKind::Struct),
        TypeDef::Enum(_) => None,
    }
}

fn resolver_receipt_claim_output_to_ir(type_def: &TypeDef) -> Option<Option<IrType>> {
    match type_def {
        TypeDef::Receipt(receipt) => Some(receipt.claim_output.as_ref().map(ast_type_to_ir_type)),
        TypeDef::Resource(_) | TypeDef::Shared(_) | TypeDef::Struct(_) | TypeDef::Enum(_) => None,
    }
}

fn ast_type_to_ir_type(ty: &Type) -> IrType {
    match ty {
        Type::U8 => IrType::U8,
        Type::U16 => IrType::U16,
        Type::U32 => IrType::U32,
        Type::U64 => IrType::U64,
        Type::U128 => IrType::U128,
        Type::Bool => IrType::Bool,
        Type::Unit => IrType::Unit,
        Type::Address => IrType::Address,
        Type::Hash => IrType::Hash,
        Type::Array(inner, size) => IrType::Array(Box::new(ast_type_to_ir_type(inner)), *size),
        Type::Tuple(items) => IrType::Tuple(items.iter().map(ast_type_to_ir_type).collect()),
        Type::Named(name) => IrType::Named(name.clone()),
        Type::Ref(inner) => IrType::Ref(Box::new(ast_type_to_ir_type(inner))),
        Type::MutRef(inner) => IrType::MutRef(Box::new(ast_type_to_ir_type(inner))),
    }
}

fn const_usize_operand(operand: &IrOperand) -> Option<usize> {
    match operand {
        IrOperand::Const(IrConst::U8(value)) => Some(*value as usize),
        IrOperand::Const(IrConst::U16(value)) => Some(*value as usize),
        IrOperand::Const(IrConst::U32(value)) => Some(*value as usize),
        IrOperand::Const(IrConst::U64(value)) => usize::try_from(*value).ok(),
        _ => None,
    }
}

fn direct_field_access_root(field: &FieldAccessExpr) -> Option<(&str, &str)> {
    match field.expr.as_ref() {
        Expr::Identifier(root) => Some((root.as_str(), field.field.as_str())),
        _ => None,
    }
}

fn same_direct_field_access(expr: &Expr, root: &str, field_name: &str) -> bool {
    let Expr::FieldAccess(field) = expr else {
        return false;
    };
    matches!(field.expr.as_ref(), Expr::Identifier(name) if name == root) && field.field == field_name
}

fn call_target_is_min(expr: &Expr) -> bool {
    matches!(expr, Expr::Identifier(name) if name == "min" || name == "math_min")
}

fn is_verifier_coverable_output_field_type(ty: &IrType) -> bool {
    matches!(ty, IrType::Bool | IrType::U8 | IrType::U16 | IrType::U32 | IrType::U64 | IrType::Address | IrType::Hash)
        || matches!(ty, IrType::Array(inner, _) if matches!(inner.as_ref(), IrType::U8))
}

fn binding_pattern_label(pattern: &BindingPattern) -> &str {
    match pattern {
        BindingPattern::Name(name) => name.as_str(),
        BindingPattern::Wildcard => "_",
        BindingPattern::Tuple(_) => "tuple_item",
    }
}

pub(crate) fn type_hash_for_name(name: &str) -> [u8; 32] {
    *blake3::hash(name.as_bytes()).as_bytes()
}
