use crate::ast::*;
use crate::error::{CompileError, Result, Span};
use crate::resolve::{FunctionDef, ModuleResolver, TypeDef};
use crate::runtime_errors::CellScriptRuntimeError;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

mod bindings;
mod optimize;
mod policy;
pub use bindings::{IrCellBinding, IrCellBindingRole, IrCellMembership, IrCellSource};
pub(crate) use optimize::{optimize_exact_cell_data_equality, optimize_source_byte_equality};
pub(crate) use policy::bind_artifact_policy;

#[derive(Debug, Clone)]
pub struct IrModule {
    pub name: String,
    pub items: Vec<IrItem>,
    pub entry_selection: IrEntrySelection,
    pub external_type_defs: Vec<IrTypeDef>,
    pub external_callable_abis: Vec<IrCallableAbi>,
    pub enum_fixed_sizes: HashMap<String, usize>,
    pub enum_layouts: HashMap<String, IrEnumLayout>,
}

/// Artifact-local entry choice, separate from the retained callable set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum IrEntrySelection {
    #[default]
    Legacy,
    Action(String),
    Lock(String),
    Artifact(crate::artifact::ArtifactDeclaration),
}

/// The callable selected by an implicit or explicit single-entry contract.
///
/// Keep the selection in shared IR so emitted code and semantic metadata cannot
/// disagree about which callable the entry wrapper invokes. A module may retain
/// other actions as dependencies; their presence does not imply dispatch.
#[derive(Debug, Clone, Copy)]
pub(crate) enum IrEntryPoint<'a> {
    Action(&'a IrAction),
    Lock(&'a IrLock),
}

impl<'a> IrEntryPoint<'a> {
    pub(crate) fn name(self) -> &'a str {
        match self {
            Self::Action(action) => &action.name,
            Self::Lock(lock) => &lock.name,
        }
    }

    pub(crate) fn params(self) -> &'a [IrParam] {
        match self {
            Self::Action(action) => &action.params,
            Self::Lock(lock) => &lock.params,
        }
    }

    #[cfg(not(feature = "wasm"))]
    pub(crate) fn kind(self) -> &'static str {
        match self {
            Self::Action(_) => "action",
            Self::Lock(_) => "lock",
        }
    }

    #[cfg(not(feature = "wasm"))]
    pub(crate) fn script_role(self) -> &'static str {
        match self {
            Self::Action(_) => "type",
            Self::Lock(_) => "lock",
        }
    }

    #[cfg(not(feature = "wasm"))]
    pub(crate) fn trigger(self) -> &'a str {
        match self {
            Self::Action(action) => action.entry_trigger.as_deref().unwrap_or("type-group"),
            Self::Lock(_) => "lock-group",
        }
    }
}

impl IrModule {
    /// Explicit scopes select exactly their named callable, even when other
    /// actions are retained as dependencies. Unscoped compilation preserves
    /// Edition 2026's runtime entry precedence: `main`, the first no-argument
    /// action, the first action, then the first Lock Script.
    pub(crate) fn resolved_entry(&self) -> Option<IrEntryPoint<'_>> {
        match &self.entry_selection {
            IrEntrySelection::Action(name) => {
                return self.items.iter().find_map(|item| match item {
                    IrItem::Action(action) if action.name == *name => Some(IrEntryPoint::Action(action)),
                    _ => None,
                });
            }
            IrEntrySelection::Lock(name) => {
                return self.items.iter().find_map(|item| match item {
                    IrItem::Lock(lock) if lock.name == *name => Some(IrEntryPoint::Lock(lock)),
                    _ => None,
                });
            }
            IrEntrySelection::Artifact(_) => return None,
            IrEntrySelection::Legacy => {}
        }
        let actions = || {
            self.items.iter().filter_map(|item| match item {
                IrItem::Action(action) => Some(action),
                _ => None,
            })
        };
        actions()
            .find(|action| action.name == "main")
            .or_else(|| actions().find(|action| action.params.is_empty()))
            .or_else(|| actions().next())
            .map(IrEntryPoint::Action)
            .or_else(|| {
                self.items.iter().find_map(|item| match item {
                    IrItem::Lock(lock) => Some(IrEntryPoint::Lock(lock)),
                    _ => None,
                })
            })
    }

    pub(crate) fn validate_entry_selection(&self) -> Result<()> {
        let (kind, name) = match &self.entry_selection {
            IrEntrySelection::Legacy => return Ok(()),
            IrEntrySelection::Action(name) => ("action", name),
            IrEntrySelection::Lock(name) => ("lock", name),
            IrEntrySelection::Artifact(declaration) => return policy::validate_artifact_selection(self, declaration),
        };
        let matches = self
            .items
            .iter()
            .filter(|item| match (kind, item) {
                ("action", IrItem::Action(action)) => action.name == *name,
                ("lock", IrItem::Lock(lock)) => lock.name == *name,
                _ => false,
            })
            .count();
        if matches != 1 || name.is_empty() {
            return Err(CompileError::without_span(format!(
                "explicit artifact entry {kind} '{name}' must identify exactly one retained callable; found {matches}"
            ))
            .with_code("E2101"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct IrEnumLayout {
    pub name: String,
    pub tag_width: usize,
    pub encoded_size: usize,
    pub variants: Vec<IrEnumVariantLayout>,
    pub contains_linear_payload: bool,
}

impl IrEnumLayout {
    pub fn has_payload(&self) -> bool {
        self.variants.iter().any(|variant| !variant.fields.is_empty())
    }
}

#[derive(Debug, Clone)]
pub struct IrEnumVariantLayout {
    pub name: String,
    pub tag: u8,
    pub payload_width: usize,
    pub fields: Vec<IrEnumFieldLayout>,
}

#[derive(Debug, Clone)]
pub struct IrEnumFieldLayout {
    pub index: usize,
    pub ty: IrType,
    pub offset: usize,
    pub width: usize,
    pub linear: bool,
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
    Invariant(IrInvariant),
    Action(IrAction),
    PureFn(IrPureFn),
    Lock(IrLock),
}

#[derive(Debug, Clone)]
pub struct IrTypeDef {
    pub name: String,
    pub type_id: Option<String>,
    pub default_hash_type: Option<String>,
    pub capacity_floor_shannons: Option<u64>,
    pub kind: IrTypeKind,
    pub fields: Vec<IrField>,
    pub capabilities: Vec<Capability>,
    pub claim_output: Option<IrType>,
    pub flow_states: Option<Vec<String>>,
    pub flow_state_field: Option<String>,
    pub flow_rules: Vec<IrFlowRule>,
    pub flow_initial_state: Option<String>,
    pub flow_terminal_states: Vec<String>,
    pub flow_terminal_discharge: Option<String>,
    pub flow_state_model: Option<String>,
    pub flow_audit_warnings: Vec<String>,
    pub validity_predicates: Vec<IrValidityPredicate>,
    /// Identity policy for v0.15 cell identity system
    pub identity: IrIdentityPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrValidityEvidence {
    CheckedStatic,
    CheckedRuntime,
    BuilderEvidenceRequired,
}

#[derive(Debug, Clone)]
pub struct IrValidityPredicate {
    pub expression: Expr,
    pub message: Option<Expr>,
    pub rendered: String,
    pub evidence: IrValidityEvidence,
    pub dependencies: Vec<String>,
    pub runtime_checked_on_create: bool,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct IrInvariant {
    pub name: String,
    pub trigger: Option<String>,
    pub scope: Option<String>,
    pub reads: Vec<AggregateTarget>,
    pub aggregates: Vec<IrAggregateInvariant>,
    pub quantifiers: Vec<BoundedQuantifier>,
    pub assert_count: usize,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct IrAggregateInvariant {
    pub kind: AggregateInvariantKind,
    pub target: AggregateTarget,
    pub scope: String,
    pub argument: Option<String>,
    pub relation: Option<AggregateRelation>,
    pub rhs: Option<AggregateTarget>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct IrFlowRule {
    pub from: String,
    pub to: String,
    pub from_index: usize,
    pub to_index: usize,
}

#[derive(Debug, Clone)]
pub struct IrStateTransitionEdge {
    pub input_binding: Option<String>,
    pub output_binding: Option<String>,
    pub type_name: String,
    pub field_name: String,
    pub from: String,
    pub to: String,
    pub from_index: usize,
    pub to_index: usize,
}

/// Explanatory participant-role candidate retained for ProtocolGraph.
///
/// These records never participate in verifier lowering or capability
/// entailment.  The graph renderer resolves them deterministically and keeps
/// the source attribution so field-name hints cannot be mistaken for
/// authorization evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrProtocolRoleCandidate {
    pub role: String,
    pub source: String,
    pub strength: String,
    pub actor_binding: Option<String>,
    pub actor_source: Option<String>,
    pub cell_binding: Option<String>,
    pub field_name: Option<String>,
    pub predicate: Option<String>,
    pub span: Option<Span>,
}

/// Destruction policy in IR, mirroring the AST-level DestructionPolicy
/// but simplified for codegen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrDestructionPolicy {
    /// Bare `destroy` — legacy v0.14, same as SingletonType
    Default,
    /// `destroy_singleton_type` — proves absence of same-TypeHash output
    SingletonType,
    /// `destroy_unique` — uses TYPE_ID to identify cell
    Unique { identity: String },
    /// `destroy_instance` — identifies by specific field
    Instance { identity_field: String },
    /// `burn_amount` — proves quantity delta, not output absence
    BurnAmount { field: String },
}

/// Identity policy in IR, mirroring the AST-level IdentityPolicy
/// but simplified for codegen and metadata emission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrIdentityPolicy {
    /// No identity tracking (default)
    None,
    /// CKB TYPE_ID based identity
    CkbTypeId,
    /// Field-based identity
    Field(String),
    /// Script args based identity
    ScriptArgs,
    /// Singleton type identity
    SingletonType,
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
    I32,
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
    /// Exact Script Group trigger selected by an Edition 2027 artifact
    /// container. Legacy actions leave this unset and retain `type-group`.
    pub entry_trigger: Option<String>,
    /// Canonical source-declared disposition plans from the Edition 2027
    /// frontend. The generated body remains the execution authority; these
    /// records prevent typed expansion from re-inferring a weaker legacy
    /// meaning from the lowered operations.
    pub source_dispositions: Vec<IrSourceDisposition>,
    /// Type-checked metadata-only declarations. These are intentionally not
    /// inserted into executable blocks.
    pub audit_claims: Vec<IrAuditClaim>,
    pub params: Vec<IrParam>,
    pub return_type: Option<IrType>,
    pub state_transition_edges: Vec<IrStateTransitionEdge>,
    pub protocol_role_candidates: Vec<IrProtocolRoleCandidate>,
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
    pub declared_effect_class: Option<EffectClass>,
    pub inferred_effect_class: EffectClass,
    pub effect_class: EffectClass,
}

/// IR Lock
#[derive(Debug, Clone)]
pub struct IrLock {
    pub name: String,
    pub params: Vec<IrParam>,
    pub audit_claims: Vec<IrAuditClaim>,
    pub body: IrBody,
}

#[derive(Debug, Clone)]
pub struct IrAuditClaim {
    pub name: String,
    pub evidence: String,
    pub subject: String,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct IrSourceDisposition {
    pub kind: IrSourceDispositionKind,
    pub input_binding: Option<String>,
    pub output_binding: Option<String>,
    pub data_fields: Vec<(String, String)>,
    pub lock_expression: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum IrSourceDispositionKind {
    Successor,
    PooledInput { pool_id: String, accounting_obligation: String },
    PoolResult { pool_id: String, accounting_obligation: String },
    Retired { absence_policy: String },
    Fresh { identity_policy: String },
}

pub(crate) fn source_disposition_id(entry_id: &str, source: &IrSourceDisposition) -> String {
    match &source.kind {
        IrSourceDispositionKind::Successor => format!(
            "disposition:{entry_id}:successor:{}->{}",
            source.input_binding.as_deref().expect("validated successor input"),
            source.output_binding.as_deref().expect("validated successor output")
        ),
        IrSourceDispositionKind::PooledInput { pool_id, .. } => format!(
            "disposition:{entry_id}:pooled-input:{pool_id}:{}",
            source.input_binding.as_deref().expect("validated pooled input")
        ),
        IrSourceDispositionKind::PoolResult { pool_id, .. } => format!(
            "disposition:{entry_id}:pool-result:{pool_id}:{}",
            source.output_binding.as_deref().expect("validated pool output")
        ),
        IrSourceDispositionKind::Retired { .. } => {
            format!("disposition:{entry_id}:retired:{}", source.input_binding.as_deref().expect("validated retirement input"))
        }
        IrSourceDispositionKind::Fresh { .. } => {
            format!("disposition:{entry_id}:fresh:{}", source.output_binding.as_deref().expect("validated fresh output"))
        }
    }
}

fn source_identity_policy(policy: &IdentityPolicy) -> String {
    match policy {
        IdentityPolicy::None => "none".to_string(),
        IdentityPolicy::CkbTypeId => "ckb-type-id".to_string(),
        IdentityPolicy::Field(field) => format!("field:{field}"),
        IdentityPolicy::ScriptArgs => "script-args".to_string(),
        IdentityPolicy::SingletonType => "singleton-type".to_string(),
    }
}

fn source_absence_policy(policy: &DestructionPolicy) -> String {
    match policy {
        DestructionPolicy::SingletonType => "same-type-hash-output-absent".to_string(),
        DestructionPolicy::Unique { .. } => "same-ckb-type-id-output-absent".to_string(),
        DestructionPolicy::Instance { identity_field } => format!("same-field-identity-output-absent:{identity_field}"),
        DestructionPolicy::Default | DestructionPolicy::BurnAmount { .. } => {
            unreachable!("native retirement requires an exact absence policy")
        }
    }
}

#[derive(Debug, Clone)]
pub struct IrParam {
    pub name: String,
    pub ty: IrType,
    pub is_mut: bool,
    pub is_ref: bool,
    pub is_read_ref: bool,
    pub source: ParamSource,
    pub binding: IrVar,
}

#[derive(Debug, Clone)]
pub struct IrBody {
    /// Resolved physical locations; later phases must not allocate ordinals.
    pub cell_bindings: Vec<IrCellBinding>,
    pub consume_set: Vec<CellPattern>,
    pub read_refs: Vec<CellPattern>,
    pub create_set: Vec<CreatePattern>,
    pub mutate_set: Vec<MutatePattern>,
    pub write_intents: Vec<WriteIntent>,
    pub bounded_collection_ops: Vec<IrBoundedCollectionOp>,
    pub borrow_regions: Vec<IrBorrowRegion>,
    /// External verifier calls whose target identity is bound in the emitted
    /// machine code and whose trust claim must be supplied by Cell.toml.
    pub trusted_external_calls: Vec<IrTrustedExternalCall>,
    /// Source-level `require`/Edition 2027 `enforce` conditions that were
    /// lowered to an explicit fail-closed branch. These bindings let the
    /// semantic foundation distinguish the claim itself from auxiliary
    /// ProofPlan/runtime obligations.
    pub enforced_claims: Vec<IrEnforcedClaim>,
    pub blocks: Vec<IrBlock>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrTrustedExternalCall {
    pub operation: String,
    pub adapter: String,
    pub code_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct IrEnforcedClaim {
    pub statement: String,
    pub condition_block: BlockId,
    pub success_block: BlockId,
    pub failure_block: BlockId,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct IrBorrowRegion {
    pub root: String,
    pub path: Vec<String>,
    pub binding: String,
    pub root_type: String,
    pub view_type: String,
    pub start_block: BlockId,
    pub start_instruction: usize,
    pub end_block: Option<BlockId>,
    pub end_instruction: Option<usize>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct IrBoundedCollectionOp {
    pub operation: String,
    pub binding: String,
    pub collection_binding: String,
    pub collection_type: String,
    pub element_type: String,
    pub max_elements: usize,
    pub source: ParamSource,
    pub output_type: Option<String>,
    /// Predicates retained from the type-checked bounded body. A selected
    /// runtime contract executes them once per element; fail-closed shapes
    /// retain them only as audit evidence.
    pub predicates: Vec<String>,
    /// Restricted outer numeric `+=` updates executed once per element. These
    /// make aggregate conservation auditable without admitting arbitrary loop
    /// mutation or Cell effects.
    pub accumulator_updates: Vec<String>,
    /// The single type-checked create template retained for `create_each`.
    pub create_template: Option<IrBoundedCreateTemplate>,
    /// Positive consensus-runtime contract selected for this exact shape.
    /// `None` keeps the operation on the explicit fail-closed path.
    pub runtime_contract: Option<String>,
    /// Exact encoded element width for the first executable bounded runtime
    /// contracts. Dynamic element schemas remain fail-closed.
    pub element_width: Option<usize>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct IrBoundedCreateTemplate {
    pub output_type: String,
    pub fields: Vec<(String, String)>,
    pub lock: Option<String>,
}

pub const BOUNDED_CONSUME_EACH_FAIL_CLOSED_HELPER: &str = "__cellscript_bounded_consume_each_fail_closed";
pub const BOUNDED_CREATE_EACH_FAIL_CLOSED_HELPER: &str = "__cellscript_bounded_create_each_fail_closed";
pub const BOUNDED_TYPE_GROUP_INPUTS_V1: &str = "bounded-type-group-inputs-v1";
pub const BOUNDED_OUTPUT_PLAN_V1: &str = "bounded-output-plan-v1";
pub const BOUNDED_OUTPUT_PLAN_MAGIC_V1: &[u8; 8] = b"CSBPLv1\0";
const BOUNDED_CELL_RUNTIME_MAX_DATA_BYTES: usize = 512;
pub const BOUNDED_OUTPUT_PLAN_MAX_BYTES: usize = 4084;

/// Recognized source/runtime contracts with intentionally unavailable execution.
/// Keep this classification shared by metadata and the emitter: a deferred
/// value-producing call must terminate, never return an error as a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrDeferredRuntimeFeature {
    CkbSighashAll,
}

impl IrDeferredRuntimeFeature {
    pub fn from_helper(helper: &str) -> Option<Self> {
        match helper {
            "__ckb_sighash_all" => Some(Self::CkbSighashAll),
            _ => None,
        }
    }

    pub fn from_source_name(name: &str) -> Option<Self> {
        match name {
            "env::sighash_all" => Some(Self::CkbSighashAll),
            _ => None,
        }
    }

    pub const fn feature(self) -> &'static str {
        match self {
            Self::CkbSighashAll => "ckb-sighash-all-deferred",
        }
    }

    pub const fn runtime_error(self) -> CellScriptRuntimeError {
        match self {
            Self::CkbSighashAll => CellScriptRuntimeError::SighashAllUnsupported,
        }
    }

    pub fn effect(self) -> String {
        format!("deferred-runtime-fail-closed:{}:{}", self.runtime_error().code(), self.feature())
    }
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
    pub identity: IrIdentityPolicy,
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
    pub index: usize,
    pub fields: Vec<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellMetadataField {
    LockHash,
    Capacity,
}

#[derive(Debug, Clone)]
pub struct IrBlock {
    pub id: BlockId,
    pub instructions: Vec<IrInstruction>,
    pub terminator: IrTerminator,
    pub runtime_error: Option<CellScriptRuntimeError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockId(pub usize);

#[derive(Debug, Clone)]
pub enum IrInstruction {
    LoadConst {
        dest: IrVar,
        value: IrConst,
    },
    LoadVar {
        dest: IrVar,
        name: String,
    },
    StoreVar {
        name: String,
        src: IrOperand,
    },
    Binary {
        dest: IrVar,
        op: BinaryOp,
        left: IrOperand,
        right: IrOperand,
    },
    Unary {
        dest: IrVar,
        op: UnaryOp,
        operand: IrOperand,
    },
    FieldAccess {
        dest: IrVar,
        obj: IrOperand,
        field: String,
    },
    Index {
        dest: IrVar,
        arr: IrOperand,
        idx: IrOperand,
    },
    Length {
        dest: IrVar,
        operand: IrOperand,
    },
    TypeHash {
        dest: IrVar,
        operand: IrOperand,
    },
    CollectionNew {
        dest: IrVar,
        ty: String,
        capacity: Option<IrOperand>,
    },
    CollectionCapacity {
        dest: IrVar,
        collection: IrOperand,
    },
    CollectionPush {
        collection: IrOperand,
        value: IrOperand,
    },
    CollectionExtend {
        collection: IrOperand,
        slice: IrOperand,
    },
    CollectionClear {
        collection: IrOperand,
    },
    CollectionContains {
        dest: IrVar,
        collection: IrOperand,
        value: IrOperand,
    },
    CollectionRemove {
        dest: IrVar,
        collection: IrOperand,
        index: IrOperand,
    },
    CollectionInsert {
        collection: IrOperand,
        index: IrOperand,
        value: IrOperand,
    },
    CollectionSet {
        collection: IrOperand,
        index: IrOperand,
        value: IrOperand,
    },
    CollectionPop {
        dest: IrVar,
        collection: IrOperand,
    },
    CollectionReverse {
        collection: IrOperand,
    },
    CollectionTruncate {
        collection: IrOperand,
        len: IrOperand,
    },
    CollectionSwap {
        collection: IrOperand,
        left: IrOperand,
        right: IrOperand,
    },
    /// Load one canonically ordered Cell from the current Type Script group's
    /// input view. `found` is false only for CKB_INDEX_OUT_OF_BOUND. A
    /// successful load at `index >= max_elements` fails with the stable
    /// bounded-cardinality runtime error.
    BoundedCellLoad {
        dest: IrVar,
        found: IrVar,
        index: IrOperand,
        max_elements: usize,
        element_type: String,
        element_width: usize,
    },
    /// Decode one element from the canonical versioned Molecule FixVec carried
    /// by the BoundedList witness parameter.
    BoundedPlanLoad {
        dest: IrVar,
        found: IrVar,
        plan: IrOperand,
        index: IrOperand,
        max_elements: usize,
        element_type: String,
        element_width: usize,
    },
    /// Verify the GroupOutput at the plan-relative index against the single
    /// type-checked create template, including lock and capacity policy.
    BoundedOutputVerify {
        index: IrOperand,
        pattern: CreatePattern,
        capacity_floor_shannons: u64,
    },
    /// Prove that the canonical GroupOutput view ends exactly where the plan
    /// ends, rejecting both missing and extra outputs.
    BoundedOutputEnd {
        index: IrOperand,
    },
    Call {
        dest: Option<IrVar>,
        func: String,
        args: Vec<IrOperand>,
    },
    ReadRef {
        dest: IrVar,
        ty: String,
    },
    Move {
        dest: IrVar,
        src: IrOperand,
    },
    Tuple {
        dest: IrVar,
        fields: Vec<IrOperand>,
    },
    EnumConstruct {
        dest: IrVar,
        enum_name: String,
        variant: String,
        fields: Vec<IrOperand>,
    },
    EnumTag {
        dest: IrVar,
        operand: IrOperand,
        enum_name: String,
    },
    EnumPayload {
        dest: IrVar,
        operand: IrOperand,
        enum_name: String,
        variant: String,
        field_index: usize,
    },
    Consume {
        operand: IrOperand,
    },
    Create {
        dest: IrVar,
        pattern: CreatePattern,
    },
    Transfer {
        dest: IrVar,
        operand: IrOperand,
        to: IrOperand,
    },
    Destroy {
        operand: IrOperand,
        policy: IrDestructionPolicy,
    },
    Claim {
        dest: IrVar,
        receipt: IrOperand,
    },
    Settle {
        dest: IrVar,
        operand: IrOperand,
    },
    CreateUnique {
        dest: IrVar,
        pattern: CreatePattern,
        identity: IrIdentityPolicy,
    },
    ReplaceUnique {
        dest: IrVar,
        operand: IrOperand,
        pattern: CreatePattern,
        identity: IrIdentityPolicy,
    },
    CellMetadataEquality {
        left: IrOperand,
        right: IrOperand,
        field: CellMetadataField,
    },
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

fn is_read_only_runtime_call(call: &CallExpr) -> bool {
    match call.func.as_ref() {
        Expr::Identifier(name) => {
            name.starts_with("env::")
                || name.starts_with("ckb::")
                || name.starts_with("source::")
                || name.starts_with("dao::")
                || name.starts_with("xudt::")
                || name.starts_with("witness::")
                || name.starts_with("script::require_")
                || matches!(
                    name.as_str(),
                    "spawn"
                        | "pipe"
                        | "pipe_write"
                        | "pipe_read"
                        | "wait"
                        | "process_id"
                        | "inherited_fd"
                        | "close"
                        | "require_maturity"
                        | "require_time"
                        | "require_epoch_after"
                        | "require_epoch_relative"
                )
        }
        Expr::FieldAccess(field) => field.field == "type_hash",
        _ => false,
    }
}

pub struct IrGenerator {
    module: IrModule,
    var_counter: usize,
    block_counter: usize,
    aggregate_fields: HashMap<usize, HashMap<String, IrVar>>,
    schema_field_roots: HashMap<usize, (usize, String)>,
    /// (branch depth, branch epoch) in which a materialized schema field
    /// became reusable. A cached read is only reused when its defining
    /// context dominates the current one; sibling branch arms re-materialize.
    aggregate_field_contexts: HashMap<usize, (u32, u32)>,
    branch_depth: u32,
    branch_epoch: u32,
    aggregate_elements: HashMap<usize, Vec<IrVar>>,
    mutated_fields: HashMap<usize, BTreeSet<String>>,
    mutated_field_transitions: HashMap<usize, BTreeMap<String, MutateFieldTransition>>,
    transition_param_ids: HashSet<usize>,
    transition_coverable_value_ids: HashSet<usize>,
    type_fields: HashMap<String, HashMap<String, IrType>>,
    type_kinds: HashMap<String, IrTypeKind>,
    type_capacity_floors: HashMap<String, u64>,
    type_identities: HashMap<String, IrIdentityPolicy>,
    receipt_claim_outputs: HashMap<String, Option<IrType>>,
    flow_states: HashMap<String, Vec<String>>,
    flow_state_fields: HashMap<String, String>,
    flow_rules: HashMap<String, Vec<IrFlowRule>>,
    flow_initial_states: HashMap<String, String>,
    flow_terminal_states: HashMap<String, Vec<String>>,
    flow_state_models: HashMap<String, String>,
    flow_audit_warnings: HashMap<String, Vec<String>>,
    type_validity: HashMap<String, Vec<IrValidityPredicate>>,
    enum_variants: HashMap<String, HashMap<String, u64>>,
    enum_definitions: HashMap<String, EnumDef>,
    constants: HashMap<String, (Expr, IrType)>,
    function_effects: HashMap<String, EffectClass>,
    external_function_effects: HashMap<String, EffectClass>,
    function_param_types: HashMap<String, Vec<IrType>>,
    external_function_param_types: HashMap<String, Vec<IrType>>,
    function_return_types: HashMap<String, Option<IrType>>,
    external_function_return_types: HashMap<String, Option<IrType>>,
    call_target_labels: HashMap<String, String>,
    lowering_lock_entry: bool,
    borrow_regions: Vec<IrBorrowRegion>,
    trusted_external_calls: Vec<IrTrustedExternalCall>,
    enforced_claims: Vec<IrEnforcedClaim>,
    loop_targets: Vec<LoopTarget>,
    errors: Vec<CompileError>,
}

#[derive(Clone)]
struct LoopTarget {
    label: Option<String>,
    break_block: BlockId,
    continue_block: BlockId,
}

struct LoweredExpr {
    operand: IrOperand,
    current: Option<BlockId>,
}

fn stmts_contain_loop_control(statements: &[Stmt]) -> bool {
    statements.iter().any(|statement| match statement {
        Stmt::Break(_) | Stmt::Continue(_) => true,
        Stmt::If(statement) => {
            stmts_contain_loop_control(&statement.then_branch)
                || statement.else_branch.as_deref().is_some_and(stmts_contain_loop_control)
        }
        Stmt::For(statement) => stmts_contain_loop_control(&statement.body),
        Stmt::While(statement) => stmts_contain_loop_control(&statement.body),
        Stmt::Borrow(statement) => stmts_contain_loop_control(&statement.body),
        Stmt::Expr(Expr::Block(statements)) => stmts_contain_loop_control(statements),
        Stmt::Expr(Expr::If(branch)) => {
            expr_contains_loop_control(&branch.then_branch) || expr_contains_loop_control(&branch.else_branch)
        }
        Stmt::Expr(Expr::Match(match_expr)) => match_expr.arms.iter().any(|arm| expr_contains_loop_control(&arm.value)),
        Stmt::Let(statement) => expr_contains_loop_control(&statement.value),
        Stmt::Return(statement) => statement.value.as_ref().is_some_and(expr_contains_loop_control),
        Stmt::Expr(_) => false,
    })
}

fn expr_contains_loop_control(expr: &Expr) -> bool {
    match expr {
        Expr::Block(statements) => stmts_contain_loop_control(statements),
        Expr::If(branch) => expr_contains_loop_control(&branch.then_branch) || expr_contains_loop_control(&branch.else_branch),
        Expr::Match(match_expr) => match_expr.arms.iter().any(|arm| expr_contains_loop_control(&arm.value)),
        _ => false,
    }
}

fn collect_protocol_role_equalities_from_statements<'a>(statements: &'a [Stmt], equalities: &mut Vec<&'a BinaryExpr>) {
    for statement in statements {
        match statement {
            Stmt::Let(statement) => collect_protocol_role_equalities_from_expr(&statement.value, equalities),
            Stmt::Expr(expr) => collect_protocol_role_equalities_from_expr(expr, equalities),
            Stmt::Return(statement) => {
                if let Some(value) = &statement.value {
                    collect_protocol_role_equalities_from_expr(value, equalities);
                }
            }
            Stmt::If(statement) => {
                collect_protocol_role_equalities_from_expr(&statement.condition, equalities);
                collect_protocol_role_equalities_from_statements(&statement.then_branch, equalities);
                if let Some(else_branch) = &statement.else_branch {
                    collect_protocol_role_equalities_from_statements(else_branch, equalities);
                }
            }
            Stmt::For(statement) => {
                collect_protocol_role_equalities_from_expr(&statement.iterable, equalities);
                collect_protocol_role_equalities_from_statements(&statement.body, equalities);
            }
            Stmt::While(statement) => {
                collect_protocol_role_equalities_from_expr(&statement.condition, equalities);
                collect_protocol_role_equalities_from_statements(&statement.body, equalities);
            }
            Stmt::Borrow(statement) => collect_protocol_role_equalities_from_statements(&statement.body, equalities),
            Stmt::Break(_) | Stmt::Continue(_) => {}
        }
    }
}

fn collect_protocol_role_equalities_from_expr<'a>(expr: &'a Expr, equalities: &mut Vec<&'a BinaryExpr>) {
    match expr {
        Expr::Require(require) => collect_protocol_role_condition_equalities(&require.condition, equalities),
        Expr::RequireBlock(block) => {
            for condition in &block.expressions {
                collect_protocol_role_condition_equalities(condition, equalities);
            }
        }
        Expr::Assert(assertion) => collect_protocol_role_condition_equalities(&assertion.condition, equalities),
        Expr::Block(statements) => collect_protocol_role_equalities_from_statements(statements, equalities),
        Expr::If(branch) => {
            collect_protocol_role_equalities_from_expr(&branch.condition, equalities);
            collect_protocol_role_equalities_from_expr(&branch.then_branch, equalities);
            collect_protocol_role_equalities_from_expr(&branch.else_branch, equalities);
        }
        Expr::Match(match_expr) => {
            collect_protocol_role_equalities_from_expr(&match_expr.expr, equalities);
            for arm in &match_expr.arms {
                collect_protocol_role_equalities_from_expr(&arm.value, equalities);
            }
        }
        _ => {}
    }
}

fn collect_protocol_role_condition_equalities<'a>(expr: &'a Expr, equalities: &mut Vec<&'a BinaryExpr>) {
    match expr {
        Expr::Binary(binary) if binary.op == BinaryOp::Eq => equalities.push(binary),
        Expr::Binary(binary) if matches!(binary.op, BinaryOp::And | BinaryOp::Or) => {
            collect_protocol_role_condition_equalities(&binary.left, equalities);
            collect_protocol_role_condition_equalities(&binary.right, equalities);
        }
        Expr::Unary(unary) => collect_protocol_role_condition_equalities(&unary.expr, equalities),
        _ => {}
    }
}

fn protocol_role_field_access(expr: &Expr) -> Option<(&str, &str)> {
    let Expr::FieldAccess(access) = expr else {
        return None;
    };
    let Expr::Identifier(binding) = access.expr.as_ref() else {
        return None;
    };
    Some((binding, &access.field))
}

fn protocol_role_actor_param(param: &Param) -> bool {
    matches!(&param.ty, Type::Address) && matches!(param.source, ParamSource::Default | ParamSource::Witness | ParamSource::LockArgs)
}

fn protocol_role_param_source(source: ParamSource) -> &'static str {
    match source {
        ParamSource::Default => "entry-witness-default",
        ParamSource::Witness => "witness",
        ParamSource::LockArgs => "lock_args",
        ParamSource::Input => "input",
        ParamSource::Output => "output",
        ParamSource::Protected => "protected",
    }
}

fn protocol_role_source_rank(source: &str) -> u8 {
    match source {
        "verification-predicate" => 0,
        "witness-binding" | "lock-args-binding" => 1,
        "field-name" => 2,
        _ => u8::MAX,
    }
}

fn protocol_role_name(name: &str) -> Option<String> {
    const ROLE_NAMES: &[&str] = &[
        "admin",
        "arbiter",
        "authority",
        "beneficiary",
        "borrower",
        "buyer",
        "claimant",
        "counterparty",
        "depositor",
        "initiator",
        "issuer",
        "lender",
        "maker",
        "minter",
        "operator",
        "owner",
        "participant",
        "payee",
        "payer",
        "proposer",
        "recipient",
        "refundee",
        "seller",
        "sender",
        "signer",
        "sponsor",
        "taker",
        "withdrawer",
    ];
    let normalized = name.to_ascii_lowercase();
    normalized.split('_').find(|part| ROLE_NAMES.binary_search(part).is_ok()).map(str::to_string)
}

struct IrImportContext {
    type_fields: HashMap<String, HashMap<String, IrType>>,
    type_kinds: HashMap<String, IrTypeKind>,
    receipt_claim_outputs: HashMap<String, Option<IrType>>,
    flow_states: HashMap<String, Vec<String>>,
    type_validity: HashMap<String, Vec<IrValidityPredicate>>,
    enum_definitions: HashMap<String, EnumDef>,
    external_function_effects: HashMap<String, EffectClass>,
    external_function_param_types: HashMap<String, Vec<IrType>>,
    external_function_return_types: HashMap<String, Option<IrType>>,
    call_target_labels: HashMap<String, String>,
}

impl IrGenerator {
    pub fn new(module_name: String) -> Self {
        Self {
            module: IrModule {
                name: module_name,
                items: Vec::new(),
                entry_selection: IrEntrySelection::Legacy,
                external_type_defs: Vec::new(),
                external_callable_abis: Vec::new(),
                enum_fixed_sizes: HashMap::new(),
                enum_layouts: HashMap::new(),
            },
            var_counter: 0,
            block_counter: 0,
            aggregate_fields: HashMap::new(),
            schema_field_roots: HashMap::new(),
            aggregate_field_contexts: HashMap::new(),
            branch_depth: 0,
            branch_epoch: 0,
            aggregate_elements: HashMap::new(),
            mutated_fields: HashMap::new(),
            mutated_field_transitions: HashMap::new(),
            transition_param_ids: HashSet::new(),
            transition_coverable_value_ids: HashSet::new(),
            type_fields: HashMap::new(),
            type_kinds: HashMap::new(),
            type_capacity_floors: HashMap::new(),
            type_identities: HashMap::new(),
            receipt_claim_outputs: HashMap::new(),
            flow_states: HashMap::new(),
            flow_state_fields: HashMap::new(),
            flow_rules: HashMap::new(),
            flow_initial_states: HashMap::new(),
            flow_terminal_states: HashMap::new(),
            flow_state_models: HashMap::new(),
            flow_audit_warnings: HashMap::new(),
            type_validity: HashMap::new(),
            enum_variants: HashMap::new(),
            enum_definitions: HashMap::new(),
            constants: HashMap::new(),
            function_effects: HashMap::new(),
            external_function_effects: HashMap::new(),
            function_param_types: HashMap::new(),
            external_function_param_types: HashMap::new(),
            function_return_types: HashMap::new(),
            external_function_return_types: HashMap::new(),
            call_target_labels: HashMap::new(),
            lowering_lock_entry: false,
            borrow_regions: Vec::new(),
            trusted_external_calls: Vec::new(),
            enforced_claims: Vec::new(),
            loop_targets: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn with_type_fields(module_name: String, type_fields: HashMap<String, HashMap<String, IrType>>) -> Self {
        let mut generator = Self::new(module_name);
        generator.type_fields = type_fields;
        generator
    }

    fn with_import_context(module_name: String, context: IrImportContext) -> Self {
        let IrImportContext {
            type_fields,
            type_kinds,
            receipt_claim_outputs,
            flow_states,
            type_validity,
            enum_definitions,
            external_function_effects,
            external_function_param_types,
            external_function_return_types,
            call_target_labels,
        } = context;
        let mut generator = Self::with_type_fields(module_name, type_fields);
        generator.type_kinds.extend(type_kinds);
        generator.receipt_claim_outputs.extend(receipt_claim_outputs);
        generator.flow_states.extend(flow_states);
        generator.type_validity.extend(type_validity);
        for (name, mut definition) in enum_definitions {
            definition.name = name.clone();
            generator.enum_variants.insert(
                name.clone(),
                definition.variants.iter().enumerate().map(|(index, variant)| (variant.name.clone(), index as u64)).collect(),
            );
            generator.enum_definitions.insert(name, definition);
        }
        generator.external_function_effects = external_function_effects;
        generator.external_function_param_types = external_function_param_types;
        generator.external_function_return_types = external_function_return_types;
        generator.call_target_labels = call_target_labels;
        generator
    }

    pub fn generate(self, ast: &Module) -> Result<IrModule> {
        self.generate_diagnostics(ast)
            .map_err(|errors| errors.into_iter().next().unwrap_or_else(|| CompileError::without_span("IR lowering failed")))
    }

    pub fn generate_diagnostics(mut self, ast: &Module) -> std::result::Result<IrModule, Vec<CompileError>> {
        let validity_constant_names = ast
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Const(constant) => Some(constant.name.as_str()),
                _ => None,
            })
            .collect::<HashSet<_>>();
        for item in &ast.items {
            if let Item::Const(c) = item {
                self.constants.insert(c.name.clone(), (c.value.clone(), Self::convert_type(&c.ty)));
            }
            match item {
                Item::Resource(r) => {
                    self.type_kinds.insert(r.name.clone(), IrTypeKind::Resource);
                    if let Some(floor) = &r.capacity_floor {
                        self.type_capacity_floors.insert(r.name.clone(), floor.shannons);
                    }
                    self.type_identities.insert(r.name.clone(), Self::lower_identity_policy(&r.identity));
                    self.type_fields.insert(
                        r.name.clone(),
                        r.fields.iter().map(|field| (field.name.clone(), Self::convert_type(&field.ty))).collect(),
                    );
                    self.type_validity.insert(
                        r.name.clone(),
                        ir_validity_predicates_with_constants(r.validity.as_ref(), &r.fields, &validity_constant_names),
                    );
                }
                Item::Shared(s) => {
                    self.type_kinds.insert(s.name.clone(), IrTypeKind::Shared);
                    if let Some(floor) = &s.capacity_floor {
                        self.type_capacity_floors.insert(s.name.clone(), floor.shannons);
                    }
                    self.type_identities.insert(s.name.clone(), Self::lower_identity_policy(&s.identity));
                    self.type_fields.insert(
                        s.name.clone(),
                        s.fields.iter().map(|field| (field.name.clone(), Self::convert_type(&field.ty))).collect(),
                    );
                    self.type_validity.insert(
                        s.name.clone(),
                        ir_validity_predicates_with_constants(s.validity.as_ref(), &s.fields, &validity_constant_names),
                    );
                }
                Item::Receipt(r) => {
                    self.type_kinds.insert(r.name.clone(), IrTypeKind::Receipt);
                    if let Some(floor) = &r.capacity_floor {
                        self.type_capacity_floors.insert(r.name.clone(), floor.shannons);
                    }
                    self.type_identities.insert(r.name.clone(), Self::lower_identity_policy(&r.identity));
                    self.receipt_claim_outputs.insert(r.name.clone(), r.claim_output.as_ref().map(Self::convert_type));
                    self.type_fields.insert(
                        r.name.clone(),
                        r.fields.iter().map(|field| (field.name.clone(), Self::convert_type(&field.ty))).collect(),
                    );
                    self.type_validity.insert(
                        r.name.clone(),
                        ir_validity_predicates_with_constants(r.validity.as_ref(), &r.fields, &validity_constant_names),
                    );
                }
                Item::Struct(s) => {
                    self.type_kinds.insert(s.name.clone(), IrTypeKind::Struct);
                    if let Some(floor) = &s.capacity_floor {
                        self.type_capacity_floors.insert(s.name.clone(), floor.shannons);
                    }
                    self.type_identities.insert(s.name.clone(), IrIdentityPolicy::None);
                    self.type_fields.insert(
                        s.name.clone(),
                        s.fields.iter().map(|field| (field.name.clone(), Self::convert_type(&field.ty))).collect(),
                    );
                    self.type_validity.insert(
                        s.name.clone(),
                        ir_validity_predicates_with_constants(s.validity.as_ref(), &s.fields, &validity_constant_names),
                    );
                }
                Item::Enum(e) => {
                    self.enum_definitions.insert(e.name.clone(), e.clone());
                    self.enum_variants.insert(
                        e.name.clone(),
                        e.variants.iter().enumerate().map(|(index, variant)| (variant.name.clone(), index as u64)).collect(),
                    );
                }
                Item::Action(action) => {
                    let params = action.params.iter().map(|param| ast_type_to_ir(&param.ty)).collect::<Vec<_>>();
                    let return_type = action.return_type.as_ref().map(ast_type_to_ir);
                    self.function_param_types.insert(action.name.clone(), params.clone());
                    self.function_param_types.insert(format!("{}::{}", self.module.name, action.name), params);
                    self.function_return_types.insert(action.name.clone(), return_type.clone());
                    self.function_return_types.insert(format!("{}::{}", self.module.name, action.name), return_type);
                }
                Item::Function(function) => {
                    let params = function.params.iter().map(|param| ast_type_to_ir(&param.ty)).collect::<Vec<_>>();
                    let return_type = function.return_type.as_ref().map(ast_type_to_ir);
                    self.function_param_types.insert(function.name.clone(), params.clone());
                    self.function_param_types.insert(format!("{}::{}", self.module.name, function.name), params);
                    self.function_return_types.insert(function.name.clone(), return_type.clone());
                    self.function_return_types.insert(format!("{}::{}", self.module.name, function.name), return_type);
                }
                Item::Lock(lock) => {
                    let params = lock.params.iter().map(|param| ast_type_to_ir(&param.ty)).collect::<Vec<_>>();
                    self.function_param_types.insert(lock.name.clone(), params.clone());
                    self.function_param_types.insert(format!("{}::{}", self.module.name, lock.name), params);
                    self.function_return_types.insert(lock.name.clone(), Some(IrType::Bool));
                    self.function_return_types.insert(format!("{}::{}", self.module.name, lock.name), Some(IrType::Bool));
                }
                Item::Flow(_) => {}
                _ => {}
            }
        }

        self.register_enum_layouts();
        self.register_flows(&ast.items);
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
                Item::Invariant(invariant) => {
                    let ir_item = IrItem::Invariant(self.gen_invariant(invariant));
                    self.module.items.push(ir_item);
                }
                Item::Const(_) | Item::Enum(_) => {}
                Item::Action(a) => {
                    let ir_item = IrItem::Action(self.gen_action(a));
                    self.module.items.push(ir_item);
                }
                Item::Function(f) => {
                    let inferred_effect = self.analyze_body_effect_class(&f.body);
                    let declared_effect = self.convert_effect_class(f.effect);
                    if f.effect_declared && !self.effect_covers(declared_effect, inferred_effect) {
                        self.record_error(
                            format!(
                                "declared effect {:?} is too weak for function '{}'; inferred effect is {:?}",
                                declared_effect, f.name, inferred_effect
                            ),
                            f.span,
                        );
                    }
                    let ir_item = IrItem::PureFn(self.gen_function(f));
                    self.module.items.push(ir_item);
                }
                Item::Lock(l) => {
                    let ir_item = IrItem::Lock(self.gen_lock(l));
                    self.module.items.push(ir_item);
                }
                Item::Flow(_) => {}
                Item::Use(_) => {}
            }
        }
        if self.errors.is_empty() {
            Ok(self.module)
        } else {
            Err(self.errors)
        }
    }

    fn register_flows(&mut self, items: &[Item]) {
        for item in items {
            let Item::Flow(machine) = item else {
                continue;
            };
            let type_name = machine.target.base.clone();
            let field_name = machine.target.field.clone();
            let states = self.flow_states_for_decl(machine);
            let rules = machine
                .transitions
                .iter()
                .filter_map(|transition| {
                    let from = self.canonical_state_name(&type_name, &transition.from);
                    let to = self.canonical_state_name(&type_name, &transition.to);
                    let from_index = states.iter().position(|state| state == &from)?;
                    let to_index = states.iter().position(|state| state == &to)?;
                    Some(IrFlowRule { from, to, from_index, to_index })
                })
                .collect::<Vec<_>>();

            self.flow_states.insert(type_name.clone(), states);
            self.flow_state_fields.insert(type_name.clone(), field_name);
            self.flow_rules.insert(type_name.clone(), rules);

            let initial_state = machine.initial_states.first().map(|state| self.canonical_state_name(&type_name, state));
            let terminal_states =
                machine.terminal_states.iter().map(|state| self.canonical_state_name(&type_name, state)).collect::<Vec<_>>();
            if let Some(initial_state) = initial_state.clone() {
                self.flow_initial_states.insert(type_name.clone(), initial_state);
            }
            if !terminal_states.is_empty() {
                self.flow_terminal_states.insert(type_name.clone(), terminal_states);
            }

            let state_model = self
                .type_fields
                .get(&type_name)
                .and_then(|fields| fields.get(&machine.target.field))
                .map_or("legacy-numeric", |ty| if matches!(ty, IrType::Named(_)) { "enum-backed" } else { "legacy-numeric" });
            self.flow_state_models.insert(type_name.clone(), state_model.to_string());
            let mut warnings = Vec::new();
            if machine.initial_states.is_empty() && machine.terminal_states.is_empty() {
                warnings.push(
                    "legacy flow omits 0.22 initial/terminal declarations; migrate before claiming 0.22 terminal coverage".to_string(),
                );
            }
            if state_model == "legacy-numeric" {
                warnings.push("legacy numeric flow state; canonical 0.22 flows use a no-payload enum-backed state field".to_string());
            }
            if let Some(initial_state) = initial_state {
                let has_outgoing = machine
                    .transitions
                    .iter()
                    .any(|transition| self.canonical_state_name(&type_name, &transition.from) == initial_state);
                if !has_outgoing {
                    warnings.push(format!("initial state '{}' has no outgoing transition", initial_state));
                }
            }
            if !warnings.is_empty() {
                self.flow_audit_warnings.insert(type_name, warnings);
            }
        }
    }

    fn flow_states_for_decl(&self, machine: &FlowDef) -> Vec<String> {
        if let Some(fields) = self.type_fields.get(&machine.target.base)
            && let Some(IrType::Named(enum_name)) = fields.get(&machine.target.field)
            && let Some(variants) = self.enum_variants.get(enum_name)
        {
            let mut ordered = variants.iter().map(|(name, ordinal)| (*ordinal, name.clone())).collect::<Vec<_>>();
            ordered.sort_by_key(|(ordinal, _)| *ordinal);
            return ordered.into_iter().map(|(_, name)| name).collect();
        }

        let mut states = Vec::new();
        for transition in &machine.transitions {
            for raw in [&transition.from, &transition.to] {
                let state = self.canonical_state_name(&machine.target.base, raw);
                if !states.iter().any(|existing| existing == &state) {
                    states.push(state);
                }
            }
        }
        states
    }

    fn canonical_state_name(&self, _type_name: &str, raw: &str) -> String {
        raw.rsplit_once("::").map_or(raw, |(_, state)| state).to_string()
    }

    fn gen_resource(&mut self, resource: &ResourceDef) -> IrTypeDef {
        IrTypeDef {
            name: resource.name.clone(),
            type_id: resource.type_id.as_ref().map(|type_id| type_id.value.clone()),
            default_hash_type: resource.default_hash_type.as_ref().map(|hash_type| hash_type.value.clone()),
            capacity_floor_shannons: resource.capacity_floor.as_ref().map(|floor| floor.shannons),
            kind: IrTypeKind::Resource,
            fields: self.layout_fields(&resource.fields),
            capabilities: resource.capabilities.clone(),
            claim_output: None,
            flow_states: self.flow_states.get(&resource.name).cloned(),
            flow_state_field: self.flow_state_fields.get(&resource.name).cloned(),
            flow_rules: self.flow_rules.get(&resource.name).cloned().unwrap_or_default(),
            flow_initial_state: self.flow_initial_states.get(&resource.name).cloned(),
            flow_terminal_states: self.flow_terminal_states.get(&resource.name).cloned().unwrap_or_default(),
            flow_terminal_discharge: self
                .flow_terminal_states
                .contains_key(&resource.name)
                .then(|| "terminal-by-output-state".to_string()),
            flow_state_model: self.flow_state_models.get(&resource.name).cloned(),
            flow_audit_warnings: self.flow_audit_warnings.get(&resource.name).cloned().unwrap_or_default(),
            validity_predicates: self.type_validity.get(&resource.name).cloned().unwrap_or_default(),
            identity: Self::lower_identity_policy(&resource.identity),
        }
    }

    fn gen_shared(&mut self, shared: &SharedDef) -> IrTypeDef {
        IrTypeDef {
            name: shared.name.clone(),
            type_id: shared.type_id.as_ref().map(|type_id| type_id.value.clone()),
            default_hash_type: shared.default_hash_type.as_ref().map(|hash_type| hash_type.value.clone()),
            capacity_floor_shannons: shared.capacity_floor.as_ref().map(|floor| floor.shannons),
            kind: IrTypeKind::Shared,
            fields: self.layout_fields(&shared.fields),
            capabilities: shared.capabilities.clone(),
            claim_output: None,
            flow_states: self.flow_states.get(&shared.name).cloned(),
            flow_state_field: self.flow_state_fields.get(&shared.name).cloned(),
            flow_rules: self.flow_rules.get(&shared.name).cloned().unwrap_or_default(),
            flow_initial_state: self.flow_initial_states.get(&shared.name).cloned(),
            flow_terminal_states: self.flow_terminal_states.get(&shared.name).cloned().unwrap_or_default(),
            flow_terminal_discharge: self
                .flow_terminal_states
                .contains_key(&shared.name)
                .then(|| "terminal-by-output-state".to_string()),
            flow_state_model: self.flow_state_models.get(&shared.name).cloned(),
            flow_audit_warnings: self.flow_audit_warnings.get(&shared.name).cloned().unwrap_or_default(),
            validity_predicates: self.type_validity.get(&shared.name).cloned().unwrap_or_default(),
            identity: Self::lower_identity_policy(&shared.identity),
        }
    }

    fn gen_receipt(&mut self, receipt: &ReceiptDef) -> IrTypeDef {
        IrTypeDef {
            name: receipt.name.clone(),
            type_id: receipt.type_id.as_ref().map(|type_id| type_id.value.clone()),
            default_hash_type: receipt.default_hash_type.as_ref().map(|hash_type| hash_type.value.clone()),
            capacity_floor_shannons: receipt.capacity_floor.as_ref().map(|floor| floor.shannons),
            kind: IrTypeKind::Receipt,
            fields: self.layout_fields(&receipt.fields),
            capabilities: receipt.capabilities.clone(),
            claim_output: receipt.claim_output.as_ref().map(Self::convert_type),
            flow_states: self.flow_states.get(&receipt.name).cloned(),
            flow_state_field: self.flow_state_fields.get(&receipt.name).cloned(),
            flow_rules: self.flow_rules.get(&receipt.name).cloned().unwrap_or_default(),
            flow_initial_state: self.flow_initial_states.get(&receipt.name).cloned(),
            flow_terminal_states: self.flow_terminal_states.get(&receipt.name).cloned().unwrap_or_default(),
            flow_terminal_discharge: self
                .flow_terminal_states
                .contains_key(&receipt.name)
                .then(|| "terminal-by-output-state".to_string()),
            flow_state_model: self.flow_state_models.get(&receipt.name).cloned(),
            flow_audit_warnings: self.flow_audit_warnings.get(&receipt.name).cloned().unwrap_or_default(),
            validity_predicates: self.type_validity.get(&receipt.name).cloned().unwrap_or_default(),
            identity: Self::lower_identity_policy(&receipt.identity),
        }
    }

    fn gen_struct(&mut self, struct_def: &StructDef) -> IrTypeDef {
        IrTypeDef {
            name: struct_def.name.clone(),
            type_id: struct_def.type_id.as_ref().map(|type_id| type_id.value.clone()),
            default_hash_type: struct_def.default_hash_type.as_ref().map(|hash_type| hash_type.value.clone()),
            capacity_floor_shannons: struct_def.capacity_floor.as_ref().map(|floor| floor.shannons),
            kind: IrTypeKind::Struct,
            fields: self.layout_fields(&struct_def.fields),
            capabilities: Vec::new(),
            claim_output: None,
            flow_states: self.flow_states.get(&struct_def.name).cloned(),
            flow_state_field: self.flow_state_fields.get(&struct_def.name).cloned(),
            flow_rules: self.flow_rules.get(&struct_def.name).cloned().unwrap_or_default(),
            flow_initial_state: self.flow_initial_states.get(&struct_def.name).cloned(),
            flow_terminal_states: self.flow_terminal_states.get(&struct_def.name).cloned().unwrap_or_default(),
            flow_terminal_discharge: self
                .flow_terminal_states
                .contains_key(&struct_def.name)
                .then(|| "terminal-by-output-state".to_string()),
            flow_state_model: self.flow_state_models.get(&struct_def.name).cloned(),
            flow_audit_warnings: self.flow_audit_warnings.get(&struct_def.name).cloned().unwrap_or_default(),
            validity_predicates: self.type_validity.get(&struct_def.name).cloned().unwrap_or_default(),
            identity: IrIdentityPolicy::None,
        }
    }

    fn gen_invariant(&self, invariant: &InvariantDef) -> IrInvariant {
        IrInvariant {
            name: invariant.name.clone(),
            trigger: invariant.trigger.clone(),
            scope: invariant.scope.clone(),
            reads: invariant.reads.clone(),
            aggregates: invariant
                .aggregates
                .iter()
                .map(|aggregate| IrAggregateInvariant {
                    kind: aggregate.kind,
                    target: aggregate.target.clone(),
                    scope: aggregate.scope.clone(),
                    argument: aggregate.argument.clone(),
                    relation: aggregate.relation,
                    rhs: aggregate.rhs.clone(),
                    span: aggregate.span,
                })
                .collect(),
            quantifiers: invariant.quantifiers.clone(),
            assert_count: invariant.asserts.len(),
            span: invariant.span,
        }
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
                        let declared = self.convert_effect_class(function.effect);
                        let effective =
                            if function.effect_declared && self.effect_covers(declared, inferred) { declared } else { inferred };
                        if self.function_effects.get(&function.name).copied() != Some(effective) {
                            self.function_effects.insert(function.name.clone(), effective);
                            self.function_effects.insert(format!("{}::{}", self.module.name, function.name), effective);
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
        let return_type = function.return_type.as_ref().map(Self::convert_type);
        let (params, mut body) =
            self.lower_signature_and_body(&function.params, &[], &function.body, return_type.clone(), &HashSet::new());
        body.cell_bindings = bindings::resolve(&params, &body, bindings::BindingContext::Helper, &self.type_kinds);
        let inferred_effect_class = self.analyze_body_effect_class(&function.body);
        let declared_effect_class = function.effect_declared.then(|| self.convert_effect_class(function.effect));
        let effect_class = declared_effect_class
            .filter(|declared| self.effect_covers(*declared, inferred_effect_class))
            .unwrap_or(inferred_effect_class);

        IrPureFn { name: function.name.clone(), params, return_type, body, declared_effect_class, inferred_effect_class, effect_class }
    }

    fn layout_fields(&self, fields: &[Field]) -> Vec<IrField> {
        let mut next_offset = Some(0usize);
        fields
            .iter()
            .map(|field| {
                let ty = Self::convert_type(&field.ty);
                let fixed_size = self.fixed_encoded_size(&ty);
                let offset = next_offset.unwrap_or(0);
                next_offset = next_offset.and_then(|current| fixed_size.and_then(|size| current.checked_add(size)));
                IrField { name: field.name.clone(), ty, offset, fixed_size }
            })
            .collect()
    }

    fn register_enum_layouts(&mut self) {
        let names = self.enum_definitions.keys().cloned().collect::<Vec<_>>();
        let mut layouts = self.module.enum_layouts.clone();
        for name in names {
            let mut visiting = HashSet::new();
            match self.build_enum_layout(&name, &mut layouts, &mut visiting) {
                Some(layout) => {
                    self.module.enum_fixed_sizes.insert(name.clone(), layout.encoded_size);
                    layouts.insert(name, layout);
                }
                None => self.record_error(
                    format!(
                        "enum '{}' has no fixed-width runtime layout; generic, dynamic, and recursive payload ADTs are deferred",
                        name
                    ),
                    self.enum_definitions.get(&name).map_or(Span::default(), |definition| definition.span),
                ),
            }
        }
        self.module.enum_layouts = layouts;
    }

    fn build_enum_layout(
        &self,
        name: &str,
        layouts: &mut HashMap<String, IrEnumLayout>,
        visiting: &mut HashSet<String>,
    ) -> Option<IrEnumLayout> {
        if let Some(layout) = layouts.get(name) {
            return Some(layout.clone());
        }
        if !visiting.insert(name.to_string()) {
            return None;
        }
        let definition = self.enum_definitions.get(name)?;
        if definition.variants.is_empty() || definition.variants.len() > u8::MAX as usize + 1 {
            visiting.remove(name);
            return None;
        }

        let mut contains_linear_payload = false;
        let mut max_payload_width = 0usize;
        let mut variants = Vec::with_capacity(definition.variants.len());
        for (tag, variant) in definition.variants.iter().enumerate() {
            let mut next_offset = 1usize;
            let mut fields = Vec::with_capacity(variant.fields.len());
            for (index, field_ty) in variant.fields.iter().enumerate() {
                let ir_ty = Self::convert_type(field_ty);
                let (width, linear) = self.enum_payload_runtime_layout(&ir_ty, layouts, visiting)?;
                fields.push(IrEnumFieldLayout { index, ty: ir_ty, offset: next_offset, width, linear });
                next_offset = next_offset.checked_add(width)?;
                contains_linear_payload |= linear;
            }
            let payload_width = next_offset.checked_sub(1)?;
            max_payload_width = max_payload_width.max(payload_width);
            variants.push(IrEnumVariantLayout { name: variant.name.clone(), tag: u8::try_from(tag).ok()?, payload_width, fields });
        }
        visiting.remove(name);
        Some(IrEnumLayout {
            name: name.to_string(),
            tag_width: 1,
            encoded_size: 1usize.checked_add(max_payload_width)?,
            variants,
            contains_linear_payload,
        })
    }

    fn enum_payload_runtime_layout(
        &self,
        ty: &IrType,
        layouts: &mut HashMap<String, IrEnumLayout>,
        visiting: &mut HashSet<String>,
    ) -> Option<(usize, bool)> {
        match ty {
            IrType::U8 | IrType::Bool => Some((1, false)),
            IrType::U16 => Some((2, false)),
            IrType::U32 | IrType::I32 => Some((4, false)),
            IrType::U64 => Some((8, false)),
            IrType::U128 => Some((16, false)),
            IrType::Address | IrType::Hash => Some((32, false)),
            IrType::Unit => Some((0, false)),
            IrType::Array(inner, len) => {
                let (width, linear) = self.enum_payload_runtime_layout(inner, layouts, visiting)?;
                Some((width.checked_mul(*len)?, linear))
            }
            IrType::Tuple(items) => items.iter().try_fold((0usize, false), |(total, any_linear), item| {
                let (width, linear) = self.enum_payload_runtime_layout(item, layouts, visiting)?;
                Some((total.checked_add(width)?, any_linear || linear))
            }),
            IrType::Named(name) => {
                let base_name = name.split('<').next().unwrap_or(name.as_str());
                if base_name != name {
                    return None;
                }
                if matches!(self.type_kinds.get(base_name), Some(IrTypeKind::Resource | IrTypeKind::Shared | IrTypeKind::Receipt)) {
                    return Some((8, true));
                }
                if self.enum_definitions.contains_key(base_name) || layouts.contains_key(base_name) {
                    let layout = self.build_enum_layout(base_name, layouts, visiting)?;
                    let result = (layout.encoded_size, layout.contains_linear_payload);
                    layouts.insert(base_name.to_string(), layout);
                    return Some(result);
                }
                if !visiting.insert(base_name.to_string()) {
                    return None;
                }
                let result = self.type_fields.get(base_name)?.values().try_fold((0usize, false), |(total, any_linear), field_ty| {
                    let (width, linear) = self.enum_payload_runtime_layout(field_ty, layouts, visiting)?;
                    Some((total.checked_add(width)?, any_linear || linear))
                });
                visiting.remove(base_name);
                result
            }
            IrType::Ref(_) | IrType::MutRef(_) => None,
        }
    }

    fn fixed_encoded_size(&self, ty: &IrType) -> Option<usize> {
        self.fixed_encoded_size_with_seen(ty, &mut HashSet::new())
    }

    fn fixed_encoded_size_with_seen(&self, ty: &IrType, seen: &mut HashSet<String>) -> Option<usize> {
        match ty {
            IrType::U8 | IrType::Bool => Some(1),
            IrType::U16 => Some(2),
            IrType::U32 => Some(4),
            IrType::I32 => Some(4),
            IrType::U64 => Some(8),
            IrType::U128 => Some(16),
            IrType::Address | IrType::Hash => Some(32),
            IrType::Array(inner, len) => {
                self.fixed_encoded_size_with_seen(inner, seen).and_then(|inner_size| inner_size.checked_mul(*len))
            }
            IrType::Tuple(items) => items
                .iter()
                .try_fold(0usize, |acc, item| self.fixed_encoded_size_with_seen(item, seen).and_then(|size| acc.checked_add(size))),
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
        let core_input_bindings = action_core_input_binding_names(action);
        let return_type = action.return_type.as_ref().map(Self::convert_type);
        let (params, mut body) =
            self.lower_signature_and_body(&action.params, &action.outputs, &action.body, return_type.clone(), &core_input_bindings);
        let context = if action.next_surface.is_some() {
            bindings::BindingContext::NativeTypeGroup
        } else {
            bindings::BindingContext::LegacyEntry
        };
        body.cell_bindings = bindings::resolve(&params, &body, context, &self.type_kinds);

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
            entry_trigger: action.next_surface.as_ref().map(|surface| format!("type-group<{}>", surface.trigger_type)),
            source_dispositions: action
                .next_surface
                .as_ref()
                .map_or_else(Vec::new, |surface| self.lower_source_dispositions(&action.name, &surface.dispositions)),
            audit_claims: action.next_surface.as_ref().map_or_else(Vec::new, |surface| Self::lower_audit_claims(&surface.audits)),
            params,
            return_type,
            state_transition_edges: self.action_state_transition_edges(action),
            protocol_role_candidates: self.action_protocol_role_candidates(action),
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

    fn lower_source_dispositions(&self, entry_name: &str, dispositions: &[crate::ast::NextDisposition]) -> Vec<IrSourceDisposition> {
        dispositions
            .iter()
            .flat_map(|disposition| match disposition {
                crate::ast::NextDisposition::Replace(replacement) => vec![IrSourceDisposition {
                    kind: IrSourceDispositionKind::Successor,
                    input_binding: Some(replacement.input.clone()),
                    output_binding: Some(replacement.output.clone()),
                    data_fields: replacement
                        .data_fields
                        .iter()
                        .map(|field| (field.clone(), "checked-successor-relation".to_string()))
                        .collect(),
                    lock_expression: Some(crate::fmt::format_expression(&replacement.lock_script)),
                    span: replacement.span,
                }],
                crate::ast::NextDisposition::Pool(pool) => {
                    let pool_id = format!("pool:{entry_name}:{}", pool.name);
                    let accounting_obligation = pool
                        .data_fields
                        .iter()
                        .filter_map(|field| match &field.treatment {
                            crate::ast::NextPoolFieldTreatment::Conserve => {
                                Some(format!("checked-u128-field-sum-equality:{}", field.field))
                            }
                            crate::ast::NextPoolFieldTreatment::Set(_) => None,
                        })
                        .collect::<Vec<_>>()
                        .join("+");
                    let mut lowered = pool
                        .inputs
                        .iter()
                        .map(|input| IrSourceDisposition {
                            kind: IrSourceDispositionKind::PooledInput {
                                pool_id: pool_id.clone(),
                                accounting_obligation: accounting_obligation.clone(),
                            },
                            input_binding: Some(input.clone()),
                            output_binding: None,
                            data_fields: pool
                                .data_fields
                                .iter()
                                .map(|field| {
                                    let treatment = match &field.treatment {
                                        crate::ast::NextPoolFieldTreatment::Conserve => {
                                            format!("contributes-to:{}:conserve", pool_id)
                                        }
                                        crate::ast::NextPoolFieldTreatment::Set(_) => format!("available-to:{}:output-plan", pool_id),
                                    };
                                    (field.field.clone(), treatment)
                                })
                                .collect(),
                            lock_expression: None,
                            span: pool.span,
                        })
                        .collect::<Vec<_>>();
                    lowered.extend(pool.outputs.iter().map(|output| {
                        IrSourceDisposition {
                            kind: IrSourceDispositionKind::PoolResult {
                                pool_id: pool_id.clone(),
                                accounting_obligation: accounting_obligation.clone(),
                            },
                            input_binding: None,
                            output_binding: Some(output.clone()),
                            data_fields: pool
                                .data_fields
                                .iter()
                                .map(|field| {
                                    let treatment = match &field.treatment {
                                        crate::ast::NextPoolFieldTreatment::Conserve => {
                                            format!("checked-by:{}:field-sum-equality", pool_id)
                                        }
                                        crate::ast::NextPoolFieldTreatment::Set(assignments) => assignments
                                            .iter()
                                            .find(|(candidate, _)| candidate == output)
                                            .map(|(_, expression)| {
                                                format!("set-from-expression:{}", crate::fmt::format_expression(expression))
                                            })
                                            .expect("validated pool output field assignment"),
                                    };
                                    (field.field.clone(), treatment)
                                })
                                .collect(),
                            lock_expression: pool
                                .output_locks
                                .iter()
                                .find(|(candidate, _)| candidate == output)
                                .map(|(_, expression)| crate::fmt::format_expression(expression)),
                            span: pool.span,
                        }
                    }));
                    lowered
                }
                crate::ast::NextDisposition::Retire(retirement) => vec![IrSourceDisposition {
                    kind: IrSourceDispositionKind::Retired { absence_policy: source_absence_policy(&retirement.absence_policy) },
                    input_binding: Some(retirement.input.clone()),
                    output_binding: None,
                    data_fields: Vec::new(),
                    lock_expression: None,
                    span: retirement.span,
                }],
                crate::ast::NextDisposition::Fresh(fresh) => vec![IrSourceDisposition {
                    kind: IrSourceDispositionKind::Fresh { identity_policy: source_identity_policy(&fresh.identity) },
                    input_binding: None,
                    output_binding: Some(fresh.output.clone()),
                    data_fields: fresh
                        .data_fields
                        .iter()
                        .map(|(field, value)| (field.clone(), crate::fmt::format_expression(value)))
                        .collect(),
                    lock_expression: Some(crate::fmt::format_expression(&fresh.lock_script)),
                    span: fresh.span,
                }],
            })
            .collect()
    }

    fn lower_audit_claims(audits: &[crate::ast::NextAudit]) -> Vec<IrAuditClaim> {
        audits
            .iter()
            .map(|audit| IrAuditClaim {
                name: audit.name.clone(),
                evidence: match audit.evidence {
                    crate::ast::NextAuditEvidence::ExternalPolicy => "external-policy".to_string(),
                },
                subject: crate::fmt::format_expression(&audit.subject),
                span: audit.span,
            })
            .collect()
    }

    fn action_protocol_role_candidates(&self, action: &ActionDef) -> Vec<IrProtocolRoleCandidate> {
        let mut candidates = Vec::new();
        let mut equalities = Vec::new();
        collect_protocol_role_equalities_from_statements(&action.body, &mut equalities);

        for equality in equalities {
            let predicate = crate::fmt::format_expression(&Expr::Binary(equality.clone()));
            for (field_side, actor_side) in
                [(equality.left.as_ref(), equality.right.as_ref()), (equality.right.as_ref(), equality.left.as_ref())]
            {
                let Some((cell_binding, field_name)) = protocol_role_field_access(field_side) else {
                    continue;
                };
                let Expr::Identifier(actor_binding) = actor_side else {
                    continue;
                };
                let Some(cell_param) = action.params.iter().find(|param| param.name == cell_binding) else {
                    continue;
                };
                let Some(type_name) = Self::named_type_name_from_ast_type(&cell_param.ty) else {
                    continue;
                };
                if !self.type_fields.get(type_name).and_then(|fields| fields.get(field_name)).is_some_and(|ty| *ty == IrType::Address)
                {
                    continue;
                }
                let Some(actor_param) = action.params.iter().find(|param| param.name == *actor_binding) else {
                    continue;
                };
                if !protocol_role_actor_param(actor_param) {
                    continue;
                }
                let role = protocol_role_name(field_name).unwrap_or_else(|| field_name.to_ascii_lowercase());
                candidates.push(IrProtocolRoleCandidate {
                    role,
                    source: "verification-predicate".to_string(),
                    strength: "explicit".to_string(),
                    actor_binding: Some(actor_binding.clone()),
                    actor_source: Some(protocol_role_param_source(actor_param.source).to_string()),
                    cell_binding: Some(cell_binding.to_string()),
                    field_name: Some(field_name.to_string()),
                    predicate: Some(predicate.clone()),
                    span: Some(equality.span),
                });
            }
        }

        for param in &action.params {
            if !matches!(&param.ty, Type::Address) {
                continue;
            }
            let Some(role) = protocol_role_name(&param.name) else {
                continue;
            };
            let (source, actor_source) = match param.source {
                ParamSource::Witness => ("witness-binding", "witness"),
                ParamSource::LockArgs => ("lock-args-binding", "lock_args"),
                ParamSource::Default => ("witness-binding", "entry-witness-default"),
                ParamSource::Input | ParamSource::Output | ParamSource::Protected => continue,
            };
            candidates.push(IrProtocolRoleCandidate {
                role,
                source: source.to_string(),
                strength: "binding".to_string(),
                actor_binding: Some(param.name.clone()),
                actor_source: Some(actor_source.to_string()),
                cell_binding: None,
                field_name: None,
                predicate: None,
                span: Some(param.span),
            });
        }

        for param in &action.params {
            let Some(type_name) = Self::named_type_name_from_ast_type(&param.ty) else {
                continue;
            };
            let Some(fields) = self.type_fields.get(type_name) else {
                continue;
            };
            let mut fields = fields.iter().collect::<Vec<_>>();
            fields.sort_by_key(|(name, _)| *name);
            for (field_name, field_ty) in fields {
                if *field_ty != IrType::Address {
                    continue;
                }
                let Some(role) = protocol_role_name(field_name) else {
                    continue;
                };
                candidates.push(IrProtocolRoleCandidate {
                    role,
                    source: "field-name".to_string(),
                    strength: "weak".to_string(),
                    actor_binding: None,
                    actor_source: None,
                    cell_binding: Some(param.name.clone()),
                    field_name: Some(field_name.clone()),
                    predicate: None,
                    span: None,
                });
            }
        }

        candidates.sort_by(|left, right| {
            protocol_role_source_rank(&left.source)
                .cmp(&protocol_role_source_rank(&right.source))
                .then_with(|| left.role.cmp(&right.role))
                .then_with(|| left.actor_binding.cmp(&right.actor_binding))
                .then_with(|| left.cell_binding.cmp(&right.cell_binding))
                .then_with(|| left.field_name.cmp(&right.field_name))
                .then_with(|| left.predicate.cmp(&right.predicate))
        });
        candidates.dedup();
        candidates
    }

    fn action_state_transition_edges(&self, action: &ActionDef) -> Vec<IrStateTransitionEdge> {
        let mut edges = Vec::new();
        for state_edge in &action.state_edges {
            let path = &state_edge.path;
            let Some(param) = action.params.iter().find(|param| param.name == path.base) else {
                continue;
            };
            let Some(type_name) = Self::named_type_name_from_ast_type(&param.ty) else {
                continue;
            };
            if let Some(mut lowered) = self.state_transition_edge_for(type_name, &path.field, &state_edge.from, &state_edge.to) {
                lowered.input_binding = Some(path.base.clone());
                lowered.output_binding = Some(state_edge.to_path.base.clone());
                edges.push(lowered);
            }
        }

        let mut unique = Vec::new();
        for state_edge in edges {
            if !unique.iter().any(|existing: &IrStateTransitionEdge| {
                existing.type_name == state_edge.type_name
                    && existing.field_name == state_edge.field_name
                    && existing.input_binding == state_edge.input_binding
                    && existing.output_binding == state_edge.output_binding
                    && existing.from_index == state_edge.from_index
                    && existing.to_index == state_edge.to_index
            }) {
                unique.push(state_edge);
            }
        }
        unique
    }

    fn state_transition_edge_for(&self, type_name: &str, field_name: &str, from: &str, to: &str) -> Option<IrStateTransitionEdge> {
        if self.flow_state_fields.get(type_name).is_some_and(|field| field != field_name) {
            return None;
        }
        let states = self.flow_states.get(type_name)?;
        let from = self.canonical_state_name(type_name, from);
        let to = self.canonical_state_name(type_name, to);
        let from_index = states.iter().position(|state| state == &from)?;
        let to_index = states.iter().position(|state| state == &to)?;
        Some(IrStateTransitionEdge {
            input_binding: None,
            output_binding: None,
            type_name: type_name.to_string(),
            field_name: field_name.to_string(),
            from,
            to,
            from_index,
            to_index,
        })
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
        let previous_lock_entry = self.lowering_lock_entry;
        self.lowering_lock_entry = true;
        let (params, mut body) = self.lower_signature_and_body(&lock.params, &[], &lock.body, Some(IrType::Bool), &HashSet::new());
        let context = if lock.next_surface.is_some() {
            bindings::BindingContext::NativeLockGroup
        } else {
            bindings::BindingContext::LegacyLockEntry
        };
        body.cell_bindings = bindings::resolve(&params, &body, context, &self.type_kinds);
        self.lowering_lock_entry = previous_lock_entry;

        IrLock {
            name: lock.name.clone(),
            params,
            audit_claims: lock.next_surface.as_ref().map_or_else(Vec::new, |surface| Self::lower_audit_claims(&surface.audits)),
            body,
        }
    }

    fn convert_type(ty: &Type) -> IrType {
        match ty {
            Type::U8 => IrType::U8,
            Type::U16 => IrType::U16,
            Type::U32 => IrType::U32,
            Type::I32 => IrType::I32,
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
        if !action_core_input_binding_names(action).is_empty() {
            return EffectClass::Mutating;
        }
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
        effect_class_covers(declared, inferred)
    }

    fn check_stmt_effects(&self, stmt: &Stmt, footprint: &mut EffectFootprint) {
        match stmt {
            Stmt::Expr(expr) | Stmt::Let(LetStmt { value: expr, .. }) => {
                self.check_expr_effects(expr, footprint);
            }
            Stmt::Return(ReturnStmt { value: Some(expr), .. }) => {
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
            Stmt::Borrow(borrow_stmt) => {
                for stmt in &borrow_stmt.body {
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
            Expr::Destroy(destroy) => {
                footprint.has_consume = true;
                self.check_expr_effects(&destroy.expr, footprint);
            }
            Expr::Claim(claim) => {
                self.apply_effect_to_footprint(EffectClass::Mutating, footprint);
                self.check_expr_effects(&claim.receipt, footprint);
            }
            Expr::Settle(settle) => {
                self.apply_effect_to_footprint(EffectClass::Mutating, footprint);
                self.check_expr_effects(&settle.expr, footprint);
            }
            Expr::CreateUnique(create) => {
                self.apply_effect_to_footprint(EffectClass::Creating, footprint);
                for (_, value) in &create.fields {
                    self.check_expr_effects(value, footprint);
                }
                if let Some(lock) = &create.lock {
                    self.check_expr_effects(lock, footprint);
                }
            }
            Expr::ReplaceUnique(replace) => {
                self.apply_effect_to_footprint(EffectClass::Mutating, footprint);
                self.check_expr_effects(&replace.expr, footprint);
                for (_, value) in &replace.fields {
                    self.check_expr_effects(value, footprint);
                }
            }
            Expr::ReadRef(_) => {
                footprint.has_read_ref = true;
            }
            Expr::Assert(assert_expr) => {
                self.check_expr_effects(&assert_expr.condition, footprint);
            }
            Expr::Require(require_expr) => {
                self.check_expr_effects(&require_expr.condition, footprint);
                if let Some(message) = &require_expr.message {
                    self.check_expr_effects(message, footprint);
                }
            }
            Expr::RequireBlock(require_block) => {
                for expr in &require_block.expressions {
                    self.check_expr_effects(expr, footprint);
                }
            }
            Expr::Preserve(_) => {
                // preserve is pure sugar; desugared requires carry no side effects beyond verification
            }
            Expr::ReplaceRelation(relation) => {
                footprint.has_consume = true;
                footprint.has_create = true;
                if let ReplaceLockTreatment::Exact(lock) | ReplaceLockTreatment::ExactHash(lock) = &relation.lock {
                    self.check_expr_effects(lock, footprint);
                }
                match &relation.data {
                    ReplaceDataTreatment::Fields(treatments) => {
                        for treatment in treatments {
                            if let ReplaceFieldTreatment::Assign(_, value) = treatment {
                                self.check_expr_effects(value, footprint);
                            }
                        }
                    }
                    ReplaceDataTreatment::SameExcept(assigned) => {
                        for (_, value) in assigned {
                            self.check_expr_effects(value, footprint);
                        }
                    }
                }
            }
            Expr::StdlibCall(call) => {
                let qualified = format!("std::{}::{}", call.namespace, call.name);
                match qualified.as_str() {
                    "std::lifecycle::transfer" | "std::receipt::claim" | "std::lifecycle::settle" => {
                        self.apply_effect_to_footprint(EffectClass::Mutating, footprint);
                    }
                    _ => {
                        // constraint patterns are verification-only
                    }
                }
                for arg in &call.args {
                    self.check_expr_effects(arg, footprint);
                }
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
                if is_read_only_runtime_call(call) {
                    self.apply_effect_to_footprint(EffectClass::ReadOnly, footprint);
                }
                if let Expr::Identifier(name) = call.func.as_ref() {
                    if name == "__cellscript_consume_each" {
                        self.apply_effect_to_footprint(EffectClass::Mutating, footprint);
                    } else if name == "__cellscript_create_each" {
                        self.apply_effect_to_footprint(EffectClass::Creating, footprint);
                    } else if let Some(effect) = self.function_effects.get(name).copied() {
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
        apply_effect_to_footprint(effect, footprint);
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

    fn lower_signature_and_body(
        &mut self,
        params: &[Param],
        outputs: &[crate::ast::ActionOutput],
        stmts: &[Stmt],
        return_type: Option<IrType>,
        core_input_bindings: &HashSet<String>,
    ) -> (Vec<IrParam>, IrBody) {
        self.borrow_regions.clear();
        self.enforced_claims.clear();
        self.loop_targets.clear();
        let mut vars = HashMap::new();
        let mut ir_params = params
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
                    source: param.source,
                    binding,
                }
            })
            .collect::<Vec<_>>();
        for output in outputs {
            let binding = self.new_var(output.name.clone(), Self::convert_type(&output.ty));
            vars.insert(output.name.clone(), binding.clone());
            ir_params.push(IrParam {
                name: output.name.clone(),
                ty: Self::convert_type(&output.ty),
                is_mut: false,
                is_ref: false,
                is_read_ref: false,
                source: ParamSource::Output,
                binding,
            });
        }
        self.transition_param_ids = ir_params.iter().map(|param| param.binding.id).collect();
        let mut blocks = Vec::new();
        let entry = self.push_block(&mut blocks);
        let tail_expr_returns = return_type.is_some();
        let _ = self.lower_stmts(stmts, entry, &mut blocks, &mut vars, return_type.as_ref(), tail_expr_returns);
        let consume_set = self.collect_consume_patterns(&blocks, &ir_params, core_input_bindings);
        let mut read_refs = self.collect_read_ref_param_patterns(&ir_params);
        read_refs.extend(self.collect_read_ref_patterns(&blocks));
        let create_set = self.collect_create_patterns(&blocks, &ir_params);
        let mutate_set = self.collect_mutate_param_patterns(&ir_params, consume_set.len(), create_set.len());
        let write_intents = Self::collect_write_intents(&create_set, &mutate_set);
        let mut bounded_collection_ops = collect_bounded_collection_ops(stmts, params);
        for operation in &mut bounded_collection_ops {
            if operation.operation == "consume_each"
                && let Some(width) =
                    self.bounded_consume_runtime_width(&operation.element_type, operation.source, operation.max_elements)
            {
                operation.runtime_contract = Some(BOUNDED_TYPE_GROUP_INPUTS_V1.to_string());
                operation.element_width = Some(width);
            } else if operation.operation == "create_each"
                && let Some(width) = self.bounded_create_runtime_width(operation)
            {
                operation.runtime_contract = Some(BOUNDED_OUTPUT_PLAN_V1.to_string());
                operation.element_width = Some(width);
            }
        }
        let borrow_regions = std::mem::take(&mut self.borrow_regions);
        let trusted_external_calls = std::mem::take(&mut self.trusted_external_calls);
        let enforced_claims = std::mem::take(&mut self.enforced_claims);
        self.transition_param_ids.clear();
        self.transition_coverable_value_ids.clear();

        (
            ir_params,
            IrBody {
                cell_bindings: Vec::new(),
                consume_set,
                read_refs,
                create_set,
                mutate_set,
                write_intents,
                bounded_collection_ops,
                borrow_regions,
                trusted_external_calls,
                enforced_claims,
                blocks,
            },
        )
    }

    fn bounded_consume_runtime_width(&self, element_type: &str, source: ParamSource, max_elements: usize) -> Option<usize> {
        if source != ParamSource::Input || !(1..=1024).contains(&max_elements) {
            return None;
        }
        if self.type_kinds.get(element_type) != Some(&IrTypeKind::Resource) {
            return None;
        }
        let width = self.fixed_encoded_size(&IrType::Named(element_type.to_string()))?;
        (width > 0 && width <= BOUNDED_CELL_RUNTIME_MAX_DATA_BYTES).then_some(width)
    }

    fn bounded_create_runtime_width(&self, operation: &IrBoundedCollectionOp) -> Option<usize> {
        if operation.source != ParamSource::Witness || !(1..=1024).contains(&operation.max_elements) {
            return None;
        }
        if self.type_kinds.get(&operation.element_type) != Some(&IrTypeKind::Struct) {
            return None;
        }
        let plan_width = self.fixed_encoded_size(&IrType::Named(operation.element_type.clone()))?;
        let encoded_max = operation.max_elements.checked_mul(plan_width)?.checked_add(12)?;
        if plan_width == 0 || encoded_max > BOUNDED_OUTPUT_PLAN_MAX_BYTES {
            return None;
        }
        let output_type = operation.output_type.as_ref()?;
        if self.type_kinds.get(output_type) != Some(&IrTypeKind::Resource)
            || self
                .fixed_encoded_size(&IrType::Named(output_type.clone()))
                .is_none_or(|width| width == 0 || width > BOUNDED_CELL_RUNTIME_MAX_DATA_BYTES)
            || self.type_capacity_floors.get(output_type).copied().is_none_or(|floor| floor == 0)
            || self.type_identities.get(output_type) != Some(&IrIdentityPolicy::None)
        {
            return None;
        }
        let template = operation.create_template.as_ref()?;
        let required_fields = self.type_fields.get(output_type)?;
        if template.lock.is_none()
            || template.fields.len() != required_fields.len()
            || !required_fields.keys().all(|field| template.fields.iter().any(|(name, _)| name == field))
        {
            return None;
        }
        Some(plan_width)
    }

    fn collect_write_intents(create_set: &[CreatePattern], mutate_set: &[MutatePattern]) -> Vec<WriteIntent> {
        let create_intents = create_set.iter().enumerate().map(|(index, pattern)| WriteIntent {
            operation: pattern.operation.clone(),
            ty: pattern.ty.clone(),
            binding: pattern.binding.clone(),
            index,
            fields: pattern.fields.iter().map(|(field, _)| field.clone()).collect(),
        });
        let mutate_intents = mutate_set.iter().map(|pattern| WriteIntent {
            operation: pattern.operation.clone(),
            ty: pattern.ty.clone(),
            binding: pattern.binding.clone(),
            index: pattern.output_index,
            fields: pattern.fields.clone(),
        });

        create_intents.chain(mutate_intents).collect()
    }

    fn collect_consume_patterns(
        &self,
        blocks: &[IrBlock],
        params: &[IrParam],
        core_input_bindings: &HashSet<String>,
    ) -> Vec<CellPattern> {
        let mut patterns = params
            .iter()
            .filter(|param| core_input_bindings.contains(param.name.as_str()))
            .filter_map(|param| self.cell_pattern_from_var(&param.binding, "input"))
            .collect::<Vec<_>>();
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
                } else if let IrInstruction::Destroy { operand, .. } = instruction {
                    if let Some(pattern) = self.cell_pattern_from_operand(operand, "destroy") {
                        patterns.push(pattern);
                    }
                } else if let IrInstruction::ReplaceUnique { operand, .. } = instruction {
                    if let Some(pattern) = self.cell_pattern_from_operand(operand, "replace_unique") {
                        patterns.push(pattern);
                    }
                } else if let IrInstruction::Claim { receipt, .. } = instruction {
                    if let Some(pattern) = self.cell_pattern_from_operand(receipt, "claim") {
                        patterns.push(pattern);
                    }
                } else if let IrInstruction::Settle { operand, .. } = instruction
                    && let Some(pattern) = self.cell_pattern_from_operand(operand, "settle")
                {
                    patterns.push(pattern);
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

    fn collect_create_patterns(&self, blocks: &[IrBlock], params: &[IrParam]) -> Vec<CreatePattern> {
        let output_bindings =
            params.iter().filter(|param| param.source == ParamSource::Output).map(|param| param.name.clone()).collect::<HashSet<_>>();
        let mut patterns = params
            .iter()
            .filter(|param| param.source == ParamSource::Output)
            .filter_map(|param| self.create_pattern_from_var(&param.binding, "output"))
            .collect::<Vec<_>>();
        for block in blocks {
            for instruction in &block.instructions {
                if let IrInstruction::Create { pattern, .. } = instruction {
                    if pattern.operation == "output" && output_bindings.contains(&pattern.binding) {
                        if let Some(existing) = patterns.iter_mut().find(|existing| existing.binding == pattern.binding) {
                            *existing = pattern.clone();
                        } else {
                            patterns.push(pattern.clone());
                        }
                    } else {
                        patterns.push(pattern.clone());
                    }
                } else if let IrInstruction::CreateUnique { pattern, .. } = instruction {
                    patterns.push(pattern.clone());
                } else if let IrInstruction::ReplaceUnique { pattern, .. } = instruction {
                    patterns.push(pattern.clone());
                } else if let IrInstruction::Transfer { dest, to, .. } = instruction {
                    if let Some(pattern) = self.create_pattern_from_var_with_lock(dest, "transfer", Some(to.clone())) {
                        patterns.push(pattern);
                    }
                } else if let IrInstruction::Claim { dest, .. } = instruction {
                    if let Some(pattern) = self.create_pattern_from_var(dest, "claim") {
                        patterns.push(pattern);
                    }
                } else if let IrInstruction::Settle { dest, .. } = instruction
                    && let Some(pattern) = self.create_pattern_from_var(dest, "settle")
                {
                    patterns.push(pattern);
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
        self.cell_pattern_from_var(var, operation)
    }

    fn cell_pattern_from_var(&self, var: &IrVar, operation: &str) -> Option<CellPattern> {
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
        Some(CreatePattern {
            operation: operation.to_string(),
            ty: type_name.to_string(),
            binding: var.name.clone(),
            fields,
            lock,
            identity: IrIdentityPolicy::None,
        })
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
        blocks: &mut [IrBlock],
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
            if &source_field_ty != output_field_ty || !is_verifier_coverable_output_field_type(output_field_ty) {
                continue;
            }
            if let Some(field_var) = self.materialize_schema_field(source_var, &field_name, active, blocks) {
                field_vars.insert(field_name, field_var);
            }
        }
        field_vars
    }

    fn named_type_name_from_ast_type(ty: &Type) -> Option<&str> {
        match ty {
            Type::Named(name) => Some(name.as_str()),
            Type::Ref(inner) | Type::MutRef(inner) => Self::named_type_name_from_ast_type(inner),
            _ => None,
        }
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
            if let Some(type_hash) = pattern.type_hash
                && shared_hashes.contains(&type_hash)
            {
                hashes.push(type_hash);
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
        return_type: Option<&IrType>,
        tail_expr_returns: bool,
    ) -> Option<BlockId> {
        for (index, stmt) in stmts.iter().enumerate() {
            if tail_expr_returns && index + 1 == stmts.len() {
                if let Stmt::Expr(expr) = stmt {
                    let lowered = if let Some(return_type) = return_type {
                        self.lower_expr_with_expected_type(expr, return_type, current, blocks, vars)
                    } else {
                        self.lower_expr(expr, current, blocks, vars)
                    };
                    let active = lowered.current?;
                    self.block_mut(blocks, active).terminator = IrTerminator::Return(Some(lowered.operand));
                    return None;
                }
                if let Stmt::If(if_stmt) = stmt {
                    return self.lower_if_stmt(if_stmt, current, blocks, vars, return_type, true);
                }
            }
            let next = self.lower_stmt(stmt, current, blocks, vars, return_type)?;
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
        return_type: Option<&IrType>,
    ) -> Option<BlockId> {
        match stmt {
            Stmt::Let(let_stmt) => {
                let transition_coverable = matches!(let_stmt.pattern, BindingPattern::Name(_))
                    && self.transition_expr_is_coverable_u64(&let_stmt.value, vars);
                let lowered = match &let_stmt.ty {
                    Some(declared_ty) => {
                        self.lower_expr_with_expected_type(&let_stmt.value, &Self::convert_type(declared_ty), current, blocks, vars)
                    }
                    None => self.lower_expr(&let_stmt.value, current, blocks, vars),
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
            Stmt::Return(ReturnStmt { value: None, .. }) => {
                self.block_mut(blocks, current).terminator = IrTerminator::Return(None);
                None
            }
            Stmt::Return(ReturnStmt { value: Some(expr), .. }) => {
                let lowered = if let Some(return_type) = return_type {
                    self.lower_expr_with_expected_type(expr, return_type, current, blocks, vars)
                } else {
                    self.lower_expr(expr, current, blocks, vars)
                };
                let active = lowered.current?;
                self.block_mut(blocks, active).terminator = IrTerminator::Return(Some(lowered.operand));
                None
            }
            Stmt::If(if_stmt) => self.lower_if_stmt(if_stmt, current, blocks, vars, return_type, false),
            Stmt::For(for_stmt) => self.lower_for_stmt(for_stmt, current, blocks, vars, return_type),
            Stmt::While(while_stmt) => self.lower_while_stmt(while_stmt, current, blocks, vars, return_type),
            Stmt::Break(control) | Stmt::Continue(control) => {
                let target = self
                    .loop_targets
                    .iter()
                    .rev()
                    .find(|target| control.label.as_ref().is_none_or(|label| target.label.as_ref() == Some(label)))
                    .cloned();
                let Some(target) = target else {
                    self.record_error("loop control has no matching lowered loop", control.span);
                    return Some(current);
                };
                let destination = if matches!(stmt, Stmt::Break(_)) { target.break_block } else { target.continue_block };
                self.block_mut(blocks, current).terminator = IrTerminator::Jump(destination);
                None
            }
            Stmt::Borrow(borrow_stmt) => {
                let Some(root) = vars.get(&borrow_stmt.root).cloned() else {
                    self.record_error(format!("borrow root '{}' was not lowered", borrow_stmt.root), borrow_stmt.span);
                    return Some(current);
                };
                let mut projected = root.clone();
                for field in &borrow_stmt.path {
                    let Some(next) = self.materialize_schema_field(&projected, field, current, blocks) else {
                        self.record_error(
                            format!("borrow path '{}.{}' has no lowered field", borrow_stmt.root, borrow_stmt.path.join(".")),
                            borrow_stmt.span,
                        );
                        return Some(current);
                    };
                    projected = next;
                }
                let view_target = match &projected.ty {
                    IrType::Ref(inner) | IrType::MutRef(inner) => inner.as_ref().clone(),
                    ty => ty.clone(),
                };
                let parent_region = self.borrow_regions.iter().rev().find(|region| region.binding == borrow_stmt.root).cloned();
                let canonical_root = parent_region.as_ref().map_or_else(|| borrow_stmt.root.clone(), |region| region.root.clone());
                let mut canonical_path = parent_region.map_or_else(Vec::new, |region| region.path);
                canonical_path.extend(borrow_stmt.path.iter().cloned());
                let region_index = self.borrow_regions.len();
                let start_instruction = self.block_mut(blocks, current).instructions.len();
                self.borrow_regions.push(IrBorrowRegion {
                    root: canonical_root,
                    path: canonical_path,
                    binding: borrow_stmt.binding.clone(),
                    root_type: ir_type_display(&root.ty),
                    view_type: ir_type_display(&view_target),
                    start_block: current,
                    start_instruction,
                    end_block: None,
                    end_instruction: None,
                    span: borrow_stmt.span,
                });
                let view = IrVar { id: projected.id, name: borrow_stmt.binding.clone(), ty: IrType::Ref(Box::new(view_target)) };
                let previous = vars.insert(borrow_stmt.binding.clone(), view);
                let exit = self.lower_stmts(&borrow_stmt.body, current, blocks, vars, return_type, false);
                if let Some(end_block) = exit {
                    self.borrow_regions[region_index].end_block = Some(end_block);
                    self.borrow_regions[region_index].end_instruction = Some(self.block_mut(blocks, end_block).instructions.len());
                }
                if let Some(previous) = previous {
                    vars.insert(borrow_stmt.binding.clone(), previous);
                } else {
                    vars.remove(&borrow_stmt.binding);
                }
                exit
            }
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
            Expr::Integer(value) => {
                LoweredExpr { operand: IrOperand::Const(Self::default_integer_const(*value)), current: Some(current) }
            }
            Expr::Bool(value) => LoweredExpr { operand: IrOperand::Const(IrConst::Bool(*value)), current: Some(current) },
            Expr::Identifier(name) => {
                if let Some(var) = vars.get(name).cloned() {
                    LoweredExpr { operand: IrOperand::Var(var), current: Some(current) }
                } else if let Some(constant) = self.lower_constant(name, Span::default()) {
                    LoweredExpr { operand: constant, current: Some(current) }
                } else if let Some(zero) = self.lower_zero_value(name) {
                    LoweredExpr { operand: zero, current: Some(current) }
                } else if let Some(lowered) = self.try_lower_enum_constructor_path(name, &[], current, blocks, vars, Span::default()) {
                    lowered
                } else if let Some(enum_variant) = self.lower_enum_variant(name) {
                    LoweredExpr { operand: enum_variant, current: Some(current) }
                } else if let Some(flow_state) = self.lower_flow_state_name(name) {
                    LoweredExpr { operand: flow_state, current: Some(current) }
                } else {
                    self.record_error(format!("IR lowering encountered unresolved identifier '{}'", name), Span::default());
                    LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(current) }
                }
            }
            Expr::Assign(assign) => self.lower_assign_expr(assign, current, blocks, vars),
            Expr::Binary(binary) => {
                let (left, right, active) = if let Expr::Integer(left_value) = binary.left.as_ref() {
                    let right = self.lower_expr(&binary.right, current, blocks, vars);
                    let Some(active) = right.current else {
                        return right;
                    };
                    let right_ty = self.operand_type(&right.operand);
                    let left = if matches!(binary.op, BinaryOp::Shl | BinaryOp::Shr) {
                        LoweredExpr { operand: IrOperand::Const(Self::default_integer_const(*left_value)), current: Some(active) }
                    } else {
                        Self::integer_const_for_expected_type(*left_value, &right_ty)
                            .map(|value| LoweredExpr { operand: IrOperand::Const(value), current: Some(active) })
                            .unwrap_or_else(|| LoweredExpr {
                                operand: IrOperand::Const(Self::default_integer_const(*left_value)),
                                current: Some(active),
                            })
                    };
                    (left, right, active)
                } else {
                    let left = self.lower_expr(&binary.left, current, blocks, vars);
                    let Some(active) = left.current else {
                        return left;
                    };
                    let right = if let Expr::Integer(right_value) = binary.right.as_ref() {
                        let left_ty = self.operand_type(&left.operand);
                        if matches!(binary.op, BinaryOp::Shl | BinaryOp::Shr) {
                            LoweredExpr { operand: IrOperand::Const(Self::default_integer_const(*right_value)), current: Some(active) }
                        } else {
                            Self::integer_const_for_expected_type(*right_value, &left_ty)
                                .map(|value| LoweredExpr { operand: IrOperand::Const(value), current: Some(active) })
                                .unwrap_or_else(|| LoweredExpr {
                                    operand: IrOperand::Const(Self::default_integer_const(*right_value)),
                                    current: Some(active),
                                })
                        }
                    } else {
                        self.lower_expr(&binary.right, active, blocks, vars)
                    };
                    let Some(active) = right.current else {
                        return right;
                    };
                    (left, right, active)
                };
                let dest = self.new_var("tmp", self.binary_result_type_for_operands(binary.op, &left.operand, &right.operand));
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
                if let Expr::Identifier(path) = call.func.as_ref()
                    && let Some(lowered) = self.try_lower_enum_constructor_path(path, &call.args, current, blocks, vars, call.span)
                {
                    return lowered;
                }
                if let Some(lowered) = self.try_lower_builtin_call(call, current, blocks, vars) {
                    return lowered;
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
                let param_types = self.call_param_types(source_func, &func);
                let mut active = current;
                let mut args = Vec::with_capacity(call.args.len());
                for (index, arg) in call.args.iter().enumerate() {
                    let lowered = if let Some(expected_ty) = param_types.as_ref().and_then(|params| params.get(index)) {
                        self.lower_expr_with_expected_type(arg, expected_ty, active, blocks, vars)
                    } else {
                        self.lower_expr(arg, active, blocks, vars)
                    };
                    let Some(next) = lowered.current else {
                        return lowered;
                    };
                    active = next;
                    args.push(lowered.operand);
                }
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
            Expr::Destroy(destroy) => self.lower_destroy_expr(destroy, current, blocks, vars),
            Expr::Claim(claim) => self.lower_claim_expr(claim, current, blocks, vars),
            Expr::Settle(settle) => self.lower_settle_expr(settle, current, blocks, vars),
            Expr::CreateUnique(cu) => self.lower_create_unique_expr(cu, current, blocks, vars),
            Expr::ReplaceUnique(ru) => self.lower_replace_unique_expr(ru, current, blocks, vars),
            Expr::Assert(assert_expr) => self.lower_assert_expr(assert_expr, current, blocks, vars),
            Expr::Require(require_expr) => self.lower_require_expr(require_expr, current, blocks, vars),
            Expr::RequireBlock(require_block) => self.lower_require_block_expr(require_block, current, blocks, vars),
            Expr::Preserve(preserve_expr) => self.lower_preserve_expr(preserve_expr, current, blocks, vars),
            Expr::ReplaceRelation(relation) => self.lower_replace_relation(relation, current, blocks, vars),
            Expr::StructInit(init) => self.lower_struct_init(init, current, blocks, vars),
            Expr::FieldAccess(field) => self.lower_field_access(field, current, blocks, vars),
            Expr::Index(index) => self.lower_index_expr(index, current, blocks, vars),
            Expr::Block(stmts) => self.lower_tail_block_value(stmts, current, blocks, vars),
            Expr::If(if_expr) => self.lower_if_expr(if_expr, current, blocks, vars),
            Expr::Match(match_expr) => self.lower_match_expr(match_expr, current, blocks, vars),
            Expr::Cast(cast) => self.lower_cast_expr(cast, current, blocks, vars),
            Expr::Array(items) => self.lower_array_expr(items, current, blocks, vars),
            Expr::Tuple(items) => self.lower_tuple_expr(items, current, blocks, vars),
            Expr::String(_) => {
                self.record_error("string literals are only supported in metadata positions such as assert messages", Span::default());
                LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(current) }
            }
            Expr::ByteString(bytes) => LoweredExpr {
                operand: IrOperand::Const(IrConst::Array(bytes.iter().copied().map(IrConst::U8).collect())),
                current: Some(current),
            },
            Expr::Range(_) => {
                self.record_error("range expressions are only supported as for-loop iterables", Span::default());
                LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(current) }
            }
            Expr::StdlibCall(call) => self.lower_stdlib_call(call, current, blocks, vars),
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
            let Some(next) = self.lower_stmt(stmt, active, blocks, vars, None) else {
                return LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: None };
            };
            active = next;
        }

        match last {
            Stmt::Expr(expr) => self.lower_expr(expr, active, blocks, vars),
            Stmt::If(if_stmt) if if_stmt.else_branch.is_some() => self.lower_if_stmt_value(if_stmt, active, blocks, vars),
            stmt => {
                let next = self.lower_stmt(stmt, active, blocks, vars, None);
                LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: next }
            }
        }
    }

    fn lower_tail_block_value_with_expected_type(
        &mut self,
        stmts: &[Stmt],
        expected_ty: &IrType,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let Some((last, prefix)) = stmts.split_last() else {
            return LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: Some(current) };
        };

        let mut active = current;
        for stmt in prefix {
            let Some(next) = self.lower_stmt(stmt, active, blocks, vars, None) else {
                return LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: None };
            };
            active = next;
        }

        match last {
            Stmt::Expr(expr) => self.lower_expr_with_expected_type(expr, expected_ty, active, blocks, vars),
            Stmt::If(if_stmt) if if_stmt.else_branch.is_some() => {
                self.lower_if_stmt_value_with_expected_type(if_stmt, expected_ty, active, blocks, vars)
            }
            stmt => {
                let next = self.lower_stmt(stmt, active, blocks, vars, None);
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
            IrConst::Array(items) => IrType::Array(Box::new(IrType::U8), items.len()),
        }
    }

    fn default_integer_const(value: u128) -> IrConst {
        u64::try_from(value).map(IrConst::U64).unwrap_or(IrConst::U128(value))
    }

    fn integer_const_for_expected_type(value: u128, expected_ty: &IrType) -> Option<IrConst> {
        match expected_ty {
            IrType::U8 => u8::try_from(value).ok().map(IrConst::U8),
            IrType::U16 => u16::try_from(value).ok().map(IrConst::U16),
            IrType::U32 => u32::try_from(value).ok().map(IrConst::U32),
            IrType::I32 => i32::try_from(value).ok().map(|value| IrConst::U32(value as u32)),
            IrType::U64 => u64::try_from(value).ok().map(IrConst::U64),
            IrType::U128 => Some(IrConst::U128(value)),
            IrType::Named(name) if name == "usize" => u64::try_from(value).ok().map(IrConst::U64),
            IrType::Named(name) if name == "isize" => {
                i64::try_from(value).ok().and_then(|_| u64::try_from(value).ok()).map(IrConst::U64)
            }
            _ => None,
        }
    }

    fn binary_result_type_for_operands(&self, op: BinaryOp, left: &IrOperand, right: &IrOperand) -> IrType {
        match op {
            BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => IrType::Bool,
            BinaryOp::Add
            | BinaryOp::Sub
            | BinaryOp::Mul
            | BinaryOp::Div
            | BinaryOp::Mod
            | BinaryOp::BitAnd
            | BinaryOp::BitOr
            | BinaryOp::BitXor => {
                let left_ty = self.operand_type(left);
                let right_ty = self.operand_type(right);
                if left_ty == right_ty {
                    left_ty
                } else if let Some(ty) = Self::unsigned_widening_result_ir_type(&left_ty, &right_ty) {
                    ty
                } else {
                    IrType::U64
                }
            }
            BinaryOp::And | BinaryOp::Or => IrType::Bool,
            BinaryOp::Shl | BinaryOp::Shr => self.operand_type(left),
        }
    }

    fn unsigned_widening_rank_ir(ty: &IrType) -> Option<u8> {
        match ty {
            IrType::U8 => Some(0),
            IrType::U16 => Some(1),
            IrType::U32 => Some(2),
            IrType::U64 => Some(3),
            IrType::U128 => Some(4),
            IrType::Named(name) if name == "usize" => Some(3),
            _ => None,
        }
    }

    fn unsigned_ir_type_for_rank(rank: u8) -> IrType {
        match rank {
            0 => IrType::U8,
            1 => IrType::U16,
            2 => IrType::U32,
            3 => IrType::U64,
            _ => IrType::U128,
        }
    }

    fn unsigned_widening_result_ir_type(left_ty: &IrType, right_ty: &IrType) -> Option<IrType> {
        let left_rank = Self::unsigned_widening_rank_ir(left_ty)?;
        let right_rank = Self::unsigned_widening_rank_ir(right_ty)?;
        Some(Self::unsigned_ir_type_for_rank(left_rank.max(right_rank)))
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
        blocks.push(IrBlock { id, instructions: Vec::new(), terminator: IrTerminator::Return(None), runtime_error: None });
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
        return_type: Option<&IrType>,
        tail_expr_returns: bool,
    ) -> Option<BlockId> {
        let lowered_cond = self.lower_expr(&if_stmt.condition, current, blocks, vars);
        let cond = lowered_cond.operand;
        let current = lowered_cond.current?;

        let then_block = self.push_block(blocks);
        let else_block = self.push_block(blocks);
        self.block_mut(blocks, current).terminator = IrTerminator::Branch { cond, then_block, else_block };

        let mut then_vars = vars.clone();
        self.branch_depth += 1;
        self.branch_epoch += 1;
        let then_exit = self.lower_stmts(&if_stmt.then_branch, then_block, blocks, &mut then_vars, return_type, tail_expr_returns);
        self.branch_depth -= 1;

        let mut else_vars = vars.clone();
        self.branch_epoch += 1;
        self.branch_depth += 1;
        let else_exit = if let Some(else_branch) = &if_stmt.else_branch {
            let exit = self.lower_stmts(else_branch, else_block, blocks, &mut else_vars, return_type, tail_expr_returns);
            self.branch_depth -= 1;
            exit
        } else {
            self.branch_depth -= 1;
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
            let next = self.lower_if_stmt(if_stmt, current, blocks, vars, None, false);
            return LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: next };
        };

        let then_block = self.push_block(blocks);
        let else_block = self.push_block(blocks);
        self.block_mut(blocks, current).terminator = IrTerminator::Branch { cond, then_block, else_block };

        let mut then_vars = vars.clone();
        self.branch_depth += 1;
        self.branch_epoch += 1;
        let then_lowered = self.lower_tail_block_value(&if_stmt.then_branch, then_block, blocks, &mut then_vars);
        self.branch_depth -= 1;
        let mut else_vars = vars.clone();
        self.branch_epoch += 1;
        self.branch_depth += 1;
        let else_lowered = self.lower_tail_block_value(else_branch, else_block, blocks, &mut else_vars);
        self.branch_depth -= 1;

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

    fn lower_if_stmt_value_with_expected_type(
        &mut self,
        if_stmt: &IfStmt,
        expected_ty: &IrType,
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
            let next = self.lower_if_stmt(if_stmt, current, blocks, vars, None, false);
            return LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: next };
        };

        let then_block = self.push_block(blocks);
        let else_block = self.push_block(blocks);
        self.block_mut(blocks, current).terminator = IrTerminator::Branch { cond, then_block, else_block };

        let mut then_vars = vars.clone();
        self.branch_depth += 1;
        self.branch_epoch += 1;
        let then_lowered =
            self.lower_tail_block_value_with_expected_type(&if_stmt.then_branch, expected_ty, then_block, blocks, &mut then_vars);
        self.branch_depth -= 1;
        let mut else_vars = vars.clone();
        self.branch_epoch += 1;
        self.branch_depth += 1;
        let else_lowered =
            self.lower_tail_block_value_with_expected_type(else_branch, expected_ty, else_block, blocks, &mut else_vars);
        self.branch_depth -= 1;

        if then_lowered.current.is_none() && else_lowered.current.is_none() {
            return LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: None };
        }

        let dest = self.new_var("if_tmp", expected_ty.clone());
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
        return_type: Option<&IrType>,
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
        self.branch_depth += 1;
        self.branch_epoch += 1;
        self.loop_targets.push(LoopTarget { label: while_stmt.label.clone(), break_block: exit_block, continue_block: cond_entry });
        let body_exit = self.lower_stmts(&while_stmt.body, body_block, blocks, &mut body_vars, return_type, false);
        self.loop_targets.pop();
        self.branch_depth -= 1;
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
        return_type: Option<&IrType>,
    ) -> Option<BlockId> {
        match &for_stmt.iterable {
            Expr::Range(range) => self.lower_for_range_stmt(for_stmt, range, current, blocks, vars, return_type),
            _ => {
                let lowered = self.lower_expr(&for_stmt.iterable, current, blocks, vars);
                let active = lowered.current?;
                self.lower_for_iterable_stmt(for_stmt, lowered.operand, active, blocks, vars, return_type)
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
        return_type: Option<&IrType>,
    ) -> Option<BlockId> {
        if let IrOperand::Var(iterable_var) = &iterable {
            if let Some(elements) = self.aggregate_elements.get(&iterable_var.id).cloned() {
                return self.lower_for_local_fixed_array_stmt(for_stmt, elements, current, blocks, vars, return_type);
            }
            if let IrType::Array(_, len) = &iterable_var.ty {
                let len = *len;
                return self.lower_for_static_array_pointer_stmt(for_stmt, iterable, len, current, blocks, vars, return_type);
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
        let has_loop_control = stmts_contain_loop_control(&for_stmt.body);
        let step_block = has_loop_control.then(|| self.push_block(blocks));
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
        self.branch_depth += 1;
        self.branch_epoch += 1;
        self.bind_pattern(&for_stmt.pattern, IrOperand::Var(item_var), self.block_mut(blocks, body_block), &mut body_vars);
        if let Some(step_block) = step_block {
            self.loop_targets.push(LoopTarget { label: for_stmt.label.clone(), break_block: exit_block, continue_block: step_block });
        }
        let body_exit = self.lower_stmts(&for_stmt.body, body_block, blocks, &mut body_vars, return_type, false);
        self.branch_depth -= 1;
        if step_block.is_some() {
            self.loop_targets.pop();
        }
        if let Some(exit) = body_exit {
            let next_index = self.new_var("iter_next", IrType::U64);
            let destination = step_block.unwrap_or(exit);
            if destination != exit {
                self.block_mut(blocks, exit).terminator = IrTerminator::Jump(destination);
            }
            let block = self.block_mut(blocks, destination);
            block.instructions.push(IrInstruction::Binary {
                dest: next_index.clone(),
                op: BinaryOp::Add,
                left: IrOperand::Var(index_var.clone()),
                right: IrOperand::Const(IrConst::U64(1)),
            });
            block.instructions.push(IrInstruction::Move { dest: index_var, src: IrOperand::Var(next_index) });
            block.terminator = IrTerminator::Jump(cond_block);
        } else if let Some(step_block) = step_block {
            let next_index = self.new_var("iter_next", IrType::U64);
            let block = self.block_mut(blocks, step_block);
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
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
        return_type: Option<&IrType>,
    ) -> Option<BlockId> {
        let Some(item_ty) = self.iter_item_type(&iterable) else {
            self.record_error("for-loop iterable has no lowered item type", for_stmt.span);
            return Some(current);
        };

        if !stmts_contain_loop_control(&for_stmt.body) {
            let mut current = current;
            for index in 0..len {
                let item_var = self.new_var(format!("iter_item_{}", index), item_ty.clone());
                self.block_mut(blocks, current).instructions.push(IrInstruction::Index {
                    dest: item_var.clone(),
                    arr: iterable.clone(),
                    idx: IrOperand::Const(IrConst::U64(index as u64)),
                });

                let mut body_vars = vars.clone();
                self.bind_pattern(&for_stmt.pattern, IrOperand::Var(item_var), self.block_mut(blocks, current), &mut body_vars);
                current = self.lower_stmts(&for_stmt.body, current, blocks, &mut body_vars, return_type, false)?;
            }
            return Some(current);
        }

        let exit_block = self.push_block(blocks);
        if len == 0 {
            self.block_mut(blocks, current).terminator = IrTerminator::Jump(exit_block);
            return Some(exit_block);
        }
        let iteration_blocks = (0..len).map(|_| self.push_block(blocks)).collect::<Vec<_>>();
        self.block_mut(blocks, current).terminator = IrTerminator::Jump(iteration_blocks[0]);
        for index in 0..len {
            let iteration_block = iteration_blocks[index];
            let next_block = iteration_blocks.get(index + 1).copied().unwrap_or(exit_block);
            let item_var = self.new_var(format!("iter_item_{}", index), item_ty.clone());
            self.block_mut(blocks, iteration_block).instructions.push(IrInstruction::Index {
                dest: item_var.clone(),
                arr: iterable.clone(),
                idx: IrOperand::Const(IrConst::U64(index as u64)),
            });

            let mut body_vars = vars.clone();
            self.bind_pattern(&for_stmt.pattern, IrOperand::Var(item_var), self.block_mut(blocks, iteration_block), &mut body_vars);
            self.loop_targets.push(LoopTarget { label: for_stmt.label.clone(), break_block: exit_block, continue_block: next_block });
            let body_exit = self.lower_stmts(&for_stmt.body, iteration_block, blocks, &mut body_vars, return_type, false);
            self.loop_targets.pop();
            if let Some(body_exit) = body_exit {
                self.block_mut(blocks, body_exit).terminator = IrTerminator::Jump(next_block);
            }
        }

        Some(exit_block)
    }

    fn lower_for_local_fixed_array_stmt(
        &mut self,
        for_stmt: &ForStmt,
        elements: Vec<IrVar>,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
        return_type: Option<&IrType>,
    ) -> Option<BlockId> {
        if !stmts_contain_loop_control(&for_stmt.body) {
            let mut current = current;
            for (index, element_var) in elements.into_iter().enumerate() {
                let item_var = self.new_var(format!("iter_item_{}", index), element_var.ty.clone());
                self.block_mut(blocks, current)
                    .instructions
                    .push(IrInstruction::Move { dest: item_var.clone(), src: IrOperand::Var(element_var.clone()) });
                self.copy_aggregate_metadata(&IrOperand::Var(element_var), item_var.id);

                let mut body_vars = vars.clone();
                self.bind_pattern(&for_stmt.pattern, IrOperand::Var(item_var), self.block_mut(blocks, current), &mut body_vars);
                current = self.lower_stmts(&for_stmt.body, current, blocks, &mut body_vars, return_type, false)?;
            }
            return Some(current);
        }

        let exit_block = self.push_block(blocks);
        if elements.is_empty() {
            self.block_mut(blocks, current).terminator = IrTerminator::Jump(exit_block);
            return Some(exit_block);
        }
        let iteration_blocks = (0..elements.len()).map(|_| self.push_block(blocks)).collect::<Vec<_>>();
        self.block_mut(blocks, current).terminator = IrTerminator::Jump(iteration_blocks[0]);
        for (index, element_var) in elements.into_iter().enumerate() {
            let iteration_block = iteration_blocks[index];
            let next_block = iteration_blocks.get(index + 1).copied().unwrap_or(exit_block);
            let item_var = self.new_var(format!("iter_item_{}", index), element_var.ty.clone());
            self.block_mut(blocks, iteration_block)
                .instructions
                .push(IrInstruction::Move { dest: item_var.clone(), src: IrOperand::Var(element_var.clone()) });
            self.copy_aggregate_metadata(&IrOperand::Var(element_var), item_var.id);

            let mut body_vars = vars.clone();
            self.bind_pattern(&for_stmt.pattern, IrOperand::Var(item_var), self.block_mut(blocks, iteration_block), &mut body_vars);
            self.loop_targets.push(LoopTarget { label: for_stmt.label.clone(), break_block: exit_block, continue_block: next_block });
            let body_exit = self.lower_stmts(&for_stmt.body, iteration_block, blocks, &mut body_vars, return_type, false);
            self.loop_targets.pop();
            if let Some(body_exit) = body_exit {
                self.block_mut(blocks, body_exit).terminator = IrTerminator::Jump(next_block);
            }
        }

        Some(exit_block)
    }

    fn lower_for_range_stmt(
        &mut self,
        for_stmt: &ForStmt,
        range: &RangeExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
        return_type: Option<&IrType>,
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
        let has_loop_control = stmts_contain_loop_control(&for_stmt.body);
        let step_block = has_loop_control.then(|| self.push_block(blocks));
        let exit_block = self.push_block(blocks);
        self.block_mut(blocks, cond_block).terminator =
            IrTerminator::Branch { cond: IrOperand::Var(cond_var), then_block: body_block, else_block: exit_block };

        let mut body_vars = vars.clone();
        self.bind_pattern(&for_stmt.pattern, IrOperand::Var(index_var.clone()), self.block_mut(blocks, body_block), &mut body_vars);
        if let Some(step_block) = step_block {
            self.loop_targets.push(LoopTarget { label: for_stmt.label.clone(), break_block: exit_block, continue_block: step_block });
        }
        let body_exit = self.lower_stmts(&for_stmt.body, body_block, blocks, &mut body_vars, return_type, false);
        if step_block.is_some() {
            self.loop_targets.pop();
        }
        if let Some(exit) = body_exit {
            let next_index = self.new_var("for_next", IrType::U64);
            let destination = step_block.unwrap_or(exit);
            if destination != exit {
                self.block_mut(blocks, exit).terminator = IrTerminator::Jump(destination);
            }
            let block = self.block_mut(blocks, destination);
            block.instructions.push(IrInstruction::Binary {
                dest: next_index.clone(),
                op: BinaryOp::Add,
                left: IrOperand::Var(index_var.clone()),
                right: IrOperand::Const(IrConst::U64(1)),
            });
            block.instructions.push(IrInstruction::Move { dest: index_var, src: IrOperand::Var(next_index) });
            block.terminator = IrTerminator::Jump(cond_block);
        } else if let Some(step_block) = step_block {
            let next_index = self.new_var("for_next", IrType::U64);
            let block = self.block_mut(blocks, step_block);
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
        self.block_mut(blocks, fail_block).terminator = IrTerminator::Return(Some(self.fail_closed_return_operand()));
        self.block_mut(blocks, fail_block).runtime_error = Some(CellScriptRuntimeError::AssertionFailed);

        LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: Some(ok_block) }
    }

    fn lower_require_expr(
        &mut self,
        require_expr: &RequireExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let lowered_cond = self.lower_expr(&require_expr.condition, current, blocks, vars);
        let Some(active) = lowered_cond.current else {
            return lowered_cond;
        };
        let cond = lowered_cond.operand;

        let ok_block = self.push_block(blocks);
        let fail_block = self.push_block(blocks);
        self.block_mut(blocks, active).terminator =
            IrTerminator::Branch { cond: cond.clone(), then_block: ok_block, else_block: fail_block };
        self.block_mut(blocks, fail_block).terminator = IrTerminator::Return(Some(self.fail_closed_return_operand()));
        self.block_mut(blocks, fail_block).runtime_error = Some(CellScriptRuntimeError::AssertionFailed);
        let condition_span = require_expr.condition.span();
        let claim_span = if condition_span.end > require_expr.span.start {
            Span::new(require_expr.span.start, condition_span.end, require_expr.span.line, require_expr.span.column)
        } else {
            require_expr.span
        };
        self.enforced_claims.push(IrEnforcedClaim {
            statement: crate::fmt::format_expression(&require_expr.condition),
            condition_block: active,
            success_block: ok_block,
            failure_block: fail_block,
            span: claim_span,
        });

        LoweredExpr { operand: IrOperand::Const(IrConst::Bool(true)), current: Some(ok_block) }
    }

    fn fail_closed_return_operand(&self) -> IrOperand {
        self.fail_closed_runtime_return_operand(CellScriptRuntimeError::AssertionFailed)
    }

    fn fail_closed_runtime_return_operand(&self, error: CellScriptRuntimeError) -> IrOperand {
        if self.lowering_lock_entry {
            IrOperand::Const(IrConst::Bool(false))
        } else {
            IrOperand::Const(IrConst::U64(error.code()))
        }
    }

    fn lower_cast_expr(
        &mut self,
        cast: &CastExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        if let Expr::Integer(value) = cast.expr.as_ref() {
            let target = Self::convert_type(&cast.ty);
            if let Some(value) = Self::integer_const_for_expected_type(*value, &target) {
                return LoweredExpr { operand: IrOperand::Const(value), current: Some(current) };
            }
        }

        let lowered = self.lower_expr(&cast.expr, current, blocks, vars);
        let Some(active) = lowered.current else {
            return lowered;
        };
        let source_ty = self.operand_type(&lowered.operand);
        let target_ty = Self::convert_type(&cast.ty);
        // Widening must retain the target type in typed IR even when both
        // values fit one register. u128 additionally changes representation
        // from a scalar to two stored limbs. Neither conversion needs a
        // range guard, but erasing it gives later operations the wrong type.
        if unsigned_ir_bits(&source_ty).zip(unsigned_ir_bits(&target_ty)).is_some_and(|(source, target)| target > source) {
            let cast_value = self.new_var("cast_value", target_ty);
            self.block_mut(blocks, active).instructions.push(IrInstruction::Move { dest: cast_value.clone(), src: lowered.operand });
            return LoweredExpr { operand: IrOperand::Var(cast_value), current: Some(active) };
        }
        let Some(maximum) = checked_cast_maximum(&source_ty, &target_ty) else {
            return LoweredExpr { operand: lowered.operand, current: Some(active) };
        };

        let condition = self.new_var("cast_fits", IrType::Bool);
        self.block_mut(blocks, active).instructions.push(IrInstruction::Binary {
            dest: condition.clone(),
            op: BinaryOp::Le,
            left: lowered.operand.clone(),
            right: IrOperand::Const(maximum),
        });

        let ok_block = self.push_block(blocks);
        let fail_block = self.push_block(blocks);
        self.block_mut(blocks, active).terminator =
            IrTerminator::Branch { cond: IrOperand::Var(condition), then_block: ok_block, else_block: fail_block };
        self.block_mut(blocks, fail_block).terminator =
            IrTerminator::Return(Some(self.fail_closed_runtime_return_operand(CellScriptRuntimeError::NumericOrDiscriminantInvalid)));
        self.block_mut(blocks, fail_block).runtime_error = Some(CellScriptRuntimeError::NumericOrDiscriminantInvalid);

        let cast_value = self.new_var("cast_value", target_ty);
        self.block_mut(blocks, ok_block).instructions.push(IrInstruction::Move { dest: cast_value.clone(), src: lowered.operand });
        LoweredExpr { operand: IrOperand::Var(cast_value), current: Some(ok_block) }
    }

    /// Lower `require { expr1, expr2, ... }` — desugar into independent atomic `require` statements.
    fn lower_require_block_expr(
        &mut self,
        require_block: &RequireBlockExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let mut active = current;
        for expr in &require_block.expressions {
            // Each expression in a require block is treated as a require condition:
            // require_block { expr1, expr2 } desugars to require expr1; require expr2;
            let lowered = self.lower_expr(expr, active, blocks, vars);
            let Some(next) = lowered.current else {
                return lowered;
            };
            let cond = lowered.operand;

            let ok_block = self.push_block(blocks);
            let fail_block = self.push_block(blocks);
            self.block_mut(blocks, next).terminator =
                IrTerminator::Branch { cond: cond.clone(), then_block: ok_block, else_block: fail_block };
            self.block_mut(blocks, fail_block).terminator = IrTerminator::Return(Some(self.fail_closed_return_operand()));
            self.block_mut(blocks, fail_block).runtime_error = Some(CellScriptRuntimeError::AssertionFailed);
            self.enforced_claims.push(IrEnforcedClaim {
                statement: crate::fmt::format_expression(expr),
                condition_block: next,
                success_block: ok_block,
                failure_block: fail_block,
                span: if expr.span().end > expr.span().start { expr.span() } else { require_block.span },
            });
            active = ok_block;
        }
        LoweredExpr { operand: IrOperand::Const(IrConst::Bool(true)), current: Some(active) }
    }

    /// Lower `preserve output from input { field1, field2, ... }` — desugar into
    /// `require output.field1 == input.field1; require output.field2 == input.field2; ...`
    fn lower_preserve_expr(
        &mut self,
        preserve: &PreserveExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let mut active = current;
        for field_name in &preserve.fields {
            let output_field = Expr::FieldAccess(FieldAccessExpr {
                expr: Box::new(Expr::Identifier(preserve.output_name.clone())),
                field: field_name.clone(),
                span: preserve.span,
            });
            let input_field = Expr::FieldAccess(FieldAccessExpr {
                expr: Box::new(Expr::Identifier(preserve.input_name.clone())),
                field: field_name.clone(),
                span: preserve.span,
            });
            let equality = Expr::Binary(BinaryExpr {
                op: BinaryOp::Eq,
                left: Box::new(output_field),
                right: Box::new(input_field),
                span: preserve.span,
            });
            let require_expr = RequireExpr { condition: Box::new(equality), message: None, span: preserve.span };
            let lowered = self.lower_require_expr(&require_expr, active, blocks, vars);
            let Some(next) = lowered.current else {
                return lowered;
            };
            active = next;
        }
        LoweredExpr { operand: IrOperand::Const(IrConst::Bool(true)), current: Some(active) }
    }

    /// Elaborate an authoring successor relation into the same checked
    /// instructions as the spelled-out Edition 2026 forms: the predecessor is
    /// consumed exactly once, every concrete schema field becomes an explicit
    /// successor equality (or is bound by the create in the exact-lock form),
    /// and the identity, capacity and lock treatments lower to the canonical
    /// type-hash, capacity and lock-hash preservation checks.
    fn lower_replace_relation(
        &mut self,
        relation: &ReplaceRelation,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let span = relation.span;
        let mut active = current;

        let resource_ty = vars
            .get(&relation.after)
            .and_then(|var| Self::named_type_name_from_ir_type(&var.ty).map(str::to_string))
            .unwrap_or_else(|| relation.after.clone());

        // 1. Account the predecessor through the ordinary consume kernel.
        let consume = ConsumeExpr { expr: Box::new(Expr::Identifier(relation.before.clone())), span };
        let lowered = self.lower_consume_expr(&consume, active, blocks, vars);
        let Some(next) = lowered.current else {
            return lowered;
        };
        active = next;

        // 2. Resolve the data treatment into explicit successor field values.
        let before_expr = Expr::Identifier(relation.before.clone());
        let after_expr = Expr::Identifier(relation.after.clone());
        let mut field_values: Vec<(String, Expr)> = Vec::new();
        match &relation.data {
            ReplaceDataTreatment::Fields(treatments) => {
                for treatment in treatments {
                    match treatment {
                        ReplaceFieldTreatment::Same(field) => field_values.push((
                            field.clone(),
                            Expr::FieldAccess(FieldAccessExpr { expr: Box::new(before_expr.clone()), field: field.clone(), span }),
                        )),
                        ReplaceFieldTreatment::Assign(field, value) => {
                            field_values.push((field.clone(), value.clone()));
                        }
                    }
                }
            }
            ReplaceDataTreatment::SameExcept(assigned) => {
                // Sorted for deterministic expansion regardless of the
                // field map's iteration order.
                let mut schema_fields =
                    self.type_fields.get(&resource_ty).map(|fields| fields.keys().cloned().collect::<Vec<_>>()).unwrap_or_default();
                schema_fields.sort();
                for field in schema_fields {
                    if let Some((_, value)) = assigned.iter().find(|(name, _)| name == &field) {
                        field_values.push((field, value.clone()));
                    } else {
                        field_values.push((
                            field.clone(),
                            Expr::FieldAccess(FieldAccessExpr { expr: Box::new(before_expr.clone()), field, span }),
                        ));
                    }
                }
                for (field, _) in assigned {
                    if !field_values.iter().any(|(name, _)| name == field) {
                        self.record_error(
                            format!("replace relation `same except` field '{field}' does not exist on resource '{resource_ty}'"),
                            span,
                        );
                    }
                }
            }
        }

        // 3. Bind the successor. Both lock treatments go through the create
        //    kernel so resource conservation is enforced the same way: the
        //    exact form binds the lock target, the same form leaves the lock
        //    unconstrained by create and pins it with the lock-hash
        //    preservation check instead.
        let create = CreateExpr {
            target: Some(relation.after.clone()),
            ty: resource_ty.clone(),
            fields: field_values.clone(),
            lock: match &relation.lock {
                ReplaceLockTreatment::Exact(lock) | ReplaceLockTreatment::ExactHash(lock) => Some(lock.clone()),
                ReplaceLockTreatment::Same => None,
            },
            span,
        };
        let lowered = self.lower_create_expr(&create, active, blocks, vars);
        let Some(next) = lowered.current else {
            return lowered;
        };
        active = next;

        if let ReplaceLockTreatment::Same = &relation.lock {
            // The lock is not bound by the create; pin it to the
            // predecessor's complete Lock Script hash instead. Conservation
            // now recognizes the updated-successor shape (verbatim aliases
            // plus verifier-checked u64 updates rooted in the consumed
            // input), so this stays executable under DenyFailClosed.
            let same_lock = StdlibCallExpr {
                namespace: "cell".to_string(),
                name: "same_lock".to_string(),
                args: vec![after_expr.clone(), before_expr.clone()],
                preserve_fields: Vec::new(),
                span,
            };
            let lowered = self.lower_stdlib_call(&same_lock, active, blocks, vars);
            let Some(next) = lowered.current else {
                return lowered;
            };
            active = next;
        }

        // 4. Identity: the successor keeps the predecessor's Type identity.
        let same_type = StdlibCallExpr {
            namespace: "cell".to_string(),
            name: "same_type".to_string(),
            args: vec![after_expr.clone(), before_expr.clone()],
            preserve_fields: Vec::new(),
            span,
        };
        let lowered = self.lower_stdlib_call(&same_type, active, blocks, vars);
        let Some(next) = lowered.current else {
            return lowered;
        };
        active = next;

        // 5. Capacity: exact equality with the predecessor.
        let preserve_capacity = StdlibCallExpr {
            namespace: "cell".to_string(),
            name: "preserve_capacity".to_string(),
            args: vec![after_expr, before_expr],
            preserve_fields: Vec::new(),
            span,
        };
        let lowered = self.lower_stdlib_call(&preserve_capacity, active, blocks, vars);
        let Some(next) = lowered.current else {
            return lowered;
        };
        active = next;

        LoweredExpr { operand: IrOperand::Const(IrConst::Bool(true)), current: Some(active) }
    }

    fn lower_cell_metadata_equality_call(
        &mut self,
        qualified: &str,
        call: &StdlibCallExpr,
        field: CellMetadataField,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        if call.args.len() != 2 {
            self.record_error(format!("{} expects 2 arguments (output, input), got {}", qualified, call.args.len()), call.span);
            return LoweredExpr { operand: IrOperand::Const(IrConst::Bool(false)), current: Some(current) };
        }

        let left = self.lower_expr(&call.args[0], current, blocks, vars);
        let Some(active) = left.current else {
            return left;
        };
        let right = self.lower_expr(&call.args[1], active, blocks, vars);
        let Some(active) = right.current else {
            return right;
        };

        self.block_mut(blocks, active).instructions.push(IrInstruction::CellMetadataEquality {
            left: left.operand,
            right: right.operand,
            field,
        });
        LoweredExpr { operand: IrOperand::Const(IrConst::Bool(true)), current: Some(active) }
    }

    fn lower_stdlib_output_create_and_preserve(
        &mut self,
        qualified: &str,
        input_role: &str,
        input: &Expr,
        output: &Expr,
        lock: Option<&Expr>,
        preserve_fields: &[String],
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> Option<BlockId> {
        let output_name = match output {
            Expr::Identifier(name) => name.clone(),
            _ => {
                self.record_error(format!("{} output must be a named Cell output binding", qualified), output.span());
                return None;
            }
        };
        let input_name = match input {
            Expr::Identifier(name) => name.clone(),
            _ => {
                self.record_error(format!("{} {} must be a named Cell input binding", qualified, input_role), input.span());
                return None;
            }
        };
        let Some(output_ty) = vars.get(&output_name).and_then(|var| Self::named_type_name_from_ir_type(&var.ty).map(str::to_string))
        else {
            self.record_error(format!("{} output must be a named Cell output binding", qualified), output.span());
            return None;
        };

        let create_fields = preserve_fields
            .iter()
            .map(|field| {
                (
                    field.clone(),
                    Expr::FieldAccess(FieldAccessExpr { expr: Box::new(input.clone()), field: field.clone(), span: input.span() }),
                )
            })
            .collect::<Vec<_>>();
        let create_expr = CreateExpr {
            target: Some(output_name.clone()),
            ty: output_ty,
            fields: create_fields,
            lock: lock.cloned().map(Box::new),
            span: output.span(),
        };
        let lowered = self.lower_create_expr(&create_expr, current, blocks, vars);
        let mut active = lowered.current?;

        if !preserve_fields.is_empty() {
            let preserve = PreserveExpr { output_name, input_name, fields: preserve_fields.to_vec(), span: input.span() };
            let lowered = self.lower_preserve_expr(&preserve, active, blocks, vars);
            active = lowered.current?;
        }

        Some(active)
    }

    /// Lower a stdlib call expression by expanding it into core IR instructions.
    ///
    /// Constraint patterns expand into `require` constraints or canonical
    /// verifier metadata checks.
    ///
    /// Lifecycle patterns expand into `consume` plus explicit output and verifier constraints.
    fn lower_stdlib_call(
        &mut self,
        call: &StdlibCallExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let qualified = format!("std::{}::{}", call.namespace, call.name);
        let mut active = current;
        let Some(signature) = crate::stdlib::signature::lookup(&call.namespace, &call.name) else {
            self.record_error(
                format!("unknown stdlib pattern '{}' — each stdlib primitive must have a canonical signature", qualified),
                call.span,
            );
            return LoweredExpr { operand: IrOperand::Const(IrConst::Bool(false)), current: Some(active) };
        };
        if call.args.len() != signature.arity {
            self.record_error(format!("{} expects {} arguments, got {}", qualified, signature.arity, call.args.len()), call.span);
            return LoweredExpr { operand: IrOperand::Const(IrConst::Bool(false)), current: Some(active) };
        }
        if !signature.allows_preserve_fields && !call.preserve_fields.is_empty() {
            self.record_error(format!("{} does not accept a preserve-field block", qualified), call.span);
            return LoweredExpr { operand: IrOperand::Const(IrConst::Bool(false)), current: Some(active) };
        }

        match qualified.as_str() {
            // Constraint patterns — expand to canonical verifier constraints
            "std::cell::same_lock" | "std::cell::preserve_lock" => {
                self.lower_cell_metadata_equality_call(&qualified, call, CellMetadataField::LockHash, active, blocks, vars)
            }
            "std::cell::same_type" | "std::cell::preserve_type" => {
                if call.args.len() != 2 {
                    self.record_error(
                        format!("{} expects 2 arguments (output, input), got {}", qualified, call.args.len()),
                        call.span,
                    );
                    return LoweredExpr { operand: IrOperand::Const(IrConst::Bool(false)), current: Some(active) };
                }
                let output = &call.args[0];
                let input = &call.args[1];
                let output_type_hash = Expr::Call(CallExpr {
                    func: Box::new(Expr::FieldAccess(FieldAccessExpr {
                        expr: Box::new(output.clone()),
                        field: "type_hash".to_string(),
                        span: call.span,
                    })),
                    type_args: Vec::new(),
                    args: vec![],
                    span: call.span,
                });
                let input_type_hash = Expr::Call(CallExpr {
                    func: Box::new(Expr::FieldAccess(FieldAccessExpr {
                        expr: Box::new(input.clone()),
                        field: "type_hash".to_string(),
                        span: call.span,
                    })),
                    type_args: Vec::new(),
                    args: vec![],
                    span: call.span,
                });
                let equality = Expr::Binary(BinaryExpr {
                    op: BinaryOp::Eq,
                    left: Box::new(output_type_hash),
                    right: Box::new(input_type_hash),
                    span: call.span,
                });
                let require_expr = RequireExpr { condition: Box::new(equality), message: None, span: call.span };
                self.lower_require_expr(&require_expr, active, blocks, vars)
            }
            "std::cell::preserve_capacity" => {
                self.lower_cell_metadata_equality_call(&qualified, call, CellMetadataField::Capacity, active, blocks, vars)
            }
            "std::accounting::conserved" => {
                if call.args.len() != 2 {
                    self.record_error(
                        format!("{} expects 2 arguments (output, input), got {}", qualified, call.args.len()),
                        call.span,
                    );
                    return LoweredExpr { operand: IrOperand::Const(IrConst::Bool(false)), current: Some(active) };
                }
                let output = &call.args[0];
                let input = &call.args[1];
                let output_amount = Expr::FieldAccess(FieldAccessExpr {
                    expr: Box::new(output.clone()),
                    field: "amount".to_string(),
                    span: call.span,
                });
                let input_amount =
                    Expr::FieldAccess(FieldAccessExpr { expr: Box::new(input.clone()), field: "amount".to_string(), span: call.span });
                let equality = Expr::Binary(BinaryExpr {
                    op: BinaryOp::Eq,
                    left: Box::new(output_amount),
                    right: Box::new(input_amount),
                    span: call.span,
                });
                let require_expr = RequireExpr { condition: Box::new(equality), message: None, span: call.span };
                self.lower_require_expr(&require_expr, active, blocks, vars)
            }

            // Lifecycle patterns — consume + explicit output and verifier constraints
            "std::lifecycle::transfer" => {
                if call.args.len() != 3 {
                    self.record_error(
                        format!("std::lifecycle::transfer expects 3 arguments (input, output, to), got {}", call.args.len()),
                        call.span,
                    );
                    return LoweredExpr { operand: IrOperand::Const(IrConst::Bool(false)), current: Some(active) };
                }
                let input = &call.args[0];
                let output = &call.args[1];
                let lock = &call.args[2];

                // 1. consume input
                let consume_expr = ConsumeExpr { expr: Box::new(input.clone()), span: call.span };
                let lowered = self.lower_consume_expr(&consume_expr, active, blocks, vars);
                let Some(next) = lowered.current else {
                    return lowered;
                };
                active = next;

                // 2. constrain the proposed output binding and lock target
                let output_name = match output {
                    Expr::Identifier(name) => name.clone(),
                    _ => {
                        self.record_error("std::lifecycle::transfer output must be a named Cell output binding", call.span);
                        return LoweredExpr { operand: IrOperand::Const(IrConst::Bool(false)), current: Some(active) };
                    }
                };
                let output_ty = vars
                    .get(&output_name)
                    .and_then(|var| Self::named_type_name_from_ir_type(&var.ty).map(str::to_string))
                    .unwrap_or_else(|| "output".to_string());
                let create_fields = call
                    .preserve_fields
                    .iter()
                    .map(|field| {
                        (
                            field.clone(),
                            Expr::FieldAccess(FieldAccessExpr {
                                expr: Box::new(input.clone()),
                                field: field.clone(),
                                span: call.span,
                            }),
                        )
                    })
                    .collect::<Vec<_>>();
                let create_expr = CreateExpr {
                    target: Some(output_name.clone()),
                    ty: output_ty,
                    fields: create_fields,
                    lock: Some(Box::new(lock.clone())),
                    span: call.span,
                };
                let lowered = self.lower_create_expr(&create_expr, active, blocks, vars);
                let Some(next) = lowered.current else {
                    return lowered;
                };
                active = next;

                // 3. require output.type_hash == input.type_hash
                let output_type_hash = Expr::Call(CallExpr {
                    func: Box::new(Expr::FieldAccess(FieldAccessExpr {
                        expr: Box::new(output.clone()),
                        field: "type_hash".to_string(),
                        span: call.span,
                    })),
                    type_args: Vec::new(),
                    args: vec![],
                    span: call.span,
                });
                let input_type_hash = Expr::Call(CallExpr {
                    func: Box::new(Expr::FieldAccess(FieldAccessExpr {
                        expr: Box::new(input.clone()),
                        field: "type_hash".to_string(),
                        span: call.span,
                    })),
                    type_args: Vec::new(),
                    args: vec![],
                    span: call.span,
                });
                let type_eq = Expr::Binary(BinaryExpr {
                    op: BinaryOp::Eq,
                    left: Box::new(output_type_hash),
                    right: Box::new(input_type_hash),
                    span: call.span,
                });
                let require_type = RequireExpr { condition: Box::new(type_eq), message: None, span: call.span };
                let lowered = self.lower_require_expr(&require_type, active, blocks, vars);
                let Some(next) = lowered.current else {
                    return lowered;
                };
                active = next;

                // 4. preserve listed fields from input to output
                if !call.preserve_fields.is_empty() {
                    let input_name = match input {
                        Expr::Identifier(name) => name.clone(),
                        _ => "input".to_string(),
                    };
                    let preserve = PreserveExpr { output_name, input_name, fields: call.preserve_fields.clone(), span: call.span };
                    let lowered = self.lower_preserve_expr(&preserve, active, blocks, vars);
                    let Some(next) = lowered.current else {
                        return lowered;
                    };
                    active = next;
                }

                LoweredExpr { operand: IrOperand::Const(IrConst::Bool(true)), current: Some(active) }
            }
            "std::receipt::claim" => {
                if call.args.len() != 3 {
                    self.record_error(format!("std::receipt::claim expects 3 arguments, got {}", call.args.len()), call.span);
                    return LoweredExpr { operand: IrOperand::Const(IrConst::Bool(false)), current: Some(active) };
                }
                let receipt = &call.args[0];

                // 1. consume receipt
                let consume_expr = ConsumeExpr { expr: Box::new(receipt.clone()), span: call.span };
                let lowered = self.lower_consume_expr(&consume_expr, active, blocks, vars);
                let Some(next) = lowered.current else {
                    return lowered;
                };
                active = next;

                // 2. canonical output construction from receipt fields with an explicit lock target.
                let Some(next) = self.lower_stdlib_output_create_and_preserve(
                    "std::receipt::claim",
                    "receipt",
                    receipt,
                    &call.args[1],
                    call.args.get(2),
                    &call.preserve_fields,
                    active,
                    blocks,
                    vars,
                ) else {
                    return LoweredExpr { operand: IrOperand::Const(IrConst::Bool(false)), current: Some(active) };
                };
                active = next;

                LoweredExpr { operand: IrOperand::Const(IrConst::Bool(true)), current: Some(active) }
            }
            "std::lifecycle::settle" => {
                if call.args.len() != 3 {
                    self.record_error(format!("std::lifecycle::settle expects 3 arguments, got {}", call.args.len()), call.span);
                    return LoweredExpr { operand: IrOperand::Const(IrConst::Bool(false)), current: Some(active) };
                }
                let input = &call.args[0];

                // 1. consume input
                let consume_expr = ConsumeExpr { expr: Box::new(input.clone()), span: call.span };
                let lowered = self.lower_consume_expr(&consume_expr, active, blocks, vars);
                let Some(next) = lowered.current else {
                    return lowered;
                };
                active = next;

                // 2. canonical output construction from settled fields with an explicit lock target.
                let Some(next) = self.lower_stdlib_output_create_and_preserve(
                    "std::lifecycle::settle",
                    "input",
                    input,
                    &call.args[1],
                    call.args.get(2),
                    &call.preserve_fields,
                    active,
                    blocks,
                    vars,
                ) else {
                    return LoweredExpr { operand: IrOperand::Const(IrConst::Bool(false)), current: Some(active) };
                };
                active = next;

                LoweredExpr { operand: IrOperand::Const(IrConst::Bool(true)), current: Some(active) }
            }

            _ => {
                self.record_error(
                    format!(
                        "unknown stdlib pattern '{}' — each stdlib primitive must have a canonical expansion into core CellScript",
                        qualified
                    ),
                    call.span,
                );
                LoweredExpr { operand: IrOperand::Const(IrConst::Bool(false)), current: Some(active) }
            }
        }
    }

    fn lower_assign_expr(
        &mut self,
        assign: &AssignExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        match assign.target.as_ref() {
            Expr::Identifier(name) => {
                let Some(target_var) = vars.get(name).cloned() else {
                    self.record_error(format!("assignment target '{}' is not bound in IR lowering", name), assign.span);
                    return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(current) };
                };
                let lowered_value = self.lower_expr_with_expected_type(&assign.value, &target_var.ty, current, blocks, vars);
                let Some(active) = lowered_value.current else {
                    return lowered_value;
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
                let lowered_value = self.lower_expr(&assign.value, current, blocks, vars);
                let Some(active) = lowered_value.current else {
                    return lowered_value;
                };
                self.lower_field_assign(field, assign.op, &assign.value, lowered_value.operand, active, blocks, vars)
            }
            Expr::Index(index) => {
                let lowered_value = self.lower_expr(&assign.value, current, blocks, vars);
                let Some(active) = lowered_value.current else {
                    return lowered_value;
                };
                self.lower_index_assign(index, assign.op, lowered_value.operand, active, blocks, vars)
            }
            _ => {
                self.record_error("invalid assignment target reached IR lowering", assign.span);
                LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(current) }
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
        let dest = if let Some(target) = &create.target {
            vars.get(target).cloned().unwrap_or_else(|| self.new_var(target.clone(), IrType::Named(create.ty.clone())))
        } else {
            self.new_var(format!("create_{}", create.ty), IrType::Named(create.ty.clone()))
        };
        let mut active = current;
        let mut lowered_fields = Vec::with_capacity(create.fields.len());
        let mut field_vars = HashMap::new();

        for (field_name, field_expr) in &create.fields {
            let expected_ty = self.type_fields.get(&create.ty).and_then(|fields| fields.get(field_name)).cloned();
            let lowered = if let Some(state_operand) = self.lower_flow_state_initializer(&create.ty, field_name, field_expr) {
                LoweredExpr { operand: state_operand, current: Some(active) }
            } else if let Some(expected_ty) = expected_ty {
                self.lower_expr_with_expected_type(field_expr, &expected_ty, active, blocks, vars)
            } else {
                self.lower_expr(field_expr, active, blocks, vars)
            };
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

        let Some(active) = self.lower_type_validity_checks(&create.ty, &field_vars, active, blocks, vars) else {
            return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: None };
        };

        let pattern = CreatePattern {
            operation: if create.target.is_some() { "output".to_string() } else { "create".to_string() },
            ty: create.ty.clone(),
            binding: dest.name.clone(),
            fields: lowered_fields,
            lock: lowered_lock,
            identity: IrIdentityPolicy::None,
        };
        self.block_mut(blocks, active).instructions.push(IrInstruction::Create { dest: dest.clone(), pattern });
        self.aggregate_fields.insert(dest.id, field_vars);
        LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) }
    }

    fn lower_type_validity_checks(
        &mut self,
        type_name: &str,
        field_vars: &HashMap<String, IrVar>,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &HashMap<String, IrVar>,
    ) -> Option<BlockId> {
        let predicates = self.type_validity.get(type_name).cloned().unwrap_or_default();
        let mut active = current;
        for predicate in predicates.into_iter().filter(|predicate| predicate.evidence == IrValidityEvidence::CheckedRuntime) {
            let mut validity_vars = vars.clone();
            validity_vars.extend(field_vars.iter().map(|(name, var)| (name.clone(), var.clone())));
            let require = RequireExpr {
                condition: Box::new(predicate.expression),
                message: predicate
                    .message
                    .map(Box::new)
                    .or_else(|| Some(Box::new(Expr::String(format!("type validity failed: {type_name}"))))),
                span: predicate.span,
            };
            let lowered = self.lower_require_expr(&require, active, blocks, &mut validity_vars);
            active = lowered.current?;
        }
        Some(active)
    }

    fn lower_flow_state_initializer(&self, type_name: &str, field_name: &str, expr: &Expr) -> Option<IrOperand> {
        if self.flow_state_fields.get(type_name).is_none_or(|state_field| state_field != field_name) {
            return None;
        }
        let Expr::Identifier(state_name) = expr else {
            return None;
        };
        self.lower_flow_state_operand(type_name, state_name)
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
        self.block_mut(blocks, active).instructions.push(IrInstruction::Destroy {
            operand: lowered.operand.clone(),
            policy: Self::lower_destruction_policy(&destroy.policy),
        });
        LoweredExpr { operand: lowered.operand, current: Some(active) }
    }

    fn lower_destruction_policy(policy: &DestructionPolicy) -> IrDestructionPolicy {
        match policy {
            DestructionPolicy::Default => IrDestructionPolicy::Default,
            DestructionPolicy::SingletonType => IrDestructionPolicy::SingletonType,
            DestructionPolicy::Unique { identity } => IrDestructionPolicy::Unique { identity: identity.clone() },
            DestructionPolicy::Instance { identity_field } => IrDestructionPolicy::Instance { identity_field: identity_field.clone() },
            DestructionPolicy::BurnAmount { field } => IrDestructionPolicy::BurnAmount { field: field.clone() },
        }
    }

    fn lower_identity_policy(policy: &IdentityPolicy) -> IrIdentityPolicy {
        match policy {
            IdentityPolicy::None => IrIdentityPolicy::None,
            IdentityPolicy::CkbTypeId => IrIdentityPolicy::CkbTypeId,
            IdentityPolicy::Field(path) => IrIdentityPolicy::Field(path.clone()),
            IdentityPolicy::ScriptArgs => IrIdentityPolicy::ScriptArgs,
            IdentityPolicy::SingletonType => IrIdentityPolicy::SingletonType,
        }
    }

    fn lower_create_unique_expr(
        &mut self,
        cu: &CreateUniqueExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let dest = if let Some(target) = &cu.target {
            vars.get(target).cloned().unwrap_or_else(|| self.new_var(target.clone(), IrType::Named(cu.ty.clone())))
        } else {
            self.new_var(format!("create_unique_{}", cu.ty), IrType::Named(cu.ty.clone()))
        };
        let mut active = current;
        let mut lowered_fields = Vec::with_capacity(cu.fields.len());
        let mut field_vars = HashMap::new();

        for (field_name, field_expr) in &cu.fields {
            let expected_ty = self.type_fields.get(&cu.ty).and_then(|fields| fields.get(field_name)).cloned();
            let lowered = if let Some(expected_ty) = expected_ty {
                self.lower_expr_with_expected_type(field_expr, &expected_ty, active, blocks, vars)
            } else {
                self.lower_expr(field_expr, active, blocks, vars)
            };
            let Some(next) = lowered.current else {
                return lowered;
            };
            active = next;
            lowered_fields.push((field_name.clone(), lowered.operand.clone()));

            let field_ty = match &lowered.operand {
                IrOperand::Var(var) => var.ty.clone(),
                IrOperand::Const(value) => self.const_type(value),
            };
            let field_var = self.new_var(format!("{}_{}", cu.ty, field_name), field_ty);
            self.block_mut(blocks, active).instructions.push(IrInstruction::Move { dest: field_var.clone(), src: lowered.operand });
            field_vars.insert(field_name.clone(), field_var);
        }

        let lowered_lock = if let Some(lock_expr) = &cu.lock {
            let lowered = self.lower_expr(lock_expr, active, blocks, vars);
            let Some(next) = lowered.current else {
                return lowered;
            };
            active = next;
            Some(lowered.operand)
        } else {
            None
        };

        let Some(active) = self.lower_type_validity_checks(&cu.ty, &field_vars, active, blocks, vars) else {
            return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: None };
        };

        let identity = Self::lower_identity_policy(&cu.identity);
        let pattern = CreatePattern {
            operation: "create_unique".to_string(),
            ty: cu.ty.clone(),
            binding: dest.name.clone(),
            fields: lowered_fields,
            lock: lowered_lock,
            identity: identity.clone(),
        };
        self.block_mut(blocks, active).instructions.push(IrInstruction::CreateUnique { dest: dest.clone(), pattern, identity });
        self.aggregate_fields.insert(dest.id, field_vars);
        LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) }
    }

    fn lower_replace_unique_expr(
        &mut self,
        ru: &ReplaceUniqueExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        // Lower the input cell expression
        let lowered_input = self.lower_expr(&ru.expr, current, blocks, vars);
        let Some(active) = lowered_input.current else {
            return lowered_input;
        };

        // Lower the replacement output fields
        let dest_ty = self.operand_type(&lowered_input.operand);
        let dest = self.new_var(format!("replace_unique_{}", ru.ty), dest_ty);
        let mut active = active;
        let mut lowered_fields = Vec::with_capacity(ru.fields.len());
        let mut field_vars = HashMap::new();

        for (field_name, field_expr) in &ru.fields {
            let expected_ty = self.type_fields.get(&ru.ty).and_then(|fields| fields.get(field_name)).cloned();
            let lowered = if let Some(expected_ty) = expected_ty {
                self.lower_expr_with_expected_type(field_expr, &expected_ty, active, blocks, vars)
            } else {
                self.lower_expr(field_expr, active, blocks, vars)
            };
            let Some(next) = lowered.current else {
                return lowered;
            };
            active = next;
            lowered_fields.push((field_name.clone(), lowered.operand.clone()));

            let field_ty = match &lowered.operand {
                IrOperand::Var(var) => var.ty.clone(),
                IrOperand::Const(value) => self.const_type(value),
            };
            let field_var = self.new_var(format!("{}_{}", ru.ty, field_name), field_ty);
            self.block_mut(blocks, active).instructions.push(IrInstruction::Move { dest: field_var.clone(), src: lowered.operand });
            field_vars.insert(field_name.clone(), field_var);
        }

        let Some(active) = self.lower_type_validity_checks(&ru.ty, &field_vars, active, blocks, vars) else {
            return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: None };
        };

        let identity = Self::lower_identity_policy(&ru.identity);
        let pattern = CreatePattern {
            operation: "replace_unique".to_string(),
            ty: ru.ty.clone(),
            binding: dest.name.clone(),
            fields: lowered_fields,
            lock: None,
            identity: identity.clone(),
        };
        self.block_mut(blocks, active).instructions.push(IrInstruction::ReplaceUnique {
            dest: dest.clone(),
            operand: lowered_input.operand,
            pattern,
            identity,
        });
        self.aggregate_fields.insert(dest.id, field_vars);
        LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) }
    }

    fn lower_read_ref_expr(&mut self, read_ref: &ReadRefExpr, current: BlockId, blocks: &mut [IrBlock]) -> LoweredExpr {
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
        let validity_active = if let IrType::Named(type_name) = &dest.ty {
            self.lower_type_validity_checks(type_name, &claim_output_fields, active, blocks, vars)
        } else {
            Some(active)
        };
        let Some(active) = validity_active else {
            return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: None };
        };
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
        let validity_active = if let IrType::Named(type_name) = &dest.ty {
            self.lower_type_validity_checks(type_name, &settle_output_fields, active, blocks, vars)
        } else {
            Some(active)
        };
        let Some(active) = validity_active else {
            return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: None };
        };
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

        if let IrOperand::Var(arr_var) = &lowered_arr.operand
            && let Some(elements) = self.aggregate_elements.get(&arr_var.id)
        {
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

    fn lower_expr_with_expected_type(
        &mut self,
        expr: &Expr,
        expected_ty: &IrType,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        match expr {
            Expr::Integer(value) => {
                if let Some(value) = Self::integer_const_for_expected_type(*value, expected_ty) {
                    LoweredExpr { operand: IrOperand::Const(value), current: Some(current) }
                } else {
                    self.lower_expr(expr, current, blocks, vars)
                }
            }
            Expr::Array(items) if collection_item_ir_type(expected_ty).is_some() => {
                self.lower_vec_literal_expr(items, expected_ty.clone(), current, blocks, vars)
            }
            Expr::Array(items) if matches!(expected_ty, IrType::Array(_, _)) => {
                self.lower_array_expr_with_expected_type(items, expected_ty.clone(), current, blocks, vars)
            }
            Expr::Block(stmts) => self.lower_tail_block_value_with_expected_type(stmts, expected_ty, current, blocks, vars),
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
                ) && Self::integer_const_for_expected_type(0, expected_ty).is_some() =>
            {
                self.lower_binary_expr_with_expected_type(binary, expected_ty.clone(), current, blocks, vars)
            }
            Expr::If(if_expr) => self.lower_if_expr_with_expected_type(if_expr, expected_ty.clone(), current, blocks, vars),
            _ => self.lower_expr(expr, current, blocks, vars),
        }
    }

    fn lower_array_expr_with_expected_type(
        &mut self,
        items: &[Expr],
        expected_ty: IrType,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let IrType::Array(item_ty, expected_len) = &expected_ty else {
            self.record_error("array literal requires an expected array type", Span::default());
            return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(current) };
        };
        if items.len() != *expected_len {
            self.record_error(
                format!("array literal length mismatch during IR lowering: expected {}, found {}", expected_len, items.len()),
                Span::default(),
            );
            return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(current) };
        }
        if items.is_empty() {
            return self.lower_empty_array_expr_with_ir_type(expected_ty, current, blocks);
        }

        let mut active = current;
        let mut elements = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            let lowered = self.lower_expr_with_expected_type(item, item_ty, active, blocks, vars);
            let Some(next) = lowered.current else {
                return lowered;
            };
            active = next;
            let actual_ty = self.operand_type(&lowered.operand);
            if actual_ty != **item_ty {
                self.record_error(
                    format!("array literal type mismatch during IR lowering: expected {:?}, found {:?}", item_ty, actual_ty),
                    Span::default(),
                );
            }
            let element_var = self.new_var(format!("array_elem_{}", index), (**item_ty).clone());
            self.block_mut(blocks, active)
                .instructions
                .push(IrInstruction::Move { dest: element_var.clone(), src: lowered.operand.clone() });
            self.copy_aggregate_metadata(&lowered.operand, element_var.id);
            elements.push(element_var);
        }

        let aggregate = self.new_var("array_tmp", expected_ty);
        self.block_mut(blocks, active)
            .instructions
            .push(IrInstruction::Move { dest: aggregate.clone(), src: IrOperand::Const(IrConst::U64(0)) });
        self.aggregate_elements.insert(aggregate.id, elements);
        LoweredExpr { operand: IrOperand::Var(aggregate), current: Some(active) }
    }

    fn lower_binary_expr_with_expected_type(
        &mut self,
        binary: &BinaryExpr,
        expected_ty: IrType,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let left = self.lower_expr_with_expected_type(&binary.left, &expected_ty, current, blocks, vars);
        let Some(active) = left.current else {
            return left;
        };
        let right = if matches!(binary.op, BinaryOp::Shl | BinaryOp::Shr) {
            self.lower_expr(&binary.right, active, blocks, vars)
        } else {
            self.lower_expr_with_expected_type(&binary.right, &expected_ty, active, blocks, vars)
        };
        let Some(active) = right.current else {
            return right;
        };
        let dest = self.new_var("tmp", expected_ty);
        let block = self.block_mut(blocks, active);
        block.instructions.push(IrInstruction::Binary { dest: dest.clone(), op: binary.op, left: left.operand, right: right.operand });
        LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) }
    }

    fn lower_vec_literal_expr(
        &mut self,
        items: &[Expr],
        vec_ty: IrType,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let Some(item_ty) = collection_item_ir_type(&vec_ty) else {
            self.record_error("Vec literal requires an expected Vec<T> type", Span::default());
            return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(current) };
        };

        let dest = self.new_var("vec_literal_tmp", vec_ty);
        self.block_mut(blocks, current).instructions.push(IrInstruction::CollectionNew {
            dest: dest.clone(),
            ty: "Vec".to_string(),
            capacity: (!items.is_empty()).then_some(IrOperand::Const(IrConst::U64(items.len() as u64))),
        });

        let mut active = current;
        for item in items {
            let lowered = self.lower_expr_with_expected_type(item, &item_ty, active, blocks, vars);
            let Some(next) = lowered.current else {
                return lowered;
            };
            active = next;

            let actual_ty = self.operand_type(&lowered.operand);
            if actual_ty != item_ty {
                self.record_error(
                    format!("Vec literal type mismatch: expected {:?}, found {:?}", item_ty, actual_ty),
                    Span::default(),
                );
            }

            self.block_mut(blocks, active)
                .instructions
                .push(IrInstruction::CollectionPush { collection: IrOperand::Var(dest.clone()), value: lowered.operand });
        }

        LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) }
    }

    fn lower_empty_array_expr_with_ir_type(&mut self, ir_ty: IrType, current: BlockId, blocks: &mut [IrBlock]) -> LoweredExpr {
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
            let expected_ty = self.type_fields.get(&init.ty).and_then(|fields| fields.get(field_name)).cloned();
            let lowered = if let Some(expected_ty) = expected_ty {
                self.lower_expr_with_expected_type(field_expr, &expected_ty, active, blocks, vars)
            } else {
                self.lower_expr(field_expr, active, blocks, vars)
            };
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

        let Some(active) = self.lower_type_validity_checks(&init.ty, &field_map, active, blocks, vars) else {
            return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: None };
        };

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
            if matches!(base_var.ty, IrType::U64) && (field.field == "lock" || field.field == "type" || field.field == "type_script") {
                let script_ref_ty = if field.field == "lock" {
                    IrType::Named(CKB_LOCK_SCRIPT_REF_TYPE.to_string())
                } else {
                    IrType::Named(CKB_TYPE_SCRIPT_REF_TYPE.to_string())
                };
                let dest = self.new_var(format!("{}_script_ref", field.field), script_ref_ty);
                self.block_mut(blocks, active)
                    .instructions
                    .push(IrInstruction::Move { dest: dest.clone(), src: lowered_base.operand });
                return LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) };
            }

            if let Some((func, dest_name, return_ty)) = script_ref_property_runtime_helper(&base_var.ty, &field.field) {
                let dest = self.new_var(dest_name, return_ty);
                self.block_mut(blocks, active).instructions.push(IrInstruction::Call {
                    dest: Some(dest.clone()),
                    func: func.to_string(),
                    args: vec![lowered_base.operand],
                });
                return LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) };
            }

            if let Some((func, dest_name, return_ty)) = typed_view_property_runtime_helper(&base_var.ty, &field.field) {
                let dest = self.new_var(dest_name, return_ty);
                self.block_mut(blocks, active).instructions.push(IrInstruction::Call {
                    dest: Some(dest.clone()),
                    func: func.to_string(),
                    args: vec![lowered_base.operand],
                });
                return LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) };
            }

            if let Some(wrapper_ty) = typed_view_property_wrapper(&base_var.ty, &field.field) {
                let dest = self.new_var(format!("{}_view", field.field), IrType::Named(wrapper_ty.to_string()));
                self.block_mut(blocks, active)
                    .instructions
                    .push(IrInstruction::Move { dest: dest.clone(), src: lowered_base.operand });
                return LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) };
            }

            if let Some(fields) = self.aggregate_fields.get(&base_var.id)
                && let Some(field_var) = fields.get(&field.field)
                && self.aggregate_field_read_dominates(field_var.id)
            {
                return LoweredExpr { operand: IrOperand::Var(field_var.clone()), current: Some(active) };
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
            Expr::Integer(value) => u64::try_from(*value).ok().map(|value| IrOperand::Const(IrConst::U64(value))),
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
            Expr::Integer(value) => u64::try_from(*value).is_ok(),
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
                        .is_some_and(|ty| matches!(ty, IrType::U8 | IrType::U16 | IrType::U32 | IrType::I32 | IrType::U64))
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

    fn lower_if_expr_with_expected_type(
        &mut self,
        if_expr: &IfExpr,
        expected_ty: IrType,
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
        let then_lowered = self.lower_expr_with_expected_type(&if_expr.then_branch, &expected_ty, then_block, blocks, &mut then_vars);
        let mut else_vars = vars.clone();
        let else_lowered = self.lower_expr_with_expected_type(&if_expr.else_branch, &expected_ty, else_block, blocks, &mut else_vars);

        if then_lowered.current.is_none() && else_lowered.current.is_none() {
            return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: None };
        }

        let dest = self.new_var("if_tmp", expected_ty);
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
            let condition =
                self.lower_match_pattern_condition(&arm.pattern, lowered_scrutinee.operand.clone(), check_block, blocks, arm.span);
            let Some(condition) = condition else {
                return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(check_block) };
            };
            if matches!(condition, IrOperand::Const(IrConst::Bool(true))) {
                self.block_mut(blocks, check_block).terminator = IrTerminator::Jump(arm_entry);
            } else {
                let else_block = if index + 1 < match_expr.arms.len() {
                    self.push_block(blocks)
                } else {
                    let fail_block = self.push_block(blocks);
                    let fail = self.block_mut(blocks, fail_block);
                    fail.terminator =
                        IrTerminator::Return(Some(IrOperand::Const(IrConst::U64(CellScriptRuntimeError::FlowNewStateInvalid.code()))));
                    fail.runtime_error = Some(CellScriptRuntimeError::FlowNewStateInvalid);
                    fail_block
                };
                self.block_mut(blocks, check_block).terminator =
                    IrTerminator::Branch { cond: condition, then_block: arm_entry, else_block };
                check_block = else_block;
            }

            let mut arm_vars = vars.clone();
            self.branch_depth += 1;
            self.branch_epoch += 1;
            if !self.bind_match_pattern(&arm.pattern, lowered_scrutinee.operand.clone(), arm_entry, blocks, &mut arm_vars, arm.span) {
                self.branch_depth -= 1;
                return LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(arm_entry) };
            }
            let lowered_value = self.lower_expr(&arm.value, arm_entry, blocks, &mut arm_vars);
            self.branch_depth -= 1;
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

    fn lower_match_pattern_condition(
        &mut self,
        pattern: &MatchPattern,
        operand: IrOperand,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        span: Span,
    ) -> Option<IrOperand> {
        match pattern {
            MatchPattern::Wildcard | MatchPattern::Binding(_) => Some(IrOperand::Const(IrConst::Bool(true))),
            MatchPattern::Tuple(items) => {
                let conditions = items
                    .iter()
                    .enumerate()
                    .map(|(index, pattern)| {
                        let field = self.lower_match_field(&operand, &index.to_string(), current, blocks, span)?;
                        self.lower_match_pattern_condition(pattern, field, current, blocks, span)
                    })
                    .collect::<Option<Vec<_>>>()?;
                self.combine_match_conditions(conditions, BinaryOp::And, current, blocks)
            }
            MatchPattern::Struct { fields, .. } => {
                let conditions = fields
                    .iter()
                    .map(|(field, pattern)| {
                        let field = self.lower_match_field(&operand, field, current, blocks, span)?;
                        self.lower_match_pattern_condition(pattern, field, current, blocks, span)
                    })
                    .collect::<Option<Vec<_>>>()?;
                self.combine_match_conditions(conditions, BinaryOp::And, current, blocks)
            }
            MatchPattern::Variant { path, fields } => {
                let IrType::Named(enum_name) = self.operand_type(&operand) else {
                    self.record_error(format!("enum pattern '{}' reached IR with a non-enum operand", path), span);
                    return None;
                };
                let variant_name = path.rsplit_once("::").map_or(path.as_str(), |(_, variant)| variant);
                let layout = self.module.enum_layouts.get(&enum_name).cloned();
                let tag_condition = if let Some(layout) = &layout {
                    let Some(variant) = layout.variants.iter().find(|variant| variant.name == variant_name) else {
                        self.record_error(format!("unknown match variant '{}'", path), span);
                        return None;
                    };
                    if layout.has_payload() {
                        let tag = self.new_var("match_enum_tag", IrType::U8);
                        self.block_mut(blocks, current).instructions.push(IrInstruction::EnumTag {
                            dest: tag.clone(),
                            operand: operand.clone(),
                            enum_name: enum_name.clone(),
                        });
                        self.lower_match_equality(IrOperand::Var(tag), IrOperand::Const(IrConst::U8(variant.tag)), current, blocks)
                    } else {
                        let pattern_operand = self.lower_match_pattern_operand(path, span)?;
                        self.lower_match_equality(operand.clone(), pattern_operand, current, blocks)
                    }
                } else {
                    let pattern_operand = self.lower_match_pattern_operand(path, span)?;
                    self.lower_match_equality(operand.clone(), pattern_operand, current, blocks)
                };
                let mut conditions = vec![tag_condition];
                if !fields.is_empty() {
                    let Some(layout) = layout.filter(|layout| layout.has_payload()) else {
                        self.record_error(format!("enum pattern '{}' has payload fields but no payload layout", path), span);
                        return None;
                    };
                    let Some(variant) = layout.variants.iter().find(|variant| variant.name == variant_name) else {
                        self.record_error(format!("unknown match variant '{}'", path), span);
                        return None;
                    };
                    for (pattern, field) in fields.iter().zip(&variant.fields) {
                        let dest = self.new_var(format!("match_{}_field_{}", variant_name, field.index), field.ty.clone());
                        self.block_mut(blocks, current).instructions.push(IrInstruction::EnumPayload {
                            dest: dest.clone(),
                            operand: operand.clone(),
                            enum_name: enum_name.clone(),
                            variant: variant_name.to_string(),
                            field_index: field.index,
                        });
                        conditions.push(self.lower_match_pattern_condition(pattern, IrOperand::Var(dest), current, blocks, span)?);
                    }
                }
                self.combine_match_conditions(conditions, BinaryOp::And, current, blocks)
            }
            MatchPattern::Or(patterns) => {
                let conditions = patterns
                    .iter()
                    .map(|pattern| self.lower_match_pattern_condition(pattern, operand.clone(), current, blocks, span))
                    .collect::<Option<Vec<_>>>()?;
                self.combine_match_conditions(conditions, BinaryOp::Or, current, blocks)
            }
        }
    }

    fn lower_match_equality(&mut self, left: IrOperand, right: IrOperand, current: BlockId, blocks: &mut [IrBlock]) -> IrOperand {
        let dest = self.new_var("match_cond", IrType::Bool);
        self.block_mut(blocks, current).instructions.push(IrInstruction::Binary { dest: dest.clone(), op: BinaryOp::Eq, left, right });
        IrOperand::Var(dest)
    }

    fn combine_match_conditions(
        &mut self,
        conditions: Vec<IrOperand>,
        op: BinaryOp,
        current: BlockId,
        blocks: &mut [IrBlock],
    ) -> Option<IrOperand> {
        let mut conditions = conditions.into_iter();
        let mut combined = conditions.next().unwrap_or(IrOperand::Const(IrConst::Bool(true)));
        for condition in conditions {
            if matches!(combined, IrOperand::Const(IrConst::Bool(true))) && op == BinaryOp::And {
                combined = condition;
                continue;
            }
            let dest = self.new_var("match_pattern_cond", IrType::Bool);
            self.block_mut(blocks, current).instructions.push(IrInstruction::Binary {
                dest: dest.clone(),
                op,
                left: combined,
                right: condition,
            });
            combined = IrOperand::Var(dest);
        }
        Some(combined)
    }

    fn lower_match_field(
        &mut self,
        operand: &IrOperand,
        field: &str,
        current: BlockId,
        blocks: &mut [IrBlock],
        span: Span,
    ) -> Option<IrOperand> {
        let base = match operand {
            IrOperand::Var(var) => var.clone(),
            IrOperand::Const(value) => {
                let var = self.new_var("match_value", self.const_type(value));
                self.block_mut(blocks, current)
                    .instructions
                    .push(IrInstruction::LoadConst { dest: var.clone(), value: value.clone() });
                var
            }
        };
        if let Some(projected) = self.aggregate_fields.get(&base.id).and_then(|fields| fields.get(field)).cloned() {
            return Some(IrOperand::Var(projected));
        }
        let Some(field_ty) = self.lookup_field_ir_type(&base.ty, field) else {
            self.record_error(format!("pattern field '{}' has no IR layout on type '{}'", field, ir_type_display(&base.ty)), span);
            return None;
        };
        let dest = self.new_var(format!("match_{}_{}", base.name, field), field_ty);
        self.block_mut(blocks, current).instructions.push(IrInstruction::FieldAccess {
            dest: dest.clone(),
            obj: IrOperand::Var(base),
            field: field.to_string(),
        });
        Some(IrOperand::Var(dest))
    }

    fn bind_match_pattern(
        &mut self,
        pattern: &MatchPattern,
        operand: IrOperand,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
        span: Span,
    ) -> bool {
        match pattern {
            MatchPattern::Wildcard => true,
            MatchPattern::Binding(name) => {
                let var = match operand {
                    IrOperand::Var(var) => var,
                    IrOperand::Const(value) => {
                        let var = self.new_var(name, self.const_type(&value));
                        self.block_mut(blocks, current).instructions.push(IrInstruction::LoadConst { dest: var.clone(), value });
                        var
                    }
                };
                vars.insert(name.clone(), var);
                true
            }
            MatchPattern::Tuple(items) => items.iter().enumerate().all(|(index, pattern)| {
                self.lower_match_field(&operand, &index.to_string(), current, blocks, span)
                    .is_some_and(|field| self.bind_match_pattern(pattern, field, current, blocks, vars, span))
            }),
            MatchPattern::Struct { fields, .. } => fields.iter().all(|(field, pattern)| {
                self.lower_match_field(&operand, field, current, blocks, span)
                    .is_some_and(|field| self.bind_match_pattern(pattern, field, current, blocks, vars, span))
            }),
            MatchPattern::Variant { path, fields } => {
                if fields.is_empty() {
                    return true;
                }
                let IrType::Named(enum_name) = self.operand_type(&operand) else {
                    self.record_error(format!("enum pattern '{}' reached binding with a non-enum operand", path), span);
                    return false;
                };
                let variant_name = path.rsplit_once("::").map_or(path.as_str(), |(_, variant)| variant);
                let Some(layout) = self.module.enum_layouts.get(&enum_name).cloned() else {
                    self.record_error(format!("enum pattern '{}' has no IR payload layout", path), span);
                    return false;
                };
                let Some(variant) = layout.variants.iter().find(|variant| variant.name == variant_name) else {
                    self.record_error(format!("unknown match variant '{}'", path), span);
                    return false;
                };
                fields.iter().zip(&variant.fields).all(|(pattern, field)| {
                    let dest = self.new_var(format!("match_{}_field_{}", variant_name, field.index), field.ty.clone());
                    self.block_mut(blocks, current).instructions.push(IrInstruction::EnumPayload {
                        dest: dest.clone(),
                        operand: operand.clone(),
                        enum_name: enum_name.clone(),
                        variant: variant_name.to_string(),
                        field_index: field.index,
                    });
                    self.bind_match_pattern(pattern, IrOperand::Var(dest), current, blocks, vars, span)
                })
            }
            MatchPattern::Or(_) => true,
        }
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
                "__cellscript_consume_each" => {
                    if let Some(lowered) = self.lower_bounded_consume_each(call, current, blocks, vars) {
                        return Some(lowered);
                    }
                    self.block_mut(blocks, current).instructions.push(IrInstruction::Call {
                        dest: None,
                        func: BOUNDED_CONSUME_EACH_FAIL_CLOSED_HELPER.to_string(),
                        args: Vec::new(),
                    });
                    Some(LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: Some(current) })
                }
                "__cellscript_create_each" => {
                    if let Some(lowered) = self.lower_bounded_create_each(call, current, blocks, vars) {
                        return Some(lowered);
                    }
                    self.block_mut(blocks, current).instructions.push(IrInstruction::Call {
                        dest: None,
                        func: BOUNDED_CREATE_EACH_FAIL_CLOSED_HELPER.to_string(),
                        args: Vec::new(),
                    });
                    Some(LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: Some(current) })
                }
                "Address::zero" if call.args.is_empty() => {
                    Some(LoweredExpr { operand: IrOperand::Const(IrConst::Address([0; 32])), current: Some(current) })
                }
                "Hash::zero" if call.args.is_empty() => {
                    Some(LoweredExpr { operand: IrOperand::Const(IrConst::Hash([0; 32])), current: Some(current) })
                }
                "Hash::from_bytes" if call.args.len() == 1 => {
                    Some(self.lower_hash_from_bytes(&call.args[0], current, blocks, vars, call.span))
                }
                "script::hash_type_data" if call.args.is_empty() => {
                    Some(LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(current) })
                }
                "script::hash_type_type" if call.args.is_empty() => {
                    Some(LoweredExpr { operand: IrOperand::Const(IrConst::U64(1)), current: Some(current) })
                }
                "script::hash_type_data1" if call.args.is_empty() => {
                    Some(LoweredExpr { operand: IrOperand::Const(IrConst::U64(2)), current: Some(current) })
                }
                "script::hash_type_data2" if call.args.is_empty() => {
                    Some(LoweredExpr { operand: IrOperand::Const(IrConst::U64(4)), current: Some(current) })
                }
                "script::args_empty" if call.args.is_empty() => Some(self.lower_script_args_empty(current, blocks)),
                "script::args" if call.args.len() == 1 => Some(self.lower_script_args(&call.args[0], current, blocks, vars)),
                "script::new" if call.args.len() == 3 => Some(self.lower_script_value(call, current, blocks, vars)),
                "script::require_cell_lock_matches" if call.args.len() == 2 => {
                    Some(self.lower_script_match_requirement(call, true, current, blocks, vars))
                }
                "script::require_cell_type_matches" if call.args.len() == 2 => {
                    Some(self.lower_script_match_requirement(call, false, current, blocks, vars))
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
                "env::current_timepoint" if call.args.is_empty() => {
                    let dest = self.new_var("current_timepoint", IrType::U64);
                    self.block_mut(blocks, current).instructions.push(IrInstruction::Call {
                        dest: Some(dest.clone()),
                        func: "__env_current_timepoint".to_string(),
                        args: Vec::new(),
                    });
                    Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(current) })
                }
                "env::sighash_all" if call.args.len() == 1 => {
                    self.lower_simple_runtime_call("__ckb_sighash_all", "sighash_all", IrType::Hash, &call.args, current, blocks, vars)
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
                "ckb::since_epoch_absolute" if call.args.len() == 3 => self.lower_simple_runtime_call(
                    "__ckb_since_epoch_absolute",
                    "ckb_since_epoch_absolute",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::since_epoch_relative" if call.args.len() == 3 => self.lower_simple_runtime_call(
                    "__ckb_since_epoch_relative",
                    "ckb_since_epoch_relative",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::since_absolute_epoch" if call.args.len() == 3 => self.lower_simple_runtime_call(
                    "__ckb_since_epoch_absolute",
                    "ckb_since_absolute_epoch",
                    IrType::Named("AbsoluteEpochSince".to_string()),
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::since_relative_epoch" if call.args.len() == 3 => self.lower_simple_runtime_call(
                    "__ckb_since_epoch_relative",
                    "ckb_since_relative_epoch",
                    IrType::Named("RelativeEpochSince".to_string()),
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::since_to_raw" | "ckb::epoch_number_to_u64" | "ckb::block_number_to_u64" | "ckb::epoch_length_to_u64"
                    if call.args.len() == 1 =>
                {
                    let helper = match name.as_str() {
                        "ckb::since_to_raw" => "__ckb_since_to_raw",
                        "ckb::epoch_number_to_u64" => "__ckb_epoch_number_to_u64",
                        "ckb::block_number_to_u64" => "__ckb_block_number_to_u64",
                        _ => "__ckb_epoch_length_to_u64",
                    };
                    self.lower_simple_runtime_call(helper, "ckb_temporal_raw", IrType::U64, &call.args, current, blocks, vars)
                }
                "ckb::current_role" if call.args.is_empty() => {
                    let role = if self.lowering_lock_entry { 1 } else { 2 };
                    Some(LoweredExpr { operand: IrOperand::Const(IrConst::U64(role)), current: Some(current) })
                }
                "ckb::current_script_hash" if call.args.is_empty() => self.lower_simple_runtime_call(
                    "__ckb_current_script_hash",
                    "ckb_current_script_hash",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::script_hash" if call.args.len() == 1 => Some(self.lower_expr(&call.args[0], current, blocks, vars)),
                "ckb::cell_capacity" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_capacity",
                    "ckb_cell_capacity",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_occupied_capacity" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_occupied_capacity",
                    "ckb_cell_occupied_capacity",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_unoccupied_capacity" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_unoccupied_capacity",
                    "ckb_cell_unoccupied_capacity",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_output_index" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_output_index",
                    "ckb_cell_output_index",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::input_out_point_index" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_input_out_point_index",
                    "ckb_input_out_point_index",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::input_out_point_tx_hash_low" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_input_out_point_tx_hash_low",
                    "ckb_input_out_point_tx_hash_low",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::input_out_point_tx_hash" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_input_out_point_tx_hash",
                    "ckb_input_out_point_tx_hash",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::hash_data_packed" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_hash_data_packed",
                    "ckb_hash_data_packed",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::hash_sha256" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_hash_sha256",
                    "ckb_hash_sha256",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::hash_sha256d" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_hash_sha256d",
                    "ckb_hash_sha256d",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::hash_sha256_pair" if call.args.len() == 2 => self.lower_simple_runtime_call(
                    "__ckb_hash_sha256_pair",
                    "ckb_hash_sha256_pair",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::hash_sha256d_pair" if call.args.len() == 2 => self.lower_simple_runtime_call(
                    "__ckb_hash_sha256d_pair",
                    "ckb_hash_sha256d_pair",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::require_sha256d_merkle_root" if call.args.len() == 5 => {
                    self.lower_void_runtime_call("__ckb_require_sha256d_merkle_root", &call.args, current, blocks, vars)
                }
                "verifier::btc::bip340::require_signature" if call.args.len() == 3 => {
                    self.lower_void_runtime_call("__novaseal_bip340_require_signature", &call.args, current, blocks, vars)
                }
                "verifier::btc::bip340::require_signature_from_cell_dep" if call.args.len() == 4 => self.lower_void_runtime_call(
                    "__novaseal_bip340_require_signature_from_cell_dep",
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_lock_hash_low" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_lock_hash_low",
                    "ckb_cell_lock_hash_low",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_type_hash_low" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_type_hash_low",
                    "ckb_cell_type_hash_low",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_lock_hash" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_lock_hash",
                    "ckb_cell_lock_hash",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_type_hash" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_type_hash",
                    "ckb_cell_type_hash",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_data_hash_field" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_data_hash_field",
                    "cell_data_hash_field",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_data_hash" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_data_hash",
                    "ckb_cell_data_hash",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::raw_transaction_hash_without_cell_deps" if call.args.is_empty() => self.lower_simple_runtime_call(
                    "__ckb_raw_transaction_hash_without_cell_deps",
                    "raw_transaction_hash_without_cell_deps",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::transaction_u32_le" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_transaction_u32_le",
                    "transaction_u32_le",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "witness::bytes32" if call.args.len() == 2 => self.lower_simple_runtime_call(
                    "__ckb_witness_bytes32",
                    "witness_bytes32",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::transaction_blake2b_gather" if call.args.len() == 4 => self.lower_simple_runtime_call(
                    "__ckb_transaction_blake2b_gather",
                    "transaction_blake2b_gather",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "witness::blake2b_select_chunks" if call.args.len() == 6 => self.lower_simple_runtime_call(
                    "__ckb_witness_blake2b_select_chunks",
                    "witness_blake2b_select_chunks",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_data_blake2b_span" | "witness::blake2b_span" if call.args.len() == 3 => {
                    let (helper, result_name) = if name == "ckb::cell_data_blake2b_span" {
                        ("__ckb_cell_data_blake2b_span", "cell_data_blake2b_span")
                    } else {
                        ("__ckb_witness_blake2b_span", "witness_blake2b_span")
                    };
                    self.lower_simple_runtime_call(helper, result_name, IrType::Hash, &call.args, current, blocks, vars)
                }
                "ckb::cell_data_hash_at" if call.args.len() == 2 => self.lower_simple_runtime_call(
                    "__ckb_cell_data_hash_at",
                    "ckb_cell_data_hash_at",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_lock_code_hash" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_lock_code_hash",
                    "ckb_cell_lock_code_hash",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_type_code_hash" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_type_code_hash",
                    "ckb_cell_type_code_hash",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_lock_hash_type" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_lock_hash_type",
                    "ckb_cell_lock_hash_type",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_type_hash_type" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_type_hash_type",
                    "ckb_cell_type_hash_type",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_lock_args_empty" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_lock_args_empty",
                    "ckb_cell_lock_args_empty",
                    IrType::Bool,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_type_args_empty" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_type_args_empty",
                    "ckb_cell_type_args_empty",
                    IrType::Bool,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_lock_args_hash" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_lock_args_hash",
                    "ckb_cell_lock_args_hash",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_lock_args32" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_lock_args_hash",
                    "ckb_cell_lock_args32",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_type_args_hash" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_type_args_hash",
                    "ckb_cell_type_args_hash",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_type_args32" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_type_args_hash",
                    "ckb_cell_type_args32",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::require_cell_lock_hash" if call.args.len() == 2 => {
                    self.lower_void_runtime_call("__ckb_require_cell_lock_hash", &call.args, current, blocks, vars)
                }
                "ckb::require_cell_type_hash" if call.args.len() == 2 => {
                    self.lower_void_runtime_call("__ckb_require_cell_type_hash", &call.args, current, blocks, vars)
                }
                "ckb::require_cell_data_hash" if call.args.len() == 2 => {
                    self.lower_void_runtime_call("__ckb_require_cell_data_hash", &call.args, current, blocks, vars)
                }
                "ckb::require_bounded_cell_dep_data_hash" if call.args.len() == 2 => {
                    self.lower_void_runtime_call("__ckb_require_bounded_cell_dep_data_hash", &call.args, current, blocks, vars)
                }
                "ckb::require_current_script_args_empty" if call.args.is_empty() => {
                    self.lower_void_runtime_call("__ckb_require_current_script_args_empty", &call.args, current, blocks, vars)
                }
                "ckb::require_cell_lock_args_empty" if call.args.len() == 1 => {
                    self.lower_void_runtime_call("__ckb_require_cell_lock_args_empty", &call.args, current, blocks, vars)
                }
                "ckb::require_cell_type_args_empty" if call.args.len() == 1 => {
                    self.lower_void_runtime_call("__ckb_require_cell_type_args_empty", &call.args, current, blocks, vars)
                }
                "ckb::require_cell_lock_args_hash" if call.args.len() == 2 => {
                    self.lower_void_runtime_call("__ckb_require_cell_lock_args_hash", &call.args, current, blocks, vars)
                }
                "ckb::require_cell_type_args_hash" if call.args.len() == 2 => {
                    self.lower_void_runtime_call("__ckb_require_cell_type_args_hash", &call.args, current, blocks, vars)
                }
                "ckb::require_cell_lock_args_prefix_hash" if call.args.len() == 2 => {
                    self.lower_void_runtime_call("__ckb_require_cell_lock_args_prefix_hash", &call.args, current, blocks, vars)
                }
                "ckb::require_cell_type_args_prefix_hash" if call.args.len() == 2 => {
                    self.lower_void_runtime_call("__ckb_require_cell_type_args_prefix_hash", &call.args, current, blocks, vars)
                }
                "ckb::require_cell_lock_args_suffix_hash" if call.args.len() == 2 => {
                    self.lower_void_runtime_call("__ckb_require_cell_lock_args_suffix_hash", &call.args, current, blocks, vars)
                }
                "ckb::require_cell_type_args_suffix_hash" if call.args.len() == 2 => {
                    self.lower_void_runtime_call("__ckb_require_cell_type_args_suffix_hash", &call.args, current, blocks, vars)
                }
                "ckb::require_cell_lock_script_hash_type" if call.args.len() == 3 => {
                    self.lower_void_runtime_call("__ckb_require_cell_lock_script_hash_type", &call.args, current, blocks, vars)
                }
                "ckb::require_cell_type_script_hash_type" if call.args.len() == 3 => {
                    self.lower_void_runtime_call("__ckb_require_cell_type_script_hash_type", &call.args, current, blocks, vars)
                }
                "ckb::require_input_out_point_tx_hash" if call.args.len() == 2 => {
                    self.lower_void_runtime_call("__ckb_require_input_out_point_tx_hash", &call.args, current, blocks, vars)
                }
                "ckb::require_input_out_point" if call.args.len() == 3 => {
                    self.lower_void_runtime_call("__ckb_require_input_out_point", &call.args, current, blocks, vars)
                }
                "ckb::require_metapoint_relative" if call.args.len() == 3 => {
                    self.lower_void_runtime_call("__ckb_require_metapoint_relative", &call.args, current, blocks, vars)
                }
                "ckb::require_lock_type_metapoint_pairs" if call.args.len() == 2 => {
                    self.lower_void_runtime_call("__ckb_require_lock_type_metapoint_pairs", &call.args, current, blocks, vars)
                }
                "ckb::require_type_lock_metapoint_pairs" if call.args.len() == 2 => {
                    self.lower_void_runtime_call("__ckb_require_type_lock_metapoint_pairs", &call.args, current, blocks, vars)
                }
                "ckb::require_lock_type_metapoint_pairs_from_i32_data" if call.args.len() == 2 => self.lower_void_runtime_call(
                    "__ckb_require_lock_type_metapoint_pairs_from_i32_data",
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::require_type_lock_metapoint_pairs_from_i32_data" if call.args.len() == 2 => self.lower_void_runtime_call(
                    "__ckb_require_type_lock_metapoint_pairs_from_i32_data",
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::require_lock_type_metapoint_pairs_from_i32_data_filtered" if call.args.len() == 4 => self
                    .lower_void_runtime_call(
                        "__ckb_require_lock_type_metapoint_pairs_from_i32_data_filtered",
                        &call.args,
                        current,
                        blocks,
                        vars,
                    ),
                "ckb::require_type_lock_metapoint_pairs_from_i32_data_filtered" if call.args.len() == 4 => self
                    .lower_void_runtime_call(
                        "__ckb_require_type_lock_metapoint_pairs_from_i32_data_filtered",
                        &call.args,
                        current,
                        blocks,
                        vars,
                    ),
                "ckb::require_lock_match_master_out_point_pairs_from_data" if call.args.len() == 5 => self.lower_void_runtime_call(
                    "__ckb_require_lock_match_master_out_point_pairs_from_data",
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::exec_cell_dep_u8_args" if call.args.len() == 6 => {
                    self.lower_void_runtime_call("__ckb_exec_cell_dep_u8_args", &call.args, current, blocks, vars)
                }
                "ckb::trusted_exec_cell_dep_u8_args" if call.args.len() == 7 => self.lower_trusted_external_call(
                    "exec",
                    "__ckb_exec_cell_dep_u8_args",
                    &call.args,
                    current,
                    blocks,
                    vars,
                    call.span,
                ),
                "ckb::exec_cell_dep_hex4" if call.args.len() == 6 => {
                    self.lower_void_runtime_call("__ckb_exec_cell_dep_hex4", &call.args, current, blocks, vars)
                }
                "ckb::trusted_exec_cell_dep_hex4" if call.args.len() == 7 => {
                    self.lower_trusted_external_call("exec", "__ckb_exec_cell_dep_hex4", &call.args, current, blocks, vars, call.span)
                }
                "ckb::spawn_wait_cell_dep_hex4" if call.args.len() == 6 => {
                    self.lower_void_runtime_call("__ckb_spawn_wait_cell_dep_hex4", &call.args, current, blocks, vars)
                }
                "ckb::trusted_spawn_wait_cell_dep_hex4" if call.args.len() == 7 => self.lower_trusted_external_call(
                    "spawn-wait",
                    "__ckb_spawn_wait_cell_dep_hex4",
                    &call.args,
                    current,
                    blocks,
                    vars,
                    call.span,
                ),
                "ckb::cell_count" | "ckb::cell_has_type" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    if name == "ckb::cell_count" { "__ckb_cell_count" } else { "__ckb_cell_has_type" },
                    if name == "ckb::cell_count" { "ckb_cell_count" } else { "ckb_cell_has_type" },
                    if name == "ckb::cell_count" { IrType::U64 } else { IrType::Bool },
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_lock_size" | "ckb::cell_type_size" | "ckb::input_since_at" if call.args.len() == 1 => {
                    let (helper, result) = match name.as_str() {
                        "ckb::cell_lock_size" => ("__ckb_cell_lock_size", "cell_lock_size"),
                        "ckb::cell_type_size" => ("__ckb_cell_type_size", "cell_type_size"),
                        _ => ("__ckb_input_since_at", "input_since_at"),
                    };
                    self.lower_simple_runtime_call(helper, result, IrType::U64, &call.args, current, blocks, vars)
                }
                "ckb::cell_lock_u8" | "ckb::cell_type_u8" if call.args.len() == 2 => {
                    let (helper, result) = if name == "ckb::cell_lock_u8" {
                        ("__ckb_cell_lock_u8", "cell_lock_u8")
                    } else {
                        ("__ckb_cell_type_u8", "cell_type_u8")
                    };
                    self.lower_simple_runtime_call(helper, result, IrType::U64, &call.args, current, blocks, vars)
                }
                "ckb::cell_data_size" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_cell_data_size",
                    "ckb_cell_data_size",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_data_u8" if call.args.len() == 2 => self.lower_simple_runtime_call(
                    "__ckb_cell_data_u8",
                    "ckb_cell_data_u8",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_data_u32_le" if call.args.len() == 2 => self.lower_simple_runtime_call(
                    "__ckb_cell_data_u32_le",
                    "ckb_cell_data_u32_le",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::cell_data_u64_le" if call.args.len() == 2 => self.lower_simple_runtime_call(
                    "__ckb_cell_data_u64_le",
                    "ckb_cell_data_u64_le",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::input" | "ckb::group_input" if call.args.len() == 1 && call.type_args.len() == 1 => {
                    let type_name = inline_ir_type_repr(&ast_type_to_ir(&call.type_args[0])).unwrap_or_else(|| "unknown".to_string());
                    self.lower_simple_runtime_call(
                        if name == "ckb::input" { "__ckb_source_input" } else { "__ckb_source_group_input" },
                        if name == "ckb::input" { "typed_input_view" } else { "typed_group_input_view" },
                        IrType::Named(format!("InputView<{type_name}>")),
                        &call.args,
                        current,
                        blocks,
                        vars,
                    )
                }
                "ckb::output" | "ckb::group_output" if call.args.len() == 1 && call.type_args.len() == 1 => {
                    let type_name = inline_ir_type_repr(&ast_type_to_ir(&call.type_args[0])).unwrap_or_else(|| "unknown".to_string());
                    self.lower_simple_runtime_call(
                        if name == "ckb::output" { "__ckb_source_output" } else { "__ckb_source_group_output" },
                        if name == "ckb::output" { "typed_output_view" } else { "typed_group_output_view" },
                        IrType::Named(format!("OutputView<{type_name}>")),
                        &call.args,
                        current,
                        blocks,
                        vars,
                    )
                }
                "ckb::cell_dep" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_source_cell_dep",
                    "typed_cell_dep_view",
                    IrType::Named("CellDepView".to_string()),
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::header_dep" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_source_header_dep",
                    "typed_header_dep_view",
                    IrType::Named("HeaderDepView".to_string()),
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "witness::args" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_source_input",
                    "typed_witness_args_view",
                    IrType::Named("WitnessArgsView".to_string()),
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::input_out_point" if call.args.len() == 1 => {
                    self.lower_transparent_view_wrapper(call, CKB_INPUT_OUT_POINT_REF_TYPE, current, blocks, vars)
                }
                "ckb::lock_script" if call.args.len() == 1 => {
                    self.lower_transparent_view_wrapper(call, CKB_LOCK_SCRIPT_REF_TYPE, current, blocks, vars)
                }
                "ckb::type_script" if call.args.len() == 1 => {
                    self.lower_transparent_view_wrapper(call, CKB_TYPE_SCRIPT_REF_TYPE, current, blocks, vars)
                }
                "source::input" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_source_input",
                    "source_input",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "source::output" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_source_output",
                    "source_output",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "source::cell_dep" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_source_cell_dep",
                    "source_cell_dep",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "source::header_dep" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_source_header_dep",
                    "source_header_dep",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "source::group_input" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_source_group_input",
                    "source_group_input",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "source::group_output" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_source_group_output",
                    "source_group_output",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "witness::count" if call.args.is_empty() => self.lower_simple_runtime_call(
                    "__ckb_witness_count",
                    "witness_count",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "witness::byte" | "witness::u32_le" | "witness::u64_le" if call.args.len() == 2 => {
                    let (helper, result_name) = match name.as_str() {
                        "witness::byte" => ("__ckb_witness_u8", "witness_u8"),
                        "witness::u32_le" => ("__ckb_witness_u32_le", "witness_u32_le"),
                        _ => ("__ckb_witness_u64_le", "witness_u64_le"),
                    };
                    self.lower_simple_runtime_call(helper, result_name, IrType::U64, &call.args, current, blocks, vars)
                }
                "witness::raw" if call.args.len() == 1 => {
                    self.lower_simple_runtime_call("__ckb_witness_raw", "witness_raw", IrType::Hash, &call.args, current, blocks, vars)
                }
                "witness::lock" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_witness_lock",
                    "witness_lock",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "witness::input_type" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_witness_input_type",
                    "witness_input_type",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "witness::output_type" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_witness_output_type",
                    "witness_output_type",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "witness::size" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_witness_size",
                    "witness_size",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "ckb::require_witness_size_at_least" if call.args.len() == 2 => {
                    self.lower_void_runtime_call("__ckb_require_witness_size_at_least", &call.args, current, blocks, vars)
                }
                "dao::accumulated_rate" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__dao_accumulated_rate",
                    "dao_accumulated_rate",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "dao::input_accumulated_rate" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__dao_input_accumulated_rate",
                    "dao_input_accumulated_rate",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "dao::is_deposit_data" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__dao_is_deposit_data",
                    "dao_is_deposit_data",
                    IrType::Bool,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "dao::is_withdrawal_request_data" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__dao_is_withdrawal_request_data",
                    "dao_is_withdrawal_request_data",
                    IrType::Bool,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "dao::has_dao_type" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__dao_has_dao_type",
                    "dao_has_dao_type",
                    IrType::Bool,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "dao::require_header_dep_for_input" if call.args.len() == 2 => {
                    self.lower_void_runtime_call("__dao_require_header_dep_for_input", &call.args, current, blocks, vars)
                }
                "dao::require_input_since_at_least" if call.args.len() == 2 => {
                    self.lower_void_runtime_call("__dao_require_input_since_at_least", &call.args, current, blocks, vars)
                }
                "dao::require_input_relative_epoch_since_at_least" if call.args.len() == 4 => self.lower_void_runtime_call(
                    "__dao_require_input_relative_epoch_since_at_least",
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "xudt::amount_low" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__xudt_amount_low",
                    "xudt_amount_low",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "xudt::amount_high" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__xudt_amount_high",
                    "xudt_amount_high",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "xudt::owner_mode_input_type_hash" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__xudt_owner_mode_input_type_hash",
                    "xudt_owner_mode_input_type_hash",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "xudt::require_owner_mode_input_type" if call.args.len() == 2 => {
                    self.lower_void_runtime_call("__xudt_require_owner_mode_input_type", &call.args, current, blocks, vars)
                }
                "xudt::require_owner_mode_type_args" if call.args.len() == 3 => {
                    self.lower_void_runtime_call("__xudt_require_owner_mode_type_args", &call.args, current, blocks, vars)
                }
                "xudt::require_owner_mode_type_args_current_script" if call.args.len() == 2 => self.lower_void_runtime_call(
                    "__xudt_require_owner_mode_type_args_current_script",
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "xudt::require_group_amount_conserved" if call.args.is_empty() => {
                    self.lower_void_runtime_call("__xudt_require_group_amount_conserved", &call.args, current, blocks, vars)
                }
                "xudt::require_group_amount_minted" if call.args.len() == 1 => {
                    self.lower_void_runtime_call("__xudt_require_group_amount_minted", &call.args, current, blocks, vars)
                }
                "xudt::require_group_amount_burned" if call.args.len() == 1 => {
                    self.lower_void_runtime_call("__xudt_require_group_amount_burned", &call.args, current, blocks, vars)
                }
                "c256::require_product_lte" if call.args.len() == 4 => {
                    self.lower_void_runtime_call("__c256_require_u128_product_lte", &call.args, current, blocks, vars)
                }
                "c256::require_product_eq" if call.args.len() == 4 => {
                    self.lower_void_runtime_call("__c256_require_u128_product_eq", &call.args, current, blocks, vars)
                }
                "c256::require_sum2_products_lte" if call.args.len() == 8 => {
                    self.lower_void_runtime_call("__c256_require_u128_sum2_products_lte", &call.args, current, blocks, vars)
                }
                "c256::require_sum2_products_eq" if call.args.len() == 8 => {
                    self.lower_void_runtime_call("__c256_require_u128_sum2_products_eq", &call.args, current, blocks, vars)
                }
                "spawn" if call.args.len() == 1 => {
                    let dest = self.new_var("spawn_result", IrType::U64);
                    let target = match &call.args[0] {
                        Expr::String(value) => IrOperand::Const(IrConst::U64(stable_u64_tag(value))),
                        Expr::Identifier(name) => match self.constants.get(name) {
                            Some((Expr::String(value), _)) => IrOperand::Const(IrConst::U64(stable_u64_tag(value))),
                            _ => {
                                let lowered = self.lower_expr(&call.args[0], current, blocks, vars);
                                let active = lowered.current?;
                                self.block_mut(blocks, active).instructions.push(IrInstruction::Call {
                                    dest: Some(dest.clone()),
                                    func: "__ckb_spawn".to_string(),
                                    args: vec![lowered.operand],
                                });
                                return Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) });
                            }
                        },
                        other => {
                            let lowered = self.lower_expr(other, current, blocks, vars);
                            let active = lowered.current?;
                            self.block_mut(blocks, active).instructions.push(IrInstruction::Call {
                                dest: Some(dest.clone()),
                                func: "__ckb_spawn".to_string(),
                                args: vec![lowered.operand],
                            });
                            return Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) });
                        }
                    };
                    self.block_mut(blocks, current).instructions.push(IrInstruction::Call {
                        dest: Some(dest.clone()),
                        func: "__ckb_spawn".to_string(),
                        args: vec![target],
                    });
                    Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(current) })
                }
                "pipe" if call.args.is_empty() => {
                    let dest = self.new_var("pipe_pair", IrType::Tuple(vec![IrType::U64, IrType::U64]));
                    self.block_mut(blocks, current).instructions.push(IrInstruction::Call {
                        dest: Some(dest.clone()),
                        func: "__ckb_pipe".to_string(),
                        args: Vec::new(),
                    });
                    Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(current) })
                }
                "wait" if call.args.is_empty() => {
                    self.lower_simple_runtime_call("__ckb_wait", "wait_result", IrType::U64, &call.args, current, blocks, vars)
                }
                "process_id" if call.args.is_empty() => {
                    self.lower_simple_runtime_call("__ckb_process_id", "process_id", IrType::U64, &call.args, current, blocks, vars)
                }
                "pipe_write" if call.args.len() == 2 => self.lower_simple_runtime_call(
                    "__ckb_pipe_write",
                    "pipe_write_result",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "pipe_read" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_pipe_read",
                    "pipe_read_result",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "inherited_fd" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_inherited_fd",
                    "inherited_fd",
                    IrType::U64,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "close" if call.args.len() == 1 => {
                    self.lower_simple_runtime_call("__ckb_close", "close_result", IrType::U64, &call.args, current, blocks, vars)
                }
                "require_maturity" if call.args.len() == 1 => {
                    self.lower_void_runtime_call("__ckb_require_maturity", &call.args, current, blocks, vars)
                }
                "require_time" if call.args.len() == 1 => {
                    self.lower_void_runtime_call("__ckb_require_time", &call.args, current, blocks, vars)
                }
                "require_epoch_after" if call.args.len() == 3 => {
                    self.lower_void_runtime_call("__ckb_require_epoch_after", &call.args, current, blocks, vars)
                }
                "require_epoch_relative" if call.args.len() == 3 => {
                    self.lower_void_runtime_call("__ckb_require_epoch_relative", &call.args, current, blocks, vars)
                }
                "occupied_capacity" if call.args.len() == 1 => {
                    let dest = self.new_var("occupied_capacity", IrType::U64);
                    let tag = match &call.args[0] {
                        Expr::String(value) => stable_u64_tag(value),
                        _ => 0,
                    };
                    self.block_mut(blocks, current).instructions.push(IrInstruction::Call {
                        dest: Some(dest.clone()),
                        func: "__ckb_occupied_capacity".to_string(),
                        args: vec![IrOperand::Const(IrConst::U64(tag))],
                    });
                    Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(current) })
                }
                "hash_chain" if call.args.len() == 1 => {
                    self.lower_simple_runtime_call("__ckb_hash_chain", "hash_chain", IrType::Hash, &call.args, current, blocks, vars)
                }
                "hash_pair" if call.args.len() == 2 => {
                    self.lower_simple_runtime_call("__ckb_hash_pair", "hash_pair", IrType::Hash, &call.args, current, blocks, vars)
                }
                "hash_blake2b" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_hash_blake2b",
                    "hash_blake2b",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
                "hash_blake2b_packed" if call.args.len() == 1 => self.lower_simple_runtime_call(
                    "__ckb_hash_blake2b_packed",
                    "hash_blake2b_packed",
                    IrType::Hash,
                    &call.args,
                    current,
                    blocks,
                    vars,
                ),
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
                    if let IrOperand::Var(var) = &lowered.operand
                        && let Some(elements) = self.aggregate_elements.get(&var.id)
                    {
                        return Some(LoweredExpr {
                            operand: IrOperand::Const(IrConst::U64(elements.len() as u64)),
                            current: Some(active),
                        });
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
                    if let IrOperand::Var(var) = &lowered.operand
                        && let Some(elements) = self.aggregate_elements.get(&var.id)
                    {
                        return Some(LoweredExpr {
                            operand: IrOperand::Const(IrConst::Bool(elements.is_empty())),
                            current: Some(active),
                        });
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
                "capacity" if call.args.is_empty() => {
                    let lowered_collection = self.lower_expr(&field.expr, current, blocks, vars);
                    let active = lowered_collection.current?;
                    let dest = self.new_var("capacity_tmp", IrType::U64);
                    self.block_mut(blocks, active)
                        .instructions
                        .push(IrInstruction::CollectionCapacity { dest: dest.clone(), collection: lowered_collection.operand });
                    Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) })
                }
                "first" if call.args.is_empty() => {
                    let lowered_collection = self.lower_expr(&field.expr, current, blocks, vars);
                    let active = lowered_collection.current?;
                    let item_ty = collection_item_ir_type(&self.operand_type(&lowered_collection.operand)).unwrap_or(IrType::U64);
                    let dest = self.new_var("first_tmp", item_ty);
                    self.block_mut(blocks, active).instructions.push(IrInstruction::Index {
                        dest: dest.clone(),
                        arr: lowered_collection.operand,
                        idx: IrOperand::Const(IrConst::U64(0)),
                    });
                    Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) })
                }
                "last" if call.args.is_empty() => {
                    let lowered_collection = self.lower_expr(&field.expr, current, blocks, vars);
                    let active = lowered_collection.current?;
                    let item_ty = collection_item_ir_type(&self.operand_type(&lowered_collection.operand)).unwrap_or(IrType::U64);
                    let len_dest = self.new_var("last_len_tmp", IrType::U64);
                    let index_dest = self.new_var("last_index_tmp", IrType::U64);
                    let dest = self.new_var("last_tmp", item_ty);
                    let block = self.block_mut(blocks, active);
                    block
                        .instructions
                        .push(IrInstruction::Length { dest: len_dest.clone(), operand: lowered_collection.operand.clone() });
                    block.instructions.push(IrInstruction::Binary {
                        dest: index_dest.clone(),
                        op: BinaryOp::Sub,
                        left: IrOperand::Var(len_dest),
                        right: IrOperand::Const(IrConst::U64(1)),
                    });
                    block.instructions.push(IrInstruction::Index {
                        dest: dest.clone(),
                        arr: lowered_collection.operand,
                        idx: IrOperand::Var(index_dest),
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
                        && matches!(&collection_var.ty, IrType::Named(name) if name == "Vec")
                        && let (Some(item_ty), Some(receiver_var)) =
                            (inline_ir_type_repr(&self.operand_type(&lowered_value.operand)), vars.get_mut(receiver_name))
                        && receiver_var.id == collection_var.id
                    {
                        receiver_var.ty = IrType::Named(format!("Vec<{}>", item_ty));
                    }
                    let block = self.block_mut(blocks, active);
                    block.instructions.push(IrInstruction::CollectionPush {
                        collection: collection_operand.clone(),
                        value: lowered_value.operand.clone(),
                    });
                    if let IrOperand::Var(collection_var) = &collection_operand
                        && let Some((root_id, field_name)) = self.schema_field_roots.get(&collection_var.id).cloned()
                    {
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
                "reverse" if call.args.is_empty() => {
                    let lowered_collection = self.lower_expr(&field.expr, current, blocks, vars);
                    let active = lowered_collection.current?;
                    self.block_mut(blocks, active)
                        .instructions
                        .push(IrInstruction::CollectionReverse { collection: lowered_collection.operand });
                    Some(LoweredExpr { operand: IrOperand::Const(IrConst::Bool(true)), current: Some(active) })
                }
                "truncate" if call.args.len() == 1 => {
                    let lowered_collection = self.lower_expr(&field.expr, current, blocks, vars);
                    let active = lowered_collection.current?;
                    let lowered_len = self.lower_expr(&call.args[0], active, blocks, vars);
                    let active = lowered_len.current?;
                    self.block_mut(blocks, active)
                        .instructions
                        .push(IrInstruction::CollectionTruncate { collection: lowered_collection.operand, len: lowered_len.operand });
                    Some(LoweredExpr { operand: IrOperand::Const(IrConst::Bool(true)), current: Some(active) })
                }
                "swap" if call.args.len() == 2 => {
                    let lowered_collection = self.lower_expr(&field.expr, current, blocks, vars);
                    let active = lowered_collection.current?;
                    let lowered_left = self.lower_expr(&call.args[0], active, blocks, vars);
                    let active = lowered_left.current?;
                    let lowered_right = self.lower_expr(&call.args[1], active, blocks, vars);
                    let active = lowered_right.current?;
                    self.block_mut(blocks, active).instructions.push(IrInstruction::CollectionSwap {
                        collection: lowered_collection.operand,
                        left: lowered_left.operand,
                        right: lowered_right.operand,
                    });
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
                        && matches!(&collection_var.ty, IrType::Named(name) if name == "Vec")
                        && let (Some(item_ty), Some(receiver_var)) =
                            (inline_ir_type_repr(&self.operand_type(&lowered_value.operand)), vars.get_mut(receiver_name))
                        && receiver_var.id == collection_var.id
                    {
                        receiver_var.ty = IrType::Named(format!("Vec<{}>", item_ty));
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
                        && matches!(&collection_var.ty, IrType::Named(name) if name == "Vec")
                        && let (Some(item_ty), Some(receiver_var)) =
                            (inline_ir_type_repr(&self.operand_type(&lowered_value.operand)), vars.get_mut(receiver_name))
                        && receiver_var.id == collection_var.id
                    {
                        receiver_var.ty = IrType::Named(format!("Vec<{}>", item_ty));
                    }
                    self.block_mut(blocks, active).instructions.push(IrInstruction::CollectionInsert {
                        collection: collection_operand,
                        index: lowered_index.operand,
                        value: lowered_value.operand,
                    });
                    Some(LoweredExpr { operand: IrOperand::Const(IrConst::Bool(true)), current: Some(active) })
                }
                "set" if call.args.len() == 2 => {
                    let lowered_collection = self.lower_expr(&field.expr, current, blocks, vars);
                    let active = lowered_collection.current?;
                    let lowered_index = self.lower_expr(&call.args[0], active, blocks, vars);
                    let active = lowered_index.current?;
                    let lowered_value = self.lower_expr(&call.args[1], active, blocks, vars);
                    let active = lowered_value.current?;
                    let collection_operand = lowered_collection.operand;
                    if let (Expr::Identifier(receiver_name), IrOperand::Var(collection_var)) =
                        (field.expr.as_ref(), &collection_operand)
                        && matches!(&collection_var.ty, IrType::Named(name) if name == "Vec")
                        && let (Some(item_ty), Some(receiver_var)) =
                            (inline_ir_type_repr(&self.operand_type(&lowered_value.operand)), vars.get_mut(receiver_name))
                        && receiver_var.id == collection_var.id
                    {
                        receiver_var.ty = IrType::Named(format!("Vec<{}>", item_ty));
                    }
                    self.block_mut(blocks, active).instructions.push(IrInstruction::CollectionSet {
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
                        && matches!(&collection_var.ty, IrType::Named(name) if name == "Vec")
                        && let (IrType::Array(inner, _), Some(receiver_var)) =
                            (self.operand_type(&lowered_slice.operand), vars.get_mut(receiver_name))
                        && receiver_var.id == collection_var.id
                        && let Some(item_ty) = inline_ir_type_repr(inner.as_ref())
                    {
                        receiver_var.ty = IrType::Named(format!("Vec<{}>", item_ty));
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

    fn lower_bounded_consume_each(
        &mut self,
        call: &CallExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> Option<LoweredExpr> {
        let [Expr::Identifier(binding), Expr::Identifier(collection_binding), Expr::Block(body)] = call.args.as_slice() else {
            return None;
        };
        let collection_var = vars.get(collection_binding)?.clone();
        let IrType::Named(collection_type) = &collection_var.ty else {
            return None;
        };
        let collection = parse_bounded_collection_type(&Type::Named(collection_type.clone()))?;
        if collection.kind != BoundedCollectionKind::CellSet {
            return None;
        }
        let element_width =
            self.bounded_consume_runtime_width(&collection.element_type, ParamSource::Input, collection.max_elements)?;

        let index_var = self.new_var("bounded_cell_index", IrType::U64);
        self.block_mut(blocks, current)
            .instructions
            .push(IrInstruction::Move { dest: index_var.clone(), src: IrOperand::Const(IrConst::U64(0)) });

        let scan_block = self.push_block(blocks);
        let body_block = self.push_block(blocks);
        let exit_block = self.push_block(blocks);
        self.block_mut(blocks, current).terminator = IrTerminator::Jump(scan_block);

        let element_var = self.new_var(binding.clone(), IrType::Named(collection.element_type.clone()));
        let found_var = self.new_var("bounded_cell_found", IrType::Bool);
        self.block_mut(blocks, scan_block).instructions.push(IrInstruction::BoundedCellLoad {
            dest: element_var.clone(),
            found: found_var.clone(),
            index: IrOperand::Var(index_var.clone()),
            max_elements: collection.max_elements,
            element_type: collection.element_type.clone(),
            element_width,
        });
        self.block_mut(blocks, scan_block).terminator =
            IrTerminator::Branch { cond: IrOperand::Var(found_var), then_block: body_block, else_block: exit_block };

        let mut body_vars = vars.clone();
        body_vars.insert(binding.clone(), element_var);
        let body_exit = self.lower_stmts(body, body_block, blocks, &mut body_vars, None, false);
        if let Some(body_exit) = body_exit {
            let next_index = self.new_var("bounded_cell_next", IrType::U64);
            let block = self.block_mut(blocks, body_exit);
            block.instructions.push(IrInstruction::Binary {
                dest: next_index.clone(),
                op: BinaryOp::Add,
                left: IrOperand::Var(index_var.clone()),
                right: IrOperand::Const(IrConst::U64(1)),
            });
            block.instructions.push(IrInstruction::Move { dest: index_var, src: IrOperand::Var(next_index) });
            block.terminator = IrTerminator::Jump(scan_block);
        }

        Some(LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: Some(exit_block) })
    }

    fn lower_bounded_create_each(
        &mut self,
        call: &CallExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> Option<LoweredExpr> {
        let [Expr::Identifier(binding), Expr::Identifier(collection_binding), Expr::Block(body)] = call.args.as_slice() else {
            return None;
        };
        let collection_var = vars.get(collection_binding)?.clone();
        let IrType::Named(collection_type) = &collection_var.ty else {
            return None;
        };
        let collection = parse_bounded_collection_type(&Type::Named(collection_type.clone()))?;
        if collection.kind != BoundedCollectionKind::List {
            return None;
        }
        let create = body.iter().find_map(|stmt| match stmt {
            Stmt::Expr(Expr::Create(create)) => Some(create),
            _ => None,
        })?;
        let (element_width, capacity_floor_shannons) =
            self.bounded_create_call_runtime_shape(&collection.element_type, collection.max_elements, create)?;

        let index_var = self.new_var("bounded_plan_index", IrType::U64);
        self.block_mut(blocks, current)
            .instructions
            .push(IrInstruction::Move { dest: index_var.clone(), src: IrOperand::Const(IrConst::U64(0)) });

        let scan_block = self.push_block(blocks);
        let body_block = self.push_block(blocks);
        let exit_block = self.push_block(blocks);
        self.block_mut(blocks, current).terminator = IrTerminator::Jump(scan_block);

        let element_var = self.new_var(binding.clone(), IrType::Named(collection.element_type.clone()));
        let found_var = self.new_var("bounded_plan_found", IrType::Bool);
        self.block_mut(blocks, scan_block).instructions.push(IrInstruction::BoundedPlanLoad {
            dest: element_var.clone(),
            found: found_var.clone(),
            plan: IrOperand::Var(collection_var),
            index: IrOperand::Var(index_var.clone()),
            max_elements: collection.max_elements,
            element_type: collection.element_type.clone(),
            element_width,
        });
        self.block_mut(blocks, scan_block).terminator =
            IrTerminator::Branch { cond: IrOperand::Var(found_var), then_block: body_block, else_block: exit_block };

        let mut body_vars = vars.clone();
        body_vars.insert(binding.clone(), element_var);
        let mut active = Some(body_block);
        for stmt in body {
            let Some(current_body) = active else { break };
            if let Stmt::Expr(Expr::Create(create)) = stmt {
                let (next, pattern) = self.lower_bounded_create_pattern(create, current_body, blocks, &mut body_vars)?;
                self.block_mut(blocks, next).instructions.push(IrInstruction::BoundedOutputVerify {
                    index: IrOperand::Var(index_var.clone()),
                    pattern,
                    capacity_floor_shannons,
                });
                active = Some(next);
            } else {
                active = self.lower_stmt(stmt, current_body, blocks, &mut body_vars, None);
            }
        }
        if let Some(body_exit) = active {
            let next_index = self.new_var("bounded_plan_next", IrType::U64);
            let block = self.block_mut(blocks, body_exit);
            block.instructions.push(IrInstruction::Binary {
                dest: next_index.clone(),
                op: BinaryOp::Add,
                left: IrOperand::Var(index_var.clone()),
                right: IrOperand::Const(IrConst::U64(1)),
            });
            block.instructions.push(IrInstruction::Move { dest: index_var.clone(), src: IrOperand::Var(next_index) });
            block.terminator = IrTerminator::Jump(scan_block);
        }

        self.block_mut(blocks, exit_block).instructions.push(IrInstruction::BoundedOutputEnd { index: IrOperand::Var(index_var) });
        Some(LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: Some(exit_block) })
    }

    fn bounded_create_call_runtime_shape(&self, element_type: &str, max_elements: usize, create: &CreateExpr) -> Option<(usize, u64)> {
        if !(1..=1024).contains(&max_elements) || self.type_kinds.get(element_type) != Some(&IrTypeKind::Struct) {
            return None;
        }
        let plan_width = self.fixed_encoded_size(&IrType::Named(element_type.to_string()))?;
        let encoded_max = max_elements.checked_mul(plan_width)?.checked_add(12)?;
        if plan_width == 0 || encoded_max > BOUNDED_OUTPUT_PLAN_MAX_BYTES {
            return None;
        }
        if self.type_kinds.get(&create.ty) != Some(&IrTypeKind::Resource)
            || self
                .fixed_encoded_size(&IrType::Named(create.ty.clone()))
                .is_none_or(|width| width == 0 || width > BOUNDED_CELL_RUNTIME_MAX_DATA_BYTES)
            || self.type_identities.get(&create.ty) != Some(&IrIdentityPolicy::None)
            || create.lock.is_none()
        {
            return None;
        }
        let fields = self.type_fields.get(&create.ty)?;
        if create.fields.len() != fields.len() || !fields.keys().all(|field| create.fields.iter().any(|(name, _)| name == field)) {
            return None;
        }
        Some((plan_width, self.type_capacity_floors.get(&create.ty).copied().filter(|floor| *floor > 0)?))
    }

    fn lower_bounded_create_pattern(
        &mut self,
        create: &CreateExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> Option<(BlockId, CreatePattern)> {
        let mut active = current;
        let mut lowered_fields = Vec::with_capacity(create.fields.len());
        let mut field_vars = HashMap::new();
        for (field_name, field_expr) in &create.fields {
            let expected_ty = self.type_fields.get(&create.ty).and_then(|fields| fields.get(field_name)).cloned();
            let lowered = if let Some(state_operand) = self.lower_flow_state_initializer(&create.ty, field_name, field_expr) {
                LoweredExpr { operand: state_operand, current: Some(active) }
            } else if let Some(expected_ty) = expected_ty {
                self.lower_expr_with_expected_type(field_expr, &expected_ty, active, blocks, vars)
            } else {
                self.lower_expr(field_expr, active, blocks, vars)
            };
            active = lowered.current?;
            lowered_fields.push((field_name.clone(), lowered.operand.clone()));
            let field_ty = self.operand_type(&lowered.operand);
            let field_var = self.new_var(format!("{}_{}", create.ty, field_name), field_ty);
            self.block_mut(blocks, active).instructions.push(IrInstruction::Move { dest: field_var.clone(), src: lowered.operand });
            field_vars.insert(field_name.clone(), field_var);
        }
        let lock = if let Some(lock_expr) = &create.lock {
            let lowered = self.lower_expr(lock_expr, active, blocks, vars);
            active = lowered.current?;
            Some(lowered.operand)
        } else {
            None
        };
        active = self.lower_type_validity_checks(&create.ty, &field_vars, active, blocks, vars)?;
        Some((
            active,
            CreatePattern {
                operation: "bounded-create".to_string(),
                ty: create.ty.clone(),
                binding: format!("bounded_create_{}", create.ty),
                fields: lowered_fields,
                lock,
                identity: IrIdentityPolicy::None,
            },
        ))
    }

    fn lower_script_args_empty(&mut self, current: BlockId, blocks: &mut [IrBlock]) -> LoweredExpr {
        let aggregate = self.new_var("script_args", IrType::Named(CKB_SCRIPT_ARGS_TYPE.to_string()));
        let bytes = self.new_var("script_args_bytes", IrType::Array(Box::new(IrType::U8), 0));
        let len = self.new_var("script_args_len", IrType::U64);
        let is_empty = self.new_var("script_args_is_empty", IrType::Bool);
        let block = self.block_mut(blocks, current);
        block.instructions.push(IrInstruction::LoadConst { dest: bytes.clone(), value: IrConst::Array(Vec::new()) });
        block.instructions.push(IrInstruction::LoadConst { dest: len.clone(), value: IrConst::U64(0) });
        block.instructions.push(IrInstruction::LoadConst { dest: is_empty.clone(), value: IrConst::Bool(true) });
        block.instructions.push(IrInstruction::Tuple {
            dest: aggregate.clone(),
            fields: vec![IrOperand::Var(bytes.clone()), IrOperand::Var(len.clone()), IrOperand::Var(is_empty.clone())],
        });
        self.aggregate_fields.insert(
            aggregate.id,
            HashMap::from([("bytes".to_string(), bytes), ("len".to_string(), len), ("is_empty".to_string(), is_empty)]),
        );
        LoweredExpr { operand: IrOperand::Var(aggregate), current: Some(current) }
    }

    fn lower_hash_from_bytes(
        &mut self,
        raw: &Expr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
        span: Span,
    ) -> LoweredExpr {
        if let Expr::ByteString(bytes) = raw {
            if bytes.len() == 32 {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(bytes);
                return LoweredExpr { operand: IrOperand::Const(IrConst::Hash(hash)), current: Some(current) };
            }
            self.record_error("Hash::from_bytes expects exactly 32 bytes ([u8; 32])", span);
            return LoweredExpr { operand: IrOperand::Const(IrConst::Hash([0; 32])), current: Some(current) };
        }

        let lowered = self.lower_expr(raw, current, blocks, vars);
        let Some(active) = lowered.current else {
            return lowered;
        };
        let raw_ty = self.operand_type(&lowered.operand);
        if !matches!(raw_ty, IrType::Array(inner, 32) if matches!(inner.as_ref(), IrType::U8)) {
            self.record_error("Hash::from_bytes expects exactly 32 bytes ([u8; 32])", span);
            return LoweredExpr { operand: IrOperand::Const(IrConst::Hash([0; 32])), current: Some(active) };
        }

        let hash = self.new_var("hash_from_bytes", IrType::Hash);
        self.block_mut(blocks, active).instructions.push(IrInstruction::Move { dest: hash.clone(), src: lowered.operand.clone() });
        self.copy_aggregate_metadata(&lowered.operand, hash.id);
        LoweredExpr { operand: IrOperand::Var(hash), current: Some(active) }
    }

    fn lower_script_args(
        &mut self,
        raw: &Expr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let lowered = match raw {
            Expr::ByteString(bytes) => LoweredExpr {
                operand: IrOperand::Const(IrConst::Array(bytes.iter().copied().map(IrConst::U8).collect())),
                current: Some(current),
            },
            _ => self.lower_expr(raw, current, blocks, vars),
        };
        let Some(active) = lowered.current else {
            return lowered;
        };
        let raw_ty = self.operand_type(&lowered.operand);
        let len_value = fixed_byte_width_for_script_args_operand(&lowered.operand, &raw_ty).unwrap_or(0) as u64;

        let aggregate = self.new_var("script_args", IrType::Named(CKB_SCRIPT_ARGS_TYPE.to_string()));
        let bytes = self.new_var("script_args_bytes", raw_ty);
        let len = self.new_var("script_args_len", IrType::U64);
        let is_empty = self.new_var("script_args_is_empty", IrType::Bool);
        let block = self.block_mut(blocks, active);
        block.instructions.push(IrInstruction::Move { dest: bytes.clone(), src: lowered.operand.clone() });
        block.instructions.push(IrInstruction::LoadConst { dest: len.clone(), value: IrConst::U64(len_value) });
        block.instructions.push(IrInstruction::LoadConst { dest: is_empty.clone(), value: IrConst::Bool(len_value == 0) });
        block.instructions.push(IrInstruction::Tuple {
            dest: aggregate.clone(),
            fields: vec![IrOperand::Var(bytes.clone()), IrOperand::Var(len.clone()), IrOperand::Var(is_empty.clone())],
        });
        self.copy_aggregate_metadata(&lowered.operand, bytes.id);
        self.aggregate_fields.insert(
            aggregate.id,
            HashMap::from([("bytes".to_string(), bytes), ("len".to_string(), len), ("is_empty".to_string(), is_empty)]),
        );
        LoweredExpr { operand: IrOperand::Var(aggregate), current: Some(active) }
    }

    fn lower_script_value(
        &mut self,
        call: &CallExpr,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let mut active = current;
        let code_hash = self.lower_expr(&call.args[0], active, blocks, vars);
        active = match code_hash.current {
            Some(next) => next,
            None => return code_hash,
        };
        let hash_type = self.lower_expr(&call.args[1], active, blocks, vars);
        active = match hash_type.current {
            Some(next) => next,
            None => return hash_type,
        };
        let args = self.lower_expr(&call.args[2], active, blocks, vars);
        active = match args.current {
            Some(next) => next,
            None => return args,
        };

        let aggregate = self.new_var("script_value", IrType::Named(CKB_SCRIPT_VALUE_TYPE.to_string()));
        let code_hash_field = self.new_var("script_code_hash", IrType::Hash);
        let hash_type_field = self.new_var("script_hash_type", IrType::U64);
        let args_field = self.new_var("script_args", IrType::Named(CKB_SCRIPT_ARGS_TYPE.to_string()));
        let block = self.block_mut(blocks, active);
        block.instructions.push(IrInstruction::Move { dest: code_hash_field.clone(), src: code_hash.operand.clone() });
        block.instructions.push(IrInstruction::Move { dest: hash_type_field.clone(), src: hash_type.operand.clone() });
        block.instructions.push(IrInstruction::Move { dest: args_field.clone(), src: args.operand.clone() });
        block.instructions.push(IrInstruction::Tuple {
            dest: aggregate.clone(),
            fields: vec![
                IrOperand::Var(code_hash_field.clone()),
                IrOperand::Var(hash_type_field.clone()),
                IrOperand::Var(args_field.clone()),
            ],
        });
        self.copy_aggregate_metadata(&args.operand, args_field.id);
        self.aggregate_fields.insert(
            aggregate.id,
            HashMap::from([
                ("code_hash".to_string(), code_hash_field),
                ("hash_type".to_string(), hash_type_field),
                ("args".to_string(), args_field),
            ]),
        );
        LoweredExpr { operand: IrOperand::Var(aggregate), current: Some(active) }
    }

    fn lower_script_match_requirement(
        &mut self,
        call: &CallExpr,
        lock_script: bool,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> LoweredExpr {
        let source = self.lower_expr(&call.args[0], current, blocks, vars);
        let Some(active) = source.current else {
            return source;
        };
        let script = self.lower_expr(&call.args[1], active, blocks, vars);
        let Some(active) = script.current else {
            return script;
        };
        let Some(script_var) = (match &script.operand {
            IrOperand::Var(var) => Some(var.clone()),
            IrOperand::Const(_) => None,
        }) else {
            self.record_error("script::require_cell_*_matches requires a constructed Script value", call.span);
            return LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: Some(active) };
        };
        let Some(fields) = self.aggregate_fields.get(&script_var.id).cloned() else {
            self.record_error(
                "script::require_cell_*_matches requires a Script constructed by script::new in this verifier path",
                call.span,
            );
            return LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: Some(active) };
        };
        let Some(code_hash) = fields.get("code_hash").cloned() else {
            self.record_error("constructed Script is missing code_hash", call.span);
            return LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: Some(active) };
        };
        let Some(hash_type) = fields.get("hash_type").cloned() else {
            self.record_error("constructed Script is missing hash_type", call.span);
            return LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: Some(active) };
        };
        let Some(args) = fields.get("args").cloned() else {
            self.record_error("constructed Script is missing args", call.span);
            return LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: Some(active) };
        };
        let Some(args_fields) = self.aggregate_fields.get(&args.id).cloned() else {
            self.record_error("constructed Script args must come from script::args or script::args_empty", call.span);
            return LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: Some(active) };
        };
        let Some(args_bytes) = args_fields.get("bytes").cloned() else {
            self.record_error("constructed ScriptArgs is missing bytes", call.span);
            return LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: Some(active) };
        };
        let args_width = fixed_byte_width_for_script_args_var(&args_bytes).unwrap_or(usize::MAX);

        let identity_helper =
            if lock_script { "__ckb_require_cell_lock_script_hash_type" } else { "__ckb_require_cell_type_script_hash_type" };
        let block = self.block_mut(blocks, active);
        block.instructions.push(IrInstruction::Call {
            dest: None,
            func: identity_helper.to_string(),
            args: vec![source.operand.clone(), IrOperand::Var(code_hash), IrOperand::Var(hash_type)],
        });
        if args_width == 0 {
            block.instructions.push(IrInstruction::Call {
                dest: None,
                func: if lock_script {
                    "__ckb_require_cell_lock_args_empty".to_string()
                } else {
                    "__ckb_require_cell_type_args_empty".to_string()
                },
                args: vec![source.operand],
            });
        } else {
            block.instructions.push(IrInstruction::Call {
                dest: None,
                func: if lock_script {
                    "__ckb_require_cell_lock_args_exact".to_string()
                } else {
                    "__ckb_require_cell_type_args_exact".to_string()
                },
                args: vec![source.operand, IrOperand::Var(args_bytes)],
            });
        }
        LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: Some(active) }
    }

    fn lower_simple_runtime_call(
        &mut self,
        func: &str,
        dest_name: &str,
        return_ty: IrType,
        args: &[Expr],
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> Option<LoweredExpr> {
        let mut active = current;
        let mut lowered_args = Vec::with_capacity(args.len());
        for arg in args {
            let lowered = self.lower_expr(arg, active, blocks, vars);
            active = lowered.current?;
            lowered_args.push(lowered.operand);
        }
        let dest = self.new_var(dest_name, return_ty);
        self.block_mut(blocks, active).instructions.push(IrInstruction::Call {
            dest: Some(dest.clone()),
            func: func.to_string(),
            args: lowered_args,
        });
        Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) })
    }

    fn lower_transparent_view_wrapper(
        &mut self,
        call: &CallExpr,
        wrapper_type: &str,
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> Option<LoweredExpr> {
        let lowered = self.lower_expr(&call.args[0], current, blocks, vars);
        let active = lowered.current?;
        let dest = self.new_var("typed_transaction_view", IrType::Named(wrapper_type.to_string()));
        self.block_mut(blocks, active).instructions.push(IrInstruction::Move { dest: dest.clone(), src: lowered.operand });
        Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) })
    }

    fn lower_void_runtime_call(
        &mut self,
        func: &str,
        args: &[Expr],
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
    ) -> Option<LoweredExpr> {
        let mut active = current;
        let mut lowered_args = Vec::with_capacity(args.len());
        for arg in args {
            let lowered = self.lower_expr(arg, active, blocks, vars);
            active = lowered.current?;
            lowered_args.push(lowered.operand);
        }
        self.block_mut(blocks, active).instructions.push(IrInstruction::Call {
            dest: None,
            func: func.to_string(),
            args: lowered_args,
        });
        Some(LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: Some(active) })
    }

    fn lower_trusted_external_call(
        &mut self,
        operation: &str,
        runtime_helper: &str,
        args: &[Expr],
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
        span: Span,
    ) -> Option<LoweredExpr> {
        let mut active = current;
        let mut lowered = Vec::with_capacity(args.len());
        for arg in args {
            let value = self.lower_expr(arg, active, blocks, vars);
            active = value.current?;
            lowered.push(value.operand);
        }
        let code_hash = match lowered.get(1) {
            Some(IrOperand::Const(IrConst::Hash(hash))) => *hash,
            _ => {
                self.record_error("trusted external verifier code_hash must be a compile-time Hash literal", span);
                [0; 32]
            }
        };
        let source = self.new_var("trusted_external_cell_dep", IrType::Named("CellDepView".to_string()));
        self.block_mut(blocks, active).instructions.extend([
            IrInstruction::Call {
                dest: Some(source.clone()),
                func: "__ckb_source_cell_dep".to_string(),
                args: vec![lowered[0].clone()],
            },
            IrInstruction::Call {
                dest: None,
                func: "__ckb_require_cell_data_hash".to_string(),
                args: vec![IrOperand::Var(source), lowered[1].clone()],
            },
            IrInstruction::Call {
                dest: None,
                func: runtime_helper.to_string(),
                args: std::iter::once(lowered[0].clone()).chain(lowered[2..].iter().cloned()).collect(),
            },
        ]);
        let adapter = match runtime_helper {
            "__ckb_exec_cell_dep_u8_args" => "u8-args-v1",
            "__ckb_exec_cell_dep_hex4" | "__ckb_spawn_wait_cell_dep_hex4" => "hex4-v1",
            _ => unreachable!("trusted external calls use a closed runtime-helper set"),
        };
        self.trusted_external_calls.push(IrTrustedExternalCall {
            operation: operation.to_string(),
            adapter: adapter.to_string(),
            code_hash,
        });
        Some(LoweredExpr { operand: IrOperand::Const(IrConst::Unit), current: Some(active) })
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
        let (value, expected_ty) = self.constants.get(name)?.clone();
        match value {
            Expr::Integer(n) => Self::integer_const_for_expected_type(n, &expected_ty).map(IrOperand::Const).or_else(|| {
                self.record_error(
                    format!("constant '{}' integer literal does not fit declared IR type {:?}", name, expected_ty),
                    span,
                );
                None
            }),
            Expr::Bool(b) => Some(IrOperand::Const(IrConst::Bool(b))),
            Expr::ByteString(bytes) => {
                let items = bytes.into_iter().map(IrConst::U8).collect::<Vec<_>>();
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

    fn try_lower_enum_constructor_path(
        &mut self,
        path: &str,
        args: &[Expr],
        current: BlockId,
        blocks: &mut Vec<IrBlock>,
        vars: &mut HashMap<String, IrVar>,
        span: Span,
    ) -> Option<LoweredExpr> {
        let (enum_name, variant_name) = path.rsplit_once("::")?;
        let layout = self.module.enum_layouts.get(enum_name)?.clone();
        if !layout.has_payload() {
            return None;
        }
        let Some(variant) = layout.variants.iter().find(|variant| variant.name == variant_name).cloned() else {
            self.record_error(format!("unknown enum variant '{}::{}' during IR lowering", enum_name, variant_name), span);
            return Some(LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(current) });
        };
        if variant.fields.len() != args.len() {
            self.record_error(
                format!(
                    "enum constructor '{}::{}' expects {} payload value(s), got {}",
                    enum_name,
                    variant_name,
                    variant.fields.len(),
                    args.len()
                ),
                span,
            );
            return Some(LoweredExpr { operand: IrOperand::Const(IrConst::U64(0)), current: Some(current) });
        }

        let mut active = current;
        let mut fields = Vec::with_capacity(args.len());
        for (argument, field) in args.iter().zip(&variant.fields) {
            let lowered = self.lower_expr_with_expected_type(argument, &field.ty, active, blocks, vars);
            let Some(next) = lowered.current else {
                return Some(lowered);
            };
            active = next;
            fields.push(lowered.operand);
        }
        let dest = self.new_var(format!("{}_{}_payload", enum_name, variant_name), IrType::Named(enum_name.to_string()));
        self.block_mut(blocks, active).instructions.push(IrInstruction::EnumConstruct {
            dest: dest.clone(),
            enum_name: enum_name.to_string(),
            variant: variant_name.to_string(),
            fields,
        });
        Some(LoweredExpr { operand: IrOperand::Var(dest), current: Some(active) })
    }

    fn lower_flow_state_name(&self, name: &str) -> Option<IrOperand> {
        let (type_name, _) = name.rsplit_once("::")?;
        self.lower_flow_state_operand(type_name, name)
    }

    fn lower_flow_state_operand(&self, type_name: &str, name: &str) -> Option<IrOperand> {
        let index = self.flow_state_index(type_name, name)? as u64;
        let field_ty = self.flow_state_field_ir_type(type_name).unwrap_or(IrType::U64);
        let value = Self::integer_const_for_expected_type(index.into(), &field_ty).unwrap_or(IrConst::U64(index));
        Some(IrOperand::Const(value))
    }

    fn flow_state_field_ir_type(&self, type_name: &str) -> Option<IrType> {
        let field_name = self.flow_state_fields.get(type_name)?;
        self.type_fields.get(type_name)?.get(field_name).cloned()
    }

    fn flow_state_index(&self, type_name: &str, name: &str) -> Option<usize> {
        let states = self.flow_states.get(type_name)?;
        if let Some((qualified_type, state_name)) = name.rsplit_once("::") {
            if qualified_type != type_name {
                return None;
            }
            states.iter().position(|state| state == state_name)
        } else {
            states.iter().position(|state| state == name)
        }
    }

    fn lookup_field_ir_type(&self, ty: &IrType, field: &str) -> Option<IrType> {
        match ty {
            IrType::Tuple(items) => field.parse::<usize>().ok().and_then(|index| items.get(index)).cloned(),
            IrType::Named(name) if name == CKB_SCRIPT_VALUE_TYPE => match field {
                "code_hash" => Some(IrType::Hash),
                "hash_type" => Some(IrType::U64),
                "args" => Some(IrType::Named(CKB_SCRIPT_ARGS_TYPE.to_string())),
                _ => None,
            },
            IrType::Named(name) if name == CKB_SCRIPT_ARGS_TYPE => match field {
                "len" => Some(IrType::U64),
                "is_empty" => Some(IrType::Bool),
                _ => None,
            },
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
            "i32" => IrType::I32,
            "u64" => IrType::U64,
            "u128" => IrType::U128,
            "bool" => IrType::Bool,
            "Address" => IrType::Address,
            "Hash" => IrType::Hash,
            other => IrType::Named(other.to_string()),
        }
    }

    fn lower_call_target_name(&self, name: &str) -> String {
        if let Some(label) = self.call_target_labels.get(name) {
            return label.clone();
        }
        if let Some((module, symbol)) = name.rsplit_once("::")
            && module == self.module.name
        {
            return symbol.to_string();
        }
        name.to_string()
    }

    fn call_param_types(&self, source_name: &str, lowered_name: &str) -> Option<Vec<IrType>> {
        self.function_param_types
            .get(source_name)
            .or_else(|| self.function_param_types.get(lowered_name))
            .or_else(|| self.external_function_param_types.get(source_name))
            .or_else(|| self.external_function_param_types.get(lowered_name))
            .cloned()
    }

    fn call_return_type(&self, source_name: &str, lowered_name: &str) -> Option<Option<IrType>> {
        self.function_return_types
            .get(source_name)
            .or_else(|| self.function_return_types.get(lowered_name))
            .or_else(|| self.external_function_return_types.get(source_name))
            .or_else(|| self.external_function_return_types.get(lowered_name))
            .cloned()
    }

    /// A cached field read is reusable only when the context that defined it
    /// dominates the current lowering position: a strictly shallower branch
    /// depth always dominates, an equal depth dominates only within the same
    /// arm epoch. Entries without a recorded context keep the legacy reuse.
    fn aggregate_field_read_dominates(&self, field_var_id: usize) -> bool {
        match self.aggregate_field_contexts.get(&field_var_id) {
            None => true,
            Some((depth, epoch)) => *depth < self.branch_depth || (*depth == self.branch_depth && *epoch == self.branch_epoch),
        }
    }

    fn materialize_schema_field(&mut self, base_var: &IrVar, field: &str, current: BlockId, blocks: &mut [IrBlock]) -> Option<IrVar> {
        let field_ty = self.lookup_field_ir_type(&base_var.ty, field)?;
        let field_var = self.new_var(format!("{}_{}", base_var.name, field), field_ty);
        self.block_mut(blocks, current).instructions.push(IrInstruction::FieldAccess {
            dest: field_var.clone(),
            obj: IrOperand::Var(base_var.clone()),
            field: field.to_string(),
        });
        self.aggregate_fields.entry(base_var.id).or_default().insert(field.to_string(), field_var.clone());
        self.schema_field_roots.insert(field_var.id, (base_var.id, field.to_string()));
        self.aggregate_field_contexts.insert(field_var.id, (self.branch_depth, self.branch_epoch));
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
        if let Some(context) = self.aggregate_field_contexts.get(&source_var.id).copied() {
            self.aggregate_field_contexts.insert(dest_id, context);
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
        IrType::I32 => Some("i32".to_string()),
        IrType::U64 => Some("u64".to_string()),
        IrType::U128 => Some("u128".to_string()),
        IrType::Bool => Some("bool".to_string()),
        IrType::Address => Some("Address".to_string()),
        IrType::Hash => Some("Hash".to_string()),
        IrType::Named(name) => Some(name.clone()),
        IrType::Unit | IrType::Array(_, _) | IrType::Tuple(_) | IrType::Ref(_) | IrType::MutRef(_) => None,
    }
}

fn ir_type_display(ty: &IrType) -> String {
    match ty {
        IrType::U8 => "u8".to_string(),
        IrType::U16 => "u16".to_string(),
        IrType::U32 => "u32".to_string(),
        IrType::I32 => "i32".to_string(),
        IrType::U64 => "u64".to_string(),
        IrType::U128 => "u128".to_string(),
        IrType::Bool => "bool".to_string(),
        IrType::Unit => "()".to_string(),
        IrType::Address => "Address".to_string(),
        IrType::Hash => "Hash".to_string(),
        IrType::Array(inner, len) => format!("[{}; {}]", ir_type_display(inner), len),
        IrType::Tuple(items) => format!("({})", items.iter().map(ir_type_display).collect::<Vec<_>>().join(", ")),
        IrType::Named(name) => name.clone(),
        IrType::Ref(inner) => format!("&{}", ir_type_display(inner)),
        IrType::MutRef(inner) => format!("&mut {}", ir_type_display(inner)),
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
        "i32" => IrType::I32,
        "u64" => IrType::U64,
        "u128" => IrType::U128,
        "bool" => IrType::Bool,
        "Address" => IrType::Address,
        "Hash" => IrType::Hash,
        other => IrType::Named(other.to_string()),
    }
}

const CKB_LOCK_SCRIPT_REF_TYPE: &str = "__ckb_lock_script_ref";
const CKB_TYPE_SCRIPT_REF_TYPE: &str = "__ckb_type_script_ref";
const CKB_INPUT_OUT_POINT_REF_TYPE: &str = "__ckb_input_out_point_ref";
const CKB_SCRIPT_ARGS_TYPE: &str = "ScriptArgs";
const CKB_SCRIPT_VALUE_TYPE: &str = "Script";

fn typed_view_property_runtime_helper(ty: &IrType, field: &str) -> Option<(&'static str, &'static str, IrType)> {
    let IrType::Named(name) = ty else {
        return None;
    };
    let base_name = name.split('<').next().unwrap_or(name.as_str());
    match (base_name, field) {
        ("InputView" | "OutputView" | "CellDepView", "capacity") => Some(("__ckb_cell_capacity", "typed_view_capacity", IrType::U64)),
        ("InputView" | "OutputView" | "CellDepView", "occupied_capacity") => {
            Some(("__ckb_cell_occupied_capacity", "typed_view_occupied_capacity", IrType::U64))
        }
        ("InputView" | "OutputView" | "CellDepView", "unoccupied_capacity") => {
            Some(("__ckb_cell_unoccupied_capacity", "typed_view_unoccupied_capacity", IrType::U64))
        }
        ("InputView" | "OutputView" | "CellDepView", "data_size") => {
            Some(("__ckb_cell_data_size", "typed_view_data_size", IrType::U64))
        }
        ("InputView" | "OutputView" | "CellDepView", "data_hash") => {
            Some(("__ckb_cell_data_hash_field", "typed_view_data_hash", IrType::Hash))
        }
        ("OutputView", "output_index") => Some(("__ckb_cell_output_index", "typed_view_output_index", IrType::U64)),
        ("InputView", "since") => Some(("__ckb_input_since_at", "typed_view_since", IrType::Named("EncodedSince".to_string()))),
        ("InputView" | "OutputView" | "CellDepView", "lock_hash") => {
            Some(("__ckb_cell_lock_hash", "typed_view_lock_hash", IrType::Hash))
        }
        ("InputView" | "OutputView" | "CellDepView", "type_hash") => {
            Some(("__ckb_cell_type_hash", "typed_view_type_hash", IrType::Hash))
        }
        ("WitnessArgsView", "size") => Some(("__ckb_witness_size", "typed_witness_size", IrType::U64)),
        ("WitnessArgsView", "lock") => Some(("__ckb_witness_lock", "typed_witness_lock", IrType::Hash)),
        ("WitnessArgsView", "input_type") => Some(("__ckb_witness_input_type", "typed_witness_input_type", IrType::Hash)),
        ("WitnessArgsView", "output_type") => Some(("__ckb_witness_output_type", "typed_witness_output_type", IrType::Hash)),
        ("HeaderDepView", "epoch_number") => {
            Some(("__ckb_header_dep_epoch_number", "typed_header_epoch_number", IrType::Named("EpochNumber".to_string())))
        }
        ("HeaderDepView", "epoch_start_block_number") => Some((
            "__ckb_header_dep_epoch_start_block_number",
            "typed_header_epoch_start_block_number",
            IrType::Named("BlockNumber".to_string()),
        )),
        ("HeaderDepView", "epoch_length") => {
            Some(("__ckb_header_dep_epoch_length", "typed_header_epoch_length", IrType::Named("EpochLength".to_string())))
        }
        (CKB_INPUT_OUT_POINT_REF_TYPE, "index") => Some(("__ckb_input_out_point_index", "typed_out_point_index", IrType::U64)),
        (CKB_INPUT_OUT_POINT_REF_TYPE, "tx_hash") => Some(("__ckb_input_out_point_tx_hash", "typed_out_point_tx_hash", IrType::Hash)),
        _ => None,
    }
}

fn typed_view_property_wrapper(ty: &IrType, field: &str) -> Option<&'static str> {
    let IrType::Named(name) = ty else {
        return None;
    };
    let base_name = name.split('<').next().unwrap_or(name.as_str());
    match (base_name, field) {
        ("InputView", "out_point") => Some(CKB_INPUT_OUT_POINT_REF_TYPE),
        ("InputView" | "OutputView" | "CellDepView", "lock") => Some(CKB_LOCK_SCRIPT_REF_TYPE),
        ("InputView" | "OutputView" | "CellDepView", "type" | "type_script") => Some(CKB_TYPE_SCRIPT_REF_TYPE),
        _ => None,
    }
}

fn script_ref_property_runtime_helper(ty: &IrType, field: &str) -> Option<(&'static str, &'static str, IrType)> {
    let IrType::Named(name) = ty else {
        return None;
    };
    let lock_script = name == CKB_LOCK_SCRIPT_REF_TYPE;
    let type_script = name == CKB_TYPE_SCRIPT_REF_TYPE;
    if !lock_script && !type_script {
        return None;
    }
    match field {
        "hash" => Some((
            if lock_script { "__ckb_cell_lock_hash" } else { "__ckb_cell_type_hash" },
            if lock_script { "ckb_cell_lock_hash" } else { "ckb_cell_type_hash" },
            IrType::Hash,
        )),
        "code_hash" => Some((
            if lock_script { "__ckb_cell_lock_code_hash" } else { "__ckb_cell_type_code_hash" },
            if lock_script { "ckb_cell_lock_code_hash" } else { "ckb_cell_type_code_hash" },
            IrType::Hash,
        )),
        "hash_type" => Some((
            if lock_script { "__ckb_cell_lock_hash_type" } else { "__ckb_cell_type_hash_type" },
            if lock_script { "ckb_cell_lock_hash_type" } else { "ckb_cell_type_hash_type" },
            IrType::U64,
        )),
        "args_empty" => Some((
            if lock_script { "__ckb_cell_lock_args_empty" } else { "__ckb_cell_type_args_empty" },
            if lock_script { "ckb_cell_lock_args_empty" } else { "ckb_cell_type_args_empty" },
            IrType::Bool,
        )),
        "args_hash" => Some((
            if lock_script { "__ckb_cell_lock_args_hash" } else { "__ckb_cell_type_args_hash" },
            if lock_script { "ckb_cell_lock_args_hash" } else { "ckb_cell_type_args_hash" },
            IrType::Hash,
        )),
        _ => None,
    }
}

fn fixed_byte_width_for_script_args_var(var: &IrVar) -> Option<usize> {
    match &var.ty {
        IrType::Hash | IrType::Address => Some(32),
        IrType::Array(inner, len) if matches!(inner.as_ref(), IrType::U8) => Some(*len),
        _ => None,
    }
}

fn fixed_byte_width_for_script_args_operand(operand: &IrOperand, ty: &IrType) -> Option<usize> {
    match operand {
        IrOperand::Const(IrConst::Hash(_)) | IrOperand::Const(IrConst::Address(_)) => Some(32),
        IrOperand::Const(IrConst::Array(items)) => Some(items.len()),
        IrOperand::Var(var) => fixed_byte_width_for_script_args_var(var),
        _ => match ty {
            IrType::Hash | IrType::Address => Some(32),
            IrType::Array(inner, len) if matches!(inner.as_ref(), IrType::U8) => Some(*len),
            _ => None,
        },
    }
}

fn checked_cast_maximum(source: &IrType, target: &IrType) -> Option<IrConst> {
    let source_bits = unsigned_ir_bits(source)?;
    let target_bits = unsigned_ir_bits(target)?;
    if target_bits >= source_bits || source_bits > 64 {
        return None;
    }
    let maximum = if target_bits == 64 { u64::MAX } else { (1u64 << target_bits) - 1 };
    match source {
        IrType::U8 => u8::try_from(maximum).ok().map(IrConst::U8),
        IrType::U16 => u16::try_from(maximum).ok().map(IrConst::U16),
        IrType::U32 => u32::try_from(maximum).ok().map(IrConst::U32),
        IrType::U64 | IrType::Named(_) => Some(IrConst::U64(maximum)),
        _ => None,
    }
}

fn unsigned_ir_bits(ty: &IrType) -> Option<u32> {
    match ty {
        IrType::U8 => Some(8),
        IrType::U16 => Some(16),
        IrType::U32 => Some(32),
        IrType::U64 => Some(64),
        IrType::U128 => Some(128),
        IrType::Named(name) if name == "usize" => Some(64),
        _ => None,
    }
}

fn ir_validity_predicates(validity: Option<&ValidityBlock>, fields: &[Field]) -> Vec<IrValidityPredicate> {
    let Some(validity) = validity else {
        return Vec::new();
    };
    let field_names = fields.iter().map(|field| field.name.as_str()).collect::<HashSet<_>>();
    validity
        .predicates
        .iter()
        .filter_map(|predicate| {
            let Expr::Require(require) = predicate else {
                return None;
            };
            let mut dependencies = BTreeSet::new();
            collect_validity_dependencies(&require.condition, &field_names, &mut dependencies);
            let evidence = if validity_expr_uses_block_number(&require.condition) {
                IrValidityEvidence::BuilderEvidenceRequired
            } else if matches!(require.condition.as_ref(), Expr::Bool(true)) {
                IrValidityEvidence::CheckedStatic
            } else {
                IrValidityEvidence::CheckedRuntime
            };
            Some(IrValidityPredicate {
                expression: (*require.condition).clone(),
                message: require.message.as_deref().cloned(),
                rendered: crate::fmt::format_expression(&require.condition),
                evidence,
                dependencies: dependencies.into_iter().collect(),
                runtime_checked_on_create: evidence == IrValidityEvidence::CheckedRuntime,
                span: require.span,
            })
        })
        .collect()
}

fn ir_validity_predicates_with_constants(
    validity: Option<&ValidityBlock>,
    fields: &[Field],
    constant_names: &HashSet<&str>,
) -> Vec<IrValidityPredicate> {
    let mut predicates = ir_validity_predicates(validity, fields);
    for predicate in &mut predicates {
        let mut dependencies = predicate.dependencies.iter().cloned().collect::<BTreeSet<_>>();
        collect_validity_constant_dependencies(&predicate.expression, constant_names, &mut dependencies);
        predicate.dependencies = dependencies.into_iter().collect();
    }
    predicates
}

fn replace_relation_inner_exprs(relation: &ReplaceRelation) -> Vec<&Expr> {
    let mut inner = Vec::new();
    if let ReplaceLockTreatment::Exact(lock) | ReplaceLockTreatment::ExactHash(lock) = &relation.lock {
        inner.push(lock.as_ref());
    }
    match &relation.data {
        ReplaceDataTreatment::Fields(treatments) => {
            for treatment in treatments {
                if let ReplaceFieldTreatment::Assign(_, value) = treatment {
                    inner.push(value);
                }
            }
        }
        ReplaceDataTreatment::SameExcept(assigned) => {
            for (_, value) in assigned {
                inner.push(value);
            }
        }
    }
    inner
}

fn collect_validity_constant_dependencies(expr: &Expr, constants: &HashSet<&str>, dependencies: &mut BTreeSet<String>) {
    match expr {
        // Relations are lifecycle syntax and are rejected in validity
        // predicates before lowering; recurse defensively into their values.
        Expr::ReplaceRelation(relation) => {
            for value in replace_relation_inner_exprs(relation) {
                collect_validity_constant_dependencies(value, constants, dependencies);
            }
        }
        Expr::Identifier(name) => {
            if constants.contains(name.as_str()) {
                dependencies.insert(format!("constant:{name}"));
            }
        }
        Expr::Call(call) => {
            for arg in &call.args {
                collect_validity_constant_dependencies(arg, constants, dependencies);
            }
        }
        Expr::Binary(binary) => {
            collect_validity_constant_dependencies(&binary.left, constants, dependencies);
            collect_validity_constant_dependencies(&binary.right, constants, dependencies);
        }
        Expr::Unary(unary) => collect_validity_constant_dependencies(&unary.expr, constants, dependencies),
        Expr::FieldAccess(field) => collect_validity_constant_dependencies(&field.expr, constants, dependencies),
        Expr::Index(index) => {
            collect_validity_constant_dependencies(&index.expr, constants, dependencies);
            collect_validity_constant_dependencies(&index.index, constants, dependencies);
        }
        Expr::Tuple(items) | Expr::Array(items) => {
            for item in items {
                collect_validity_constant_dependencies(item, constants, dependencies);
            }
        }
        Expr::Cast(cast) => collect_validity_constant_dependencies(&cast.expr, constants, dependencies),
        Expr::Range(range) => {
            collect_validity_constant_dependencies(&range.start, constants, dependencies);
            collect_validity_constant_dependencies(&range.end, constants, dependencies);
        }
        Expr::StructInit(init) => {
            for (_, value) in &init.fields {
                collect_validity_constant_dependencies(value, constants, dependencies);
            }
        }
        Expr::Integer(_)
        | Expr::Bool(_)
        | Expr::String(_)
        | Expr::ByteString(_)
        | Expr::Assign(_)
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
        | Expr::RequireBlock(_)
        | Expr::Preserve(_)
        | Expr::Block(_)
        | Expr::If(_)
        | Expr::Match(_)
        | Expr::StdlibCall(_) => {}
    }
}

fn validity_expr_uses_block_number(expr: &Expr) -> bool {
    match expr {
        Expr::ReplaceRelation(relation) => {
            replace_relation_inner_exprs(relation).iter().any(|value| validity_expr_uses_block_number(value))
        }
        Expr::Call(call) => {
            matches!(call.func.as_ref(), Expr::Identifier(name) if name == "env::block_number")
                || validity_expr_uses_block_number(&call.func)
                || call.args.iter().any(validity_expr_uses_block_number)
        }
        Expr::Binary(binary) => validity_expr_uses_block_number(&binary.left) || validity_expr_uses_block_number(&binary.right),
        Expr::Unary(unary) => validity_expr_uses_block_number(&unary.expr),
        Expr::FieldAccess(field) => validity_expr_uses_block_number(&field.expr),
        Expr::Index(index) => validity_expr_uses_block_number(&index.expr) || validity_expr_uses_block_number(&index.index),
        Expr::Tuple(items) | Expr::Array(items) => items.iter().any(validity_expr_uses_block_number),
        Expr::Cast(cast) => validity_expr_uses_block_number(&cast.expr),
        Expr::Range(range) => validity_expr_uses_block_number(&range.start) || validity_expr_uses_block_number(&range.end),
        Expr::StructInit(init) => init.fields.iter().any(|(_, value)| validity_expr_uses_block_number(value)),
        Expr::Integer(_)
        | Expr::Bool(_)
        | Expr::String(_)
        | Expr::ByteString(_)
        | Expr::Identifier(_)
        | Expr::Assign(_)
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
        | Expr::RequireBlock(_)
        | Expr::Preserve(_)
        | Expr::Block(_)
        | Expr::If(_)
        | Expr::Match(_)
        | Expr::StdlibCall(_) => false,
    }
}

fn collect_validity_dependencies(expr: &Expr, fields: &HashSet<&str>, dependencies: &mut BTreeSet<String>) {
    match expr {
        Expr::ReplaceRelation(relation) => {
            for value in replace_relation_inner_exprs(relation) {
                collect_validity_dependencies(value, fields, dependencies);
            }
        }
        Expr::Identifier(name) => {
            if fields.contains(name.as_str()) {
                dependencies.insert(format!("field:{name}"));
            }
        }
        Expr::Call(call) => {
            if let Expr::Identifier(name) = call.func.as_ref() {
                if name == "env::block_number" {
                    dependencies.insert("environment:env::block_number".to_string());
                    dependencies.insert("builder:header-dep-block-number-evidence".to_string());
                } else if !matches!(name.as_str(), "Address::zero" | "Hash::zero") {
                    dependencies.insert(format!("helper:{name}"));
                }
            }
            for arg in &call.args {
                collect_validity_dependencies(arg, fields, dependencies);
            }
        }
        Expr::Binary(binary) => {
            collect_validity_dependencies(&binary.left, fields, dependencies);
            collect_validity_dependencies(&binary.right, fields, dependencies);
        }
        Expr::Unary(unary) => collect_validity_dependencies(&unary.expr, fields, dependencies),
        Expr::FieldAccess(field) => collect_validity_dependencies(&field.expr, fields, dependencies),
        Expr::Index(index) => {
            collect_validity_dependencies(&index.expr, fields, dependencies);
            collect_validity_dependencies(&index.index, fields, dependencies);
        }
        Expr::Tuple(items) | Expr::Array(items) => {
            for item in items {
                collect_validity_dependencies(item, fields, dependencies);
            }
        }
        Expr::Cast(cast) => collect_validity_dependencies(&cast.expr, fields, dependencies),
        Expr::Range(range) => {
            collect_validity_dependencies(&range.start, fields, dependencies);
            collect_validity_dependencies(&range.end, fields, dependencies);
        }
        Expr::StructInit(init) => {
            for (_, value) in &init.fields {
                collect_validity_dependencies(value, fields, dependencies);
            }
        }
        Expr::Integer(_)
        | Expr::Bool(_)
        | Expr::String(_)
        | Expr::ByteString(_)
        | Expr::Assign(_)
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
        | Expr::RequireBlock(_)
        | Expr::Preserve(_)
        | Expr::Block(_)
        | Expr::If(_)
        | Expr::Match(_)
        | Expr::StdlibCall(_) => {}
    }
}

fn qualify_external_validity_predicates(type_def: &mut IrTypeDef, owner_module: &str, resolver: &ModuleResolver) {
    let field_names = type_def.fields.iter().map(|field| field.name.clone()).collect::<Vec<_>>();
    let fields = field_names.iter().map(String::as_str).collect::<HashSet<_>>();
    for predicate in &mut type_def.validity_predicates {
        let mut external_constant_dependencies = BTreeSet::new();
        qualify_validity_dependencies(&mut predicate.expression, owner_module, resolver, &fields, &mut external_constant_dependencies);
        let mut dependencies = BTreeSet::new();
        collect_validity_dependencies(&predicate.expression, &fields, &mut dependencies);
        dependencies.extend(external_constant_dependencies);
        predicate.dependencies = dependencies.into_iter().collect();
    }
}

fn qualify_validity_dependencies(
    expr: &mut Expr,
    owner_module: &str,
    resolver: &ModuleResolver,
    fields: &HashSet<&str>,
    constant_dependencies: &mut BTreeSet<String>,
) {
    match expr {
        Expr::ReplaceRelation(relation) => {
            if let ReplaceLockTreatment::Exact(lock) | ReplaceLockTreatment::ExactHash(lock) = &mut relation.lock {
                qualify_validity_dependencies(lock, owner_module, resolver, fields, constant_dependencies);
            }
            if let ReplaceDataTreatment::Fields(treatments) = &mut relation.data {
                for treatment in treatments {
                    if let ReplaceFieldTreatment::Assign(_, value) = treatment {
                        qualify_validity_dependencies(value, owner_module, resolver, fields, constant_dependencies);
                    }
                }
            }
        }
        Expr::Call(call) => {
            if let Expr::Identifier(name) = call.func.as_mut()
                && let Some((callee_module, function)) = resolver.resolve_function_with_module(owner_module, name)
            {
                *name = format!("{}::{}", callee_module, function_def_name(&function));
            }
            qualify_validity_dependencies(&mut call.func, owner_module, resolver, fields, constant_dependencies);
            for arg in &mut call.args {
                qualify_validity_dependencies(arg, owner_module, resolver, fields, constant_dependencies);
            }
        }
        Expr::Binary(binary) => {
            qualify_validity_dependencies(&mut binary.left, owner_module, resolver, fields, constant_dependencies);
            qualify_validity_dependencies(&mut binary.right, owner_module, resolver, fields, constant_dependencies);
        }
        Expr::Unary(unary) => qualify_validity_dependencies(&mut unary.expr, owner_module, resolver, fields, constant_dependencies),
        Expr::FieldAccess(field) => {
            qualify_validity_dependencies(&mut field.expr, owner_module, resolver, fields, constant_dependencies)
        }
        Expr::Index(index) => {
            qualify_validity_dependencies(&mut index.expr, owner_module, resolver, fields, constant_dependencies);
            qualify_validity_dependencies(&mut index.index, owner_module, resolver, fields, constant_dependencies);
        }
        Expr::Tuple(items) | Expr::Array(items) => {
            for item in items {
                qualify_validity_dependencies(item, owner_module, resolver, fields, constant_dependencies);
            }
        }
        Expr::Cast(cast) => qualify_validity_dependencies(&mut cast.expr, owner_module, resolver, fields, constant_dependencies),
        Expr::Range(range) => {
            qualify_validity_dependencies(&mut range.start, owner_module, resolver, fields, constant_dependencies);
            qualify_validity_dependencies(&mut range.end, owner_module, resolver, fields, constant_dependencies);
        }
        Expr::StructInit(init) => {
            for (_, value) in &mut init.fields {
                qualify_validity_dependencies(value, owner_module, resolver, fields, constant_dependencies);
            }
        }
        Expr::Identifier(name) if !fields.contains(name.as_str()) => {
            let source_name = name.clone();
            if let Some((constant_module, constant)) = resolver.resolve_constant_with_module(owner_module, &source_name) {
                constant_dependencies.insert(format!("constant:{constant_module}::{}", constant.name));
                *expr = constant.value;
                qualify_validity_dependencies(expr, owner_module, resolver, fields, constant_dependencies);
            }
        }
        Expr::Integer(_)
        | Expr::Bool(_)
        | Expr::String(_)
        | Expr::ByteString(_)
        | Expr::Identifier(_)
        | Expr::Assign(_)
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
        | Expr::RequireBlock(_)
        | Expr::Preserve(_)
        | Expr::Block(_)
        | Expr::If(_)
        | Expr::Match(_)
        | Expr::StdlibCall(_) => {}
    }
}

pub fn generate(ast: &Module) -> Result<IrModule> {
    let generator = IrGenerator::new(ast.name.clone());
    generator.generate(ast)
}

pub fn generate_diagnostics(ast: &Module) -> std::result::Result<IrModule, Vec<CompileError>> {
    let generator = IrGenerator::new(ast.name.clone());
    generator.generate_diagnostics(ast)
}

pub fn generate_with_resolver(ast: &Module, resolver: &ModuleResolver, module_name: &str) -> Result<IrModule> {
    generate_with_resolver_diagnostics(ast, resolver, module_name).map_err(collapse_ir_errors)
}

pub fn generate_with_resolver_diagnostics(
    ast: &Module,
    resolver: &ModuleResolver,
    module_name: &str,
) -> std::result::Result<IrModule, Vec<CompileError>> {
    generate_with_resolver_diagnostics_inner(ast, resolver, module_name, true)
}

fn collapse_ir_errors(errors: Vec<CompileError>) -> CompileError {
    errors.into_iter().next().unwrap_or_else(|| CompileError::without_span("IR lowering failed"))
}

fn generate_with_resolver_inner(
    ast: &Module,
    resolver: &ModuleResolver,
    module_name: &str,
    include_external_callables: bool,
) -> Result<IrModule> {
    generate_with_resolver_diagnostics_inner(ast, resolver, module_name, include_external_callables).map_err(collapse_ir_errors)
}

#[derive(Default)]
struct ExternalCallableContext {
    function_effects: HashMap<String, EffectClass>,
    function_param_types: HashMap<String, Vec<IrType>>,
    function_return_types: HashMap<String, Option<IrType>>,
    target_labels: HashMap<String, String>,
    abis: Vec<IrCallableAbi>,
    names: HashSet<String>,
}

fn generate_with_resolver_diagnostics_inner(
    ast: &Module,
    resolver: &ModuleResolver,
    module_name: &str,
    include_external_callables: bool,
) -> std::result::Result<IrModule, Vec<CompileError>> {
    let mut type_fields = HashMap::new();
    let mut type_kinds = HashMap::new();
    let mut receipt_claim_outputs = HashMap::new();
    let mut flow_states = HashMap::new();
    let mut external_type_defs = Vec::new();
    let mut external_type_names = HashSet::new();
    let mut external_enum_definitions = HashMap::new();
    let mut external_callables = ExternalCallableContext::default();

    let mut resolved_external_types: Vec<(String, String, TypeDef)> = Vec::new();

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
                if let Some(states) = resolver_flow_states_to_ir(&type_def) {
                    flow_states.insert(local_name.clone(), states);
                }
                if let Some(fields) = resolver_type_fields_to_ir(&type_def) {
                    type_fields.insert(local_name.clone(), fields);
                }
                if external_type_names.insert(local_name.clone()) {
                    resolved_external_types.push((local_name.clone(), use_stmt.module_path.join("::"), type_def));
                }
            }
            if let Some((owner_module, function)) = resolver.resolve_function_with_module(module_name, &local_name) {
                register_external_callable_context(
                    module_name,
                    &owner_module,
                    &local_name,
                    &function,
                    resolver,
                    Some(&local_name),
                    &mut external_callables,
                );
            }
        }
    }

    for (local_name, owner_module, type_def) in resolved_external_types {
        if let TypeDef::Enum(mut enum_def) = type_def.clone() {
            enum_def.name = local_name.clone();
            external_enum_definitions.insert(local_name.clone(), enum_def);
        }
        if let Some(mut ir_type_def) = resolver_type_def_to_ir(&local_name, &type_def, &type_fields) {
            qualify_external_validity_predicates(&mut ir_type_def, &owner_module, resolver);
            external_type_defs.push(ir_type_def);
        }
    }
    let imported_type_validity = external_type_defs
        .iter()
        .map(|type_def| (type_def.name.clone(), type_def.validity_predicates.clone()))
        .collect::<HashMap<_, _>>();

    let mut call_names = collect_call_names(ast);
    for predicates in imported_type_validity.values() {
        for predicate in predicates {
            collect_call_names_from_expr(&predicate.expression, &mut call_names);
        }
    }
    for call_name in call_names {
        if let Some((owner_module, function)) = resolver.resolve_function_with_module(module_name, &call_name) {
            register_external_callable_context(
                module_name,
                &owner_module,
                &call_name,
                &function,
                resolver,
                None,
                &mut external_callables,
            );
        }
    }

    let ExternalCallableContext {
        function_effects: external_function_effects,
        function_param_types: external_function_param_types,
        function_return_types: external_function_return_types,
        target_labels: call_target_labels,
        abis: external_callable_abis,
        names: _,
    } = external_callables;
    let generator = IrGenerator::with_import_context(
        ast.name.clone(),
        IrImportContext {
            type_fields,
            type_kinds,
            receipt_claim_outputs,
            flow_states,
            type_validity: imported_type_validity,
            enum_definitions: external_enum_definitions,
            external_function_effects,
            external_function_param_types,
            external_function_return_types,
            call_target_labels,
        },
    );
    let mut ir = generator.generate_diagnostics(ast)?;
    ir.external_type_defs = external_type_defs;
    ir.external_callable_abis = external_callable_abis;
    if include_external_callables {
        append_external_callable_bodies(&mut ir, ast, resolver, module_name).map_err(|error| vec![error])?;
    }
    Ok(ir)
}

fn append_external_callable_bodies(ir: &mut IrModule, ast: &Module, resolver: &ModuleResolver, module_name: &str) -> Result<()> {
    let mut known_callables = ir_callable_names(ir);
    let mut imported_callables = HashSet::new();
    let entry_call_labels = imported_callable_label_overrides(ast, resolver, module_name);
    let mut pending = collect_call_names(ast)
        .into_iter()
        .map(|call_name| PendingExternalCall { lookup_module: module_name.to_string(), call_name })
        .collect::<Vec<_>>();
    let mut validity_calls = HashSet::new();
    for type_def in &ir.external_type_defs {
        for predicate in &type_def.validity_predicates {
            collect_call_names_from_expr(&predicate.expression, &mut validity_calls);
        }
    }
    pending
        .extend(validity_calls.into_iter().map(|call_name| PendingExternalCall { lookup_module: module_name.to_string(), call_name }));

    while let Some(pending_call) = pending.pop() {
        let Some((owner_module, function)) =
            resolver.resolve_function_with_module(&pending_call.lookup_module, &pending_call.call_name)
        else {
            continue;
        };
        let symbol = function_def_name(&function).to_string();
        let label = if pending_call.lookup_module == module_name {
            entry_call_labels
                .get(&pending_call.call_name)
                .cloned()
                .unwrap_or_else(|| callable_label_for(module_name, &owner_module, &symbol))
        } else {
            callable_label_for(module_name, &owner_module, &symbol)
        };
        if known_callables.contains(&label) {
            continue;
        }

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
        for (name, layout) in external_ir.enum_layouts {
            ir.enum_layouts.entry(name).or_insert(layout);
        }

        if let Some(mut item) =
            external_ir.items.into_iter().find(|item| ir_item_callable_name(item).is_some_and(|name| name == symbol))
        {
            rewrite_external_callable_item_calls(&mut item, &owner_module, module_name, resolver, &mut pending);
            rename_ir_item_callable(&mut item, label.clone());
            if known_callables.insert(label) {
                ir.items.push(item);
            }
        }
    }

    Ok(())
}

fn imported_callable_label_overrides(ast: &Module, resolver: &ModuleResolver, module_name: &str) -> HashMap<String, String> {
    let mut labels = HashMap::new();
    for item in &ast.items {
        let Item::Use(use_stmt) = item else {
            continue;
        };
        for import in &use_stmt.imports {
            let local_name = import.alias.clone().unwrap_or_else(|| import.name.clone());
            let Some((owner_module, function)) = resolver.resolve_function_with_module(module_name, &local_name) else {
                continue;
            };
            let symbol = function_def_name(&function);
            let full_path = format!("{}::{}", owner_module, symbol);
            let label = labels.get(&full_path).cloned().unwrap_or_else(|| {
                if owner_module == module_name {
                    symbol.to_string()
                } else {
                    local_name.clone()
                }
            });
            labels.insert(local_name, label.clone());
            labels.entry(full_path).or_insert(label);
        }
    }
    labels
}

fn register_external_callable_context(
    consumer_module: &str,
    owner_module: &str,
    source_name: &str,
    function: &FunctionDef,
    resolver: &ModuleResolver,
    preferred_label: Option<&str>,
    context: &mut ExternalCallableContext,
) {
    let symbol = function_def_name(function);
    let full_path = format!("{}::{}", owner_module, symbol);
    let label = context
        .target_labels
        .get(&full_path)
        .or_else(|| context.target_labels.get(source_name))
        .cloned()
        .or_else(|| preferred_label.map(str::to_string))
        .unwrap_or_else(|| callable_label_for(consumer_module, owner_module, symbol));
    let effect = function_def_transitive_effect_class(resolver, owner_module, function, &mut HashSet::new());
    let params = function_def_param_types_ir(function);
    let return_type = function_def_return_type(function);

    for key in [source_name.to_string(), full_path.clone(), label.clone()] {
        context.function_effects.insert(key.clone(), effect);
        context.function_param_types.insert(key.clone(), params.clone());
        context.function_return_types.insert(key, return_type.clone());
    }
    context.target_labels.insert(source_name.to_string(), label.clone());
    context.target_labels.entry(full_path).or_insert_with(|| label.clone());
    if owner_module != consumer_module {
        push_external_callable_abi(&mut context.abis, &mut context.names, label, function);
    }
}

fn callable_label_for(consumer_module: &str, owner_module: &str, symbol: &str) -> String {
    if owner_module == consumer_module {
        symbol.to_string()
    } else {
        format!("__cellscript_ext_{}__{}", sanitize_callable_label_part(owner_module), sanitize_callable_label_part(symbol))
    }
}

fn sanitize_callable_label_part(value: &str) -> String {
    value.chars().map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' }).collect::<String>()
}

fn function_def_name(function: &FunctionDef) -> &str {
    match function {
        FunctionDef::Action(action) => &action.name,
        FunctionDef::Function(function) => &function.name,
        FunctionDef::Lock(lock) => &lock.name,
    }
}

#[derive(Debug, Clone)]
struct PendingExternalCall {
    lookup_module: String,
    call_name: String,
}

fn ir_callable_names(ir: &IrModule) -> HashSet<String> {
    ir.items.iter().filter_map(ir_item_callable_name).map(str::to_string).collect()
}

fn ir_item_callable_name(item: &IrItem) -> Option<&str> {
    match item {
        IrItem::Action(action) => Some(&action.name),
        IrItem::PureFn(function) => Some(&function.name),
        IrItem::Lock(lock) => Some(&lock.name),
        IrItem::TypeDef(_) | IrItem::Invariant(_) => None,
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

fn rename_ir_item_callable(item: &mut IrItem, label: String) {
    match item {
        IrItem::Action(action) => action.name = label,
        IrItem::PureFn(function) => function.name = label,
        IrItem::Lock(lock) => lock.name = label,
        IrItem::TypeDef(_) | IrItem::Invariant(_) => {}
    }
}

fn rewrite_external_callable_item_calls(
    item: &mut IrItem,
    owner_module: &str,
    entry_module: &str,
    resolver: &ModuleResolver,
    pending: &mut Vec<PendingExternalCall>,
) {
    match item {
        IrItem::Action(action) => rewrite_external_body_calls(&mut action.body, owner_module, entry_module, resolver, pending),
        IrItem::PureFn(function) => rewrite_external_body_calls(&mut function.body, owner_module, entry_module, resolver, pending),
        IrItem::Lock(lock) => rewrite_external_body_calls(&mut lock.body, owner_module, entry_module, resolver, pending),
        IrItem::TypeDef(_) | IrItem::Invariant(_) => {}
    }
}

fn rewrite_external_body_calls(
    body: &mut IrBody,
    owner_module: &str,
    entry_module: &str,
    resolver: &ModuleResolver,
    pending: &mut Vec<PendingExternalCall>,
) {
    for block in &mut body.blocks {
        for instruction in &mut block.instructions {
            if let IrInstruction::Call { func, .. } = instruction {
                let original = func.clone();
                let Some((callee_module, function)) = resolver.resolve_function_with_module(owner_module, &original) else {
                    continue;
                };
                let symbol = function_def_name(&function).to_string();
                *func = callable_label_for(entry_module, &callee_module, &symbol);
                if callee_module != entry_module {
                    pending.push(PendingExternalCall { lookup_module: owner_module.to_string(), call_name: original });
                }
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
                source: param.source,
                binding: IrVar { id: index, name: param.name.clone(), ty },
            }
        })
        .collect()
}

fn function_def_param_types_ir(function: &FunctionDef) -> Vec<IrType> {
    let params = match function {
        FunctionDef::Action(action) => &action.params,
        FunctionDef::Function(function) => &function.params,
        FunctionDef::Lock(lock) => &lock.params,
    };
    params.iter().map(|param| ast_type_to_ir(&param.ty)).collect()
}

fn collect_call_names(ast: &Module) -> HashSet<String> {
    let mut names = HashSet::new();
    for item in &ast.items {
        match item {
            Item::Action(action) => collect_call_names_from_stmts(&action.body, &mut names),
            Item::Function(function) => collect_call_names_from_stmts(&function.body, &mut names),
            Item::Lock(lock) => collect_call_names_from_stmts(&lock.body, &mut names),
            Item::Resource(resource) => collect_call_names_from_validity(resource.validity.as_ref(), &mut names),
            Item::Shared(shared) => collect_call_names_from_validity(shared.validity.as_ref(), &mut names),
            Item::Receipt(receipt) => collect_call_names_from_validity(receipt.validity.as_ref(), &mut names),
            Item::Struct(struct_def) => collect_call_names_from_validity(struct_def.validity.as_ref(), &mut names),
            Item::Flow(_) | Item::Invariant(_) | Item::Const(_) | Item::Enum(_) | Item::Use(_) => {}
        }
    }
    names
}

fn collect_call_names_from_validity(validity: Option<&ValidityBlock>, names: &mut HashSet<String>) {
    if let Some(validity) = validity {
        for predicate in &validity.predicates {
            collect_call_names_from_expr(predicate, names);
        }
    }
}

fn collect_bounded_collection_ops(stmts: &[Stmt], params: &[Param]) -> Vec<IrBoundedCollectionOp> {
    let mut ops = Vec::new();
    collect_bounded_collection_ops_from_stmts(stmts, params, &mut ops);
    ops
}

fn collect_bounded_collection_ops_from_stmts(stmts: &[Stmt], params: &[Param], ops: &mut Vec<IrBoundedCollectionOp>) {
    for stmt in stmts {
        match stmt {
            Stmt::Expr(expr) | Stmt::Let(LetStmt { value: expr, .. }) | Stmt::Return(ReturnStmt { value: Some(expr), .. }) => {
                collect_bounded_collection_ops_from_expr(expr, params, ops);
            }
            Stmt::If(if_stmt) => {
                collect_bounded_collection_ops_from_expr(&if_stmt.condition, params, ops);
                collect_bounded_collection_ops_from_stmts(&if_stmt.then_branch, params, ops);
                if let Some(else_branch) = &if_stmt.else_branch {
                    collect_bounded_collection_ops_from_stmts(else_branch, params, ops);
                }
            }
            Stmt::For(for_stmt) => {
                collect_bounded_collection_ops_from_expr(&for_stmt.iterable, params, ops);
                collect_bounded_collection_ops_from_stmts(&for_stmt.body, params, ops);
            }
            Stmt::While(while_stmt) => {
                collect_bounded_collection_ops_from_expr(&while_stmt.condition, params, ops);
                collect_bounded_collection_ops_from_stmts(&while_stmt.body, params, ops);
            }
            Stmt::Borrow(borrow_stmt) => collect_bounded_collection_ops_from_stmts(&borrow_stmt.body, params, ops),
            Stmt::Return(ReturnStmt { value: None, .. }) => {}
            Stmt::Break(_) | Stmt::Continue(_) => {}
        }
    }
}

fn collect_bounded_collection_ops_from_expr(expr: &Expr, params: &[Param], ops: &mut Vec<IrBoundedCollectionOp>) {
    let Expr::Call(call) = expr else {
        return;
    };
    let Expr::Identifier(operation) = call.func.as_ref() else {
        return;
    };
    if !matches!(operation.as_str(), "__cellscript_consume_each" | "__cellscript_create_each") {
        return;
    }
    let [Expr::Identifier(binding), Expr::Identifier(collection_binding), Expr::Block(body)] = call.args.as_slice() else {
        return;
    };
    let Some(param) = params.iter().find(|param| param.name == *collection_binding) else {
        return;
    };
    let Some(collection) = parse_bounded_collection_type(&param.ty) else {
        return;
    };
    let Type::Named(collection_type) = &param.ty else {
        return;
    };
    let output_type = body.iter().find_map(|stmt| match stmt {
        Stmt::Expr(Expr::Create(create)) => Some(create.ty.clone()),
        _ => None,
    });
    let predicates = body
        .iter()
        .filter_map(|stmt| match stmt {
            Stmt::Expr(Expr::Require(require)) => Some(vec![crate::fmt::format_expression(&require.condition)]),
            Stmt::Expr(Expr::RequireBlock(require_block)) => {
                Some(require_block.expressions.iter().map(crate::fmt::format_expression).collect())
            }
            _ => None,
        })
        .flatten()
        .collect();
    let accumulator_updates = body
        .iter()
        .filter_map(|stmt| match stmt {
            Stmt::Expr(expr @ Expr::Assign(assign)) if assign.op == AssignOp::AddAssign => Some(crate::fmt::format_expression(expr)),
            _ => None,
        })
        .collect();
    let create_template = body.iter().find_map(|stmt| match stmt {
        Stmt::Expr(Expr::Create(create)) => Some(IrBoundedCreateTemplate {
            output_type: create.ty.clone(),
            fields: create.fields.iter().map(|(field, value)| (field.clone(), crate::fmt::format_expression(value))).collect(),
            lock: create.lock.as_deref().map(crate::fmt::format_expression),
        }),
        _ => None,
    });
    ops.push(IrBoundedCollectionOp {
        operation: operation.trim_start_matches("__cellscript_").to_string(),
        binding: binding.clone(),
        collection_binding: collection_binding.clone(),
        collection_type: collection_type.clone(),
        element_type: collection.element_type,
        max_elements: collection.max_elements,
        source: param.source,
        output_type,
        predicates,
        accumulator_updates,
        create_template,
        runtime_contract: None,
        element_width: None,
        span: call.span,
    });
}

fn collect_call_names_from_stmts(stmts: &[Stmt], names: &mut HashSet<String>) {
    for stmt in stmts {
        collect_call_names_from_stmt(stmt, names);
    }
}

fn collect_call_names_from_stmt(stmt: &Stmt, names: &mut HashSet<String>) {
    match stmt {
        Stmt::Expr(expr) | Stmt::Let(LetStmt { value: expr, .. }) | Stmt::Return(ReturnStmt { value: Some(expr), .. }) => {
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
        Stmt::Borrow(borrow_stmt) => collect_call_names_from_stmts(&borrow_stmt.body, names),
        Stmt::Return(ReturnStmt { value: None, .. }) => {}
        Stmt::Break(_) | Stmt::Continue(_) => {}
    }
}

fn collect_call_names_from_expr(expr: &Expr, names: &mut HashSet<String>) {
    match expr {
        Expr::ReplaceRelation(relation) => {
            for value in replace_relation_inner_exprs(relation) {
                collect_call_names_from_expr(value, names);
            }
        }
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
        Expr::Destroy(destroy) => collect_call_names_from_expr(&destroy.expr, names),
        Expr::Claim(claim) => collect_call_names_from_expr(&claim.receipt, names),
        Expr::Settle(settle) => collect_call_names_from_expr(&settle.expr, names),
        Expr::CreateUnique(cu) => {
            for (_, value) in &cu.fields {
                collect_call_names_from_expr(value, names);
            }
            if let Some(lock) = &cu.lock {
                collect_call_names_from_expr(lock, names);
            }
        }
        Expr::ReplaceUnique(ru) => {
            collect_call_names_from_expr(&ru.expr, names);
            for (_, value) in &ru.fields {
                collect_call_names_from_expr(value, names);
            }
        }
        Expr::Assert(assert_expr) => {
            collect_call_names_from_expr(&assert_expr.condition, names);
        }
        Expr::Require(require_expr) => {
            collect_call_names_from_expr(&require_expr.condition, names);
            if let Some(message) = &require_expr.message {
                collect_call_names_from_expr(message, names);
            }
        }
        Expr::RequireBlock(require_block) => {
            for expr in &require_block.expressions {
                collect_call_names_from_expr(expr, names);
            }
        }
        Expr::Preserve(_) => {}
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
        Expr::StdlibCall(call) => {
            for arg in &call.args {
                collect_call_names_from_expr(arg, names);
            }
        }
    }
}

fn function_def_transitive_effect_class(
    resolver: &ModuleResolver,
    owner_module: &str,
    function: &FunctionDef,
    visiting: &mut HashSet<String>,
) -> EffectClass {
    let key = format!("{}::{}", owner_module, function_def_name(function));
    let direct = function_def_inferred_effect_class(function);
    if !visiting.insert(key.clone()) {
        return direct;
    }

    let mut footprint = EffectFootprint::default();
    apply_effect_to_footprint(direct, &mut footprint);
    let mut call_names = HashSet::new();
    collect_call_names_from_stmts(function_def_body(function), &mut call_names);
    for call_name in call_names {
        let Some((callee_module, callee)) = resolver.resolve_function_with_module(owner_module, &call_name) else {
            continue;
        };
        let effect = function_def_transitive_effect_class(resolver, &callee_module, &callee, visiting);
        apply_effect_to_footprint(effect, &mut footprint);
    }
    visiting.remove(&key);

    let inferred = effect_from_footprint(&footprint);
    function_def_declared_effect_class(function).filter(|declared| effect_class_covers(*declared, inferred)).unwrap_or(inferred)
}

fn function_def_inferred_effect_class(function: &FunctionDef) -> EffectClass {
    match function {
        FunctionDef::Action(action) => infer_action_effect_without_call_graph(action),
        FunctionDef::Function(function) => infer_fn_effect_without_call_graph(function),
        FunctionDef::Lock(_) => EffectClass::ReadOnly,
    }
}

fn function_def_declared_effect_class(function: &FunctionDef) -> Option<EffectClass> {
    match function {
        FunctionDef::Action(action) => action.effect_declared.then(|| ast_effect_to_ir(action.effect)),
        FunctionDef::Function(function) => function.effect_declared.then(|| ast_effect_to_ir(function.effect)),
        FunctionDef::Lock(_) => None,
    }
}

fn function_def_body(function: &FunctionDef) -> &[Stmt] {
    match function {
        FunctionDef::Action(action) => &action.body,
        FunctionDef::Function(function) => &function.body,
        FunctionDef::Lock(lock) => &lock.body,
    }
}

fn apply_effect_to_footprint(effect: EffectClass, footprint: &mut EffectFootprint) {
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

fn effect_class_covers(declared: EffectClass, inferred: EffectClass) -> bool {
    matches!(
        (declared, inferred),
        (EffectClass::Pure, EffectClass::Pure)
            | (EffectClass::ReadOnly, EffectClass::Pure | EffectClass::ReadOnly)
            | (EffectClass::Creating, EffectClass::Pure | EffectClass::ReadOnly | EffectClass::Creating)
            | (EffectClass::Destroying, EffectClass::Pure | EffectClass::ReadOnly | EffectClass::Destroying)
            | (EffectClass::Mutating, _)
    )
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
        Type::I32 => IrType::I32,
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
    if !action_core_input_binding_names(action).is_empty() {
        return EffectClass::Mutating;
    }
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
        Stmt::Expr(expr) | Stmt::Let(LetStmt { value: expr, .. }) | Stmt::Return(ReturnStmt { value: Some(expr), .. }) => {
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
        Stmt::Borrow(borrow_stmt) => {
            for stmt in &borrow_stmt.body {
                collect_ast_stmt_effects(stmt, footprint);
            }
        }
        _ => {}
    }
}

fn collect_ast_expr_effects(expr: &Expr, footprint: &mut EffectFootprint) {
    match expr {
        Expr::ReplaceRelation(relation) => {
            footprint.has_consume = true;
            footprint.has_create = true;
            for value in replace_relation_inner_exprs(relation) {
                collect_ast_expr_effects(value, footprint);
            }
        }
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
        Expr::Destroy(destroy) => {
            footprint.has_consume = true;
            collect_ast_expr_effects(&destroy.expr, footprint);
        }
        Expr::Claim(claim) => {
            apply_effect_to_footprint(EffectClass::Mutating, footprint);
            collect_ast_expr_effects(&claim.receipt, footprint);
        }
        Expr::Settle(settle) => {
            apply_effect_to_footprint(EffectClass::Mutating, footprint);
            collect_ast_expr_effects(&settle.expr, footprint);
        }
        Expr::CreateUnique(create) => {
            apply_effect_to_footprint(EffectClass::Creating, footprint);
            for (_, value) in &create.fields {
                collect_ast_expr_effects(value, footprint);
            }
            if let Some(lock) = &create.lock {
                collect_ast_expr_effects(lock, footprint);
            }
        }
        Expr::ReplaceUnique(replace) => {
            apply_effect_to_footprint(EffectClass::Mutating, footprint);
            collect_ast_expr_effects(&replace.expr, footprint);
            for (_, value) in &replace.fields {
                collect_ast_expr_effects(value, footprint);
            }
        }
        Expr::ReadRef(_) => footprint.has_read_ref = true,
        Expr::Assert(assert_expr) => {
            collect_ast_expr_effects(&assert_expr.condition, footprint);
        }
        Expr::Require(require_expr) => {
            collect_ast_expr_effects(&require_expr.condition, footprint);
            if let Some(message) = &require_expr.message {
                collect_ast_expr_effects(message, footprint);
            }
        }
        Expr::RequireBlock(require_block) => {
            for expr in &require_block.expressions {
                collect_ast_expr_effects(expr, footprint);
            }
        }
        Expr::Preserve(_) => {}
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
            if is_read_only_runtime_call(call) {
                footprint.has_read_ref = true;
            }
            if let Expr::Identifier(name) = call.func.as_ref() {
                match name.as_str() {
                    "__cellscript_consume_each" => apply_effect_to_footprint(EffectClass::Mutating, footprint),
                    "__cellscript_create_each" => apply_effect_to_footprint(EffectClass::Creating, footprint),
                    _ => {}
                }
            }
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
        Expr::StdlibCall(call) => {
            let qualified = format!("std::{}::{}", call.namespace, call.name);
            if matches!(qualified.as_str(), "std::lifecycle::transfer" | "std::receipt::claim" | "std::lifecycle::settle") {
                apply_effect_to_footprint(EffectClass::Mutating, footprint);
            }
            for arg in &call.args {
                collect_ast_expr_effects(arg, footprint);
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
        Expr::Integer(_) | Expr::Bool(_) | Expr::String(_) | Expr::ByteString(_) | Expr::Identifier(_) => {}
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

fn resolver_type_def_to_ir(
    local_name: &str,
    type_def: &TypeDef,
    type_fields: &HashMap<String, HashMap<String, IrType>>,
) -> Option<IrTypeDef> {
    match type_def {
        TypeDef::Resource(resource) => Some(IrTypeDef {
            name: local_name.to_string(),
            type_id: resource.type_id.as_ref().map(|type_id| type_id.value.clone()),
            default_hash_type: resource.default_hash_type.as_ref().map(|hash_type| hash_type.value.clone()),
            capacity_floor_shannons: resource.capacity_floor.as_ref().map(|floor| floor.shannons),
            kind: IrTypeKind::Resource,
            fields: layout_resolver_fields(&resource.fields, type_fields),
            capabilities: resource.capabilities.clone(),
            claim_output: None,
            flow_states: None,
            flow_state_field: None,
            flow_rules: Vec::new(),
            flow_initial_state: None,
            flow_terminal_states: Vec::new(),
            flow_terminal_discharge: None,
            flow_state_model: None,
            flow_audit_warnings: Vec::new(),
            validity_predicates: ir_validity_predicates(resource.validity.as_ref(), &resource.fields),
            identity: lower_identity_policy_ast(&resource.identity),
        }),
        TypeDef::Shared(shared) => Some(IrTypeDef {
            name: local_name.to_string(),
            type_id: shared.type_id.as_ref().map(|type_id| type_id.value.clone()),
            default_hash_type: shared.default_hash_type.as_ref().map(|hash_type| hash_type.value.clone()),
            capacity_floor_shannons: shared.capacity_floor.as_ref().map(|floor| floor.shannons),
            kind: IrTypeKind::Shared,
            fields: layout_resolver_fields(&shared.fields, type_fields),
            capabilities: shared.capabilities.clone(),
            claim_output: None,
            flow_states: None,
            flow_state_field: None,
            flow_rules: Vec::new(),
            flow_initial_state: None,
            flow_terminal_states: Vec::new(),
            flow_terminal_discharge: None,
            flow_state_model: None,
            flow_audit_warnings: Vec::new(),
            validity_predicates: ir_validity_predicates(shared.validity.as_ref(), &shared.fields),
            identity: lower_identity_policy_ast(&shared.identity),
        }),
        TypeDef::Receipt(receipt) => Some(IrTypeDef {
            name: local_name.to_string(),
            type_id: receipt.type_id.as_ref().map(|type_id| type_id.value.clone()),
            default_hash_type: receipt.default_hash_type.as_ref().map(|hash_type| hash_type.value.clone()),
            capacity_floor_shannons: receipt.capacity_floor.as_ref().map(|floor| floor.shannons),
            kind: IrTypeKind::Receipt,
            fields: layout_resolver_fields(&receipt.fields, type_fields),
            capabilities: receipt.capabilities.clone(),
            claim_output: receipt.claim_output.as_ref().map(ast_type_to_ir_type),
            flow_states: None,
            flow_state_field: None,
            flow_rules: Vec::new(),
            flow_initial_state: None,
            flow_terminal_states: Vec::new(),
            flow_terminal_discharge: None,
            flow_state_model: None,
            flow_audit_warnings: Vec::new(),
            validity_predicates: ir_validity_predicates(receipt.validity.as_ref(), &receipt.fields),
            identity: lower_identity_policy_ast(&receipt.identity),
        }),
        TypeDef::Struct(struct_def) => Some(IrTypeDef {
            name: local_name.to_string(),
            type_id: struct_def.type_id.as_ref().map(|type_id| type_id.value.clone()),
            default_hash_type: struct_def.default_hash_type.as_ref().map(|hash_type| hash_type.value.clone()),
            capacity_floor_shannons: struct_def.capacity_floor.as_ref().map(|floor| floor.shannons),
            kind: IrTypeKind::Struct,
            fields: layout_resolver_fields(&struct_def.fields, type_fields),
            capabilities: Vec::new(),
            claim_output: None,
            flow_states: None,
            flow_state_field: None,
            flow_rules: Vec::new(),
            flow_initial_state: None,
            flow_terminal_states: Vec::new(),
            flow_terminal_discharge: None,
            flow_state_model: None,
            flow_audit_warnings: Vec::new(),
            validity_predicates: ir_validity_predicates(struct_def.validity.as_ref(), &struct_def.fields),
            identity: IrIdentityPolicy::None,
        }),
        TypeDef::Enum(_) => None,
    }
}

fn lower_identity_policy_ast(policy: &IdentityPolicy) -> IrIdentityPolicy {
    match policy {
        IdentityPolicy::None => IrIdentityPolicy::None,
        IdentityPolicy::CkbTypeId => IrIdentityPolicy::CkbTypeId,
        IdentityPolicy::Field(path) => IrIdentityPolicy::Field(path.clone()),
        IdentityPolicy::ScriptArgs => IrIdentityPolicy::ScriptArgs,
        IdentityPolicy::SingletonType => IrIdentityPolicy::SingletonType,
    }
}

fn layout_resolver_fields(fields: &[Field], type_fields: &HashMap<String, HashMap<String, IrType>>) -> Vec<IrField> {
    let mut next_offset = Some(0usize);
    fields
        .iter()
        .map(|field| {
            let ty = ast_type_to_ir_type(&field.ty);
            let fixed_size = fixed_encoded_size_for_resolver_ir_type(&ty, type_fields, &mut HashSet::new());
            let offset = next_offset.unwrap_or(0);
            next_offset = next_offset.and_then(|current| fixed_size.and_then(|size| current.checked_add(size)));
            IrField { name: field.name.clone(), ty, offset, fixed_size }
        })
        .collect()
}

fn fixed_encoded_size_for_resolver_ir_type(
    ty: &IrType,
    type_fields: &HashMap<String, HashMap<String, IrType>>,
    seen: &mut HashSet<String>,
) -> Option<usize> {
    match ty {
        IrType::U8 | IrType::Bool => Some(1),
        IrType::U16 => Some(2),
        IrType::U32 => Some(4),
        IrType::I32 => Some(4),
        IrType::U64 => Some(8),
        IrType::U128 => Some(16),
        IrType::Address | IrType::Hash => Some(32),
        IrType::Array(inner, len) => {
            fixed_encoded_size_for_resolver_ir_type(inner, type_fields, seen).and_then(|inner_size| inner_size.checked_mul(*len))
        }
        IrType::Tuple(items) => items.iter().try_fold(0usize, |acc, item| {
            fixed_encoded_size_for_resolver_ir_type(item, type_fields, seen).and_then(|size| acc.checked_add(size))
        }),
        IrType::Unit => Some(0),
        IrType::Named(name) => {
            let base_name = name.split('<').next().unwrap_or(name.as_str());
            if !seen.insert(base_name.to_string()) {
                return None;
            }
            let size = type_fields.get(base_name).and_then(|fields| {
                fields.values().try_fold(0usize, |acc, field_ty| {
                    fixed_encoded_size_for_resolver_ir_type(field_ty, type_fields, seen)
                        .and_then(|field_size| acc.checked_add(field_size))
                })
            });
            seen.remove(base_name);
            size
        }
        IrType::Ref(_) | IrType::MutRef(_) => None,
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

fn resolver_flow_states_to_ir(type_def: &TypeDef) -> Option<Vec<String>> {
    match type_def {
        TypeDef::Resource(_) | TypeDef::Shared(_) | TypeDef::Struct(_) | TypeDef::Enum(_) => None,
        TypeDef::Receipt(_) => None,
    }
}

fn ast_type_to_ir_type(ty: &Type) -> IrType {
    match ty {
        Type::U8 => IrType::U8,
        Type::U16 => IrType::U16,
        Type::U32 => IrType::U32,
        Type::I32 => IrType::I32,
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

fn action_core_input_binding_names(action: &ActionDef) -> HashSet<String> {
    action_inferred_lineage_bindings(action).keys().cloned().collect()
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
    for (name, type_name) in action_output_binding_types(action) {
        if bindings.values().any(|bound_output| bound_output == &name) {
            continue;
        }
        outputs_by_type.entry(type_name).or_default().push(name);
    }

    let mut inputs_by_type: HashMap<String, Vec<String>> = HashMap::new();
    for param in &action.params {
        if consumed.contains(&param.name) || bindings.contains_key(&param.name) {
            continue;
        }
        let Some(type_name) = ast_named_cell_type_name(&param.ty) else {
            continue;
        };
        if param.source != ParamSource::Default && param.source != ParamSource::Input {
            continue;
        }
        if param.is_ref || param.is_mut || param.is_read_ref {
            continue;
        }
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

fn action_output_binding_types(action: &ActionDef) -> HashMap<String, String> {
    let mut bindings = HashMap::new();
    for output in &action.outputs {
        if let Some(type_name) = ast_named_cell_type_name(&output.ty) {
            bindings.insert(output.name.clone(), type_name.to_string());
        }
    }
    bindings
}

fn ast_named_cell_type_name(ty: &Type) -> Option<&str> {
    match ty {
        Type::Named(name) => Some(name.split('<').next().unwrap_or(name.as_str())),
        _ => None,
    }
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
        Expr::ReplaceRelation(relation) => {
            bindings.insert(relation.before.clone());
        }
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
        Expr::ReadRef(_) => {}
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
        Expr::RequireBlock(require_block) => {
            for expr in &require_block.expressions {
                collect_consumed_bindings_from_expr(expr, bindings);
            }
        }
        Expr::Preserve(_) => {}
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
        Expr::StdlibCall(call) => {
            if let Some(name) = stdlib_lifecycle_consumed_binding(call) {
                bindings.insert(name);
            }
        }
        Expr::Identifier(_) | Expr::Integer(_) | Expr::Bool(_) | Expr::String(_) | Expr::ByteString(_) => {}
    }
}

fn stdlib_lifecycle_consumed_binding(call: &StdlibCallExpr) -> Option<String> {
    let qualified = format!("std::{}::{}", call.namespace, call.name);
    match qualified.as_str() {
        "std::lifecycle::transfer" | "std::receipt::claim" | "std::lifecycle::settle" => match call.args.first() {
            Some(Expr::Identifier(name)) => Some(name.clone()),
            _ => None,
        },
        _ => None,
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
    matches!(ty, IrType::Bool | IrType::U8 | IrType::U16 | IrType::U32 | IrType::I32 | IrType::U64 | IrType::Address | IrType::Hash)
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
    crate::ckb_blake2b256(name.as_bytes())
}

fn stable_u64_tag(value: &str) -> u64 {
    value.bytes().fold(0xcbf2_9ce4_8422_2325u64, |acc, byte| acc.wrapping_mul(0x100_0000_01b3).wrapping_add(byte as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::lex;
    use crate::parser::parse;

    fn parse_and_lower(source: &str) -> IrModule {
        let tokens = lex(source).unwrap();
        let ast = parse(&tokens).unwrap();
        crate::types::check(&ast).unwrap();
        crate::flow::check(&ast).unwrap();
        generate(&ast).unwrap()
    }

    #[test]
    fn preserve_sugar_populates_preserved_fields() {
        let source = r#"
module test

resource Offer has store {
    seller: u64
    price: u64
    payment_symbol: u64
    state: u8
}

flow Offer.state {
    Live -> Filled;
}

action fill(input: Offer) -> (output: Offer) {
    transition input.state: Live -> output.state: Filled
    verification
        preserve output from input {
            seller
            price
        }
        require output.payment_symbol == input.payment_symbol
}
"#;
        let ir = parse_and_lower(source);
        let action = ir
            .items
            .iter()
            .find_map(|item| match item {
                IrItem::Action(a) if a.name == "fill" => Some(a.clone()),
                _ => None,
            })
            .expect("expected fill action");
        // Find the mutate for the output binding
        let mutate = action.body.mutate_set.iter().find(|m| m.binding == "output");
        if let Some(mutate) = mutate {
            assert!(
                mutate.preserved_fields.contains(&"seller".to_string()),
                "preserved_fields should contain 'seller', got {:?}",
                mutate.preserved_fields
            );
            assert!(
                mutate.preserved_fields.contains(&"price".to_string()),
                "preserved_fields should contain 'price', got {:?}",
                mutate.preserved_fields
            );
        }
    }

    #[test]
    fn require_block_lowers_to_atomic_requires() {
        let source = r#"
module test

action check(x: u64, y: u64) -> u64 {
    verification
        require {
            x > 0
            y > 0
        }
        return x + y
}
"#;
        let ir = parse_and_lower(source);
        let action = ir
            .items
            .iter()
            .find_map(|item| match item {
                IrItem::Action(a) if a.name == "check" => Some(a.clone()),
                _ => None,
            })
            .expect("expected check action");
        // The require block should produce multiple basic blocks due to conditional branching.
        // Each require produces a Branch terminator (cond ? ok : fail) in the IR CFG.
        // With 2 require expressions + return, we expect at least 5 blocks
        // (entry, require1_ok, require2_ok, return_block, fail_block).
        assert!(
            action.body.blocks.len() >= 3,
            "expected at least 3 basic blocks from 2 require expressions, found {} blocks",
            action.body.blocks.len()
        );
        // Count the Branch terminators which represent require conditionals
        let branch_count = action.body.blocks.iter().filter(|b| matches!(b.terminator, IrTerminator::Branch { .. })).count();
        assert!(
            branch_count >= 2,
            "expected at least 2 branch terminators from require block, found {} out of {} blocks",
            branch_count,
            action.body.blocks.len()
        );
    }

    #[test]
    fn byte_string_literal_lowers_to_fixed_array_const() {
        let source = r#"
module test

action symbol() -> [u8; 4]
{
    verification
        return b"TEST"
}
"#;
        let ir = parse_and_lower(source);
        let action = ir
            .items
            .iter()
            .find_map(|item| match item {
                IrItem::Action(a) if a.name == "symbol" => Some(a),
                _ => None,
            })
            .expect("expected symbol action");
        let bytes = action.body.blocks.iter().find_map(|block| match &block.terminator {
            IrTerminator::Return(Some(IrOperand::Const(IrConst::Array(items)))) => Some(items),
            _ => None,
        });

        let bytes = bytes.expect("expected byte string return to lower to a fixed array const");
        let lowered = bytes
            .iter()
            .map(|byte| match byte {
                IrConst::U8(byte) => *byte,
                other => panic!("expected fixed byte const, got {:?}", other),
            })
            .collect::<Vec<_>>();
        assert_eq!(lowered, b"TEST");
    }

    #[test]
    fn typed_integer_literals_lower_with_expected_numeric_width() {
        let source = r#"
module test

const SMALL: u8 = 2

action literal_widths(flag: bool) -> u8 {
    verification
        let left: u8 = 1
        let right: u8 = if flag { SMALL } else { 3 }
        return left + right
}
"#;
        let ir = parse_and_lower(source);
        let action = ir
            .items
            .iter()
            .find_map(|item| match item {
                IrItem::Action(action) if action.name == "literal_widths" => Some(action),
                _ => None,
            })
            .expect("expected literal_widths action");

        let returned_ty = action.body.blocks.iter().find_map(|block| match &block.terminator {
            IrTerminator::Return(Some(IrOperand::Var(var))) => Some(var.ty.clone()),
            _ => None,
        });

        assert_eq!(returned_ty, Some(IrType::U8));
        assert!(action.body.blocks.iter().flat_map(|block| &block.instructions).any(|instruction| {
            matches!(instruction, IrInstruction::Move { src: IrOperand::Const(IrConst::U8(1..=3)), .. })
                || matches!(instruction, IrInstruction::LoadConst { value: IrConst::U8(1..=3), .. })
        }));
    }

    #[test]
    fn stdlib_transfer_lowers_to_single_consumed_input_and_locked_output() {
        let source = r#"
module test

resource Coin has store, replace, relock, consume, burn {
    amount: u64
}

action transfer_only(coin: Coin, to: Address) -> next_coin: Coin {
    verification
        std::lifecycle::transfer(coin, next_coin, to) { amount }
}
"#;
        let ir = parse_and_lower(source);
        let action = ir
            .items
            .iter()
            .find_map(|item| match item {
                IrItem::Action(a) if a.name == "transfer_only" => Some(a),
                _ => None,
            })
            .expect("expected transfer_only action");

        assert_eq!(action.body.consume_set.len(), 1, "stdlib transfer should not also infer an input lineage consume");
        assert_eq!(action.body.consume_set[0].operation, "consume");
        assert_eq!(action.body.consume_set[0].binding, "coin");

        assert_eq!(action.body.create_set.len(), 1);
        let output = &action.body.create_set[0];
        assert_eq!(output.operation, "output");
        assert_eq!(output.binding, "next_coin");
        assert!(output.lock.is_some(), "stdlib transfer must bind the output lock target");
        assert!(output.fields.iter().any(|(field, _)| field == "amount"));
    }

    #[test]
    fn stdlib_claim_lowers_to_consumed_receipt_and_locked_declared_output() {
        let source = r#"
module test

resource Coin has store, replace, relock, consume, burn {
    amount: u64
}

receipt Voucher -> Coin has destroy {
    amount: u64
    holder: Address
}

action claim_only(voucher: Voucher) -> coin: Coin {
    verification
        std::receipt::claim(voucher, coin, voucher.holder) { amount }
}
"#;
        let ir = parse_and_lower(source);
        let action = ir
            .items
            .iter()
            .find_map(|item| match item {
                IrItem::Action(a) if a.name == "claim_only" => Some(a),
                _ => None,
            })
            .expect("expected claim_only action");

        assert_eq!(action.body.consume_set.len(), 1, "stdlib claim should consume exactly the receipt");
        assert_eq!(action.body.consume_set[0].operation, "consume");
        assert_eq!(action.body.consume_set[0].binding, "voucher");

        assert_eq!(action.body.create_set.len(), 1);
        let output = &action.body.create_set[0];
        assert_eq!(output.operation, "output");
        assert_eq!(output.binding, "coin");
        assert!(output.lock.is_some(), "stdlib claim must bind the explicit output lock target");
        assert!(output.fields.iter().any(|(field, _)| field == "amount"));
    }

    #[test]
    fn stdlib_settle_lowers_to_consumed_input_and_locked_output() {
        let source = r#"
module test

resource Coin has store, replace, relock, consume, burn {
    amount: u64
    owner: Address
}

action settle_coin(coin: Coin) -> next_coin: Coin {
    verification
        std::lifecycle::settle(coin, next_coin, coin.owner) {
            amount
            owner
        }
}
"#;
        let ir = parse_and_lower(source);
        let action = ir
            .items
            .iter()
            .find_map(|item| match item {
                IrItem::Action(a) if a.name == "settle_coin" => Some(a),
                _ => None,
            })
            .expect("expected settle_coin action");

        assert_eq!(action.body.consume_set.len(), 1, "stdlib settle should consume exactly the input");
        assert_eq!(action.body.consume_set[0].operation, "consume");
        assert_eq!(action.body.consume_set[0].binding, "coin");

        assert_eq!(action.body.create_set.len(), 1);
        let output = &action.body.create_set[0];
        assert_eq!(output.operation, "output");
        assert_eq!(output.binding, "next_coin");
        assert!(output.lock.is_some(), "stdlib settle must bind the explicit output lock target");
        assert!(output.fields.iter().any(|(field, _)| field == "amount"));
        assert!(output.fields.iter().any(|(field, _)| field == "owner"));
    }

    #[test]
    fn imported_function_effects_are_recomputed_transitively_from_source() {
        fn parse_module(source: &str) -> Module {
            parse(&lex(source).unwrap()).unwrap()
        }

        let dep = parse_module(
            r#"
module dep

resource Token has destroy {
    amount: u64
}

action issue(amount: u64) -> u64 {
    verification
        let token = create Token { amount: amount }
        destroy token
        return amount
}
"#,
        );
        let bridge = parse_module(
            r#"
module bridge

use dep::{issue}

#[effect(Pure)]
fn hidden_issue(amount: u64) -> u64 {
    return issue(amount)
}
"#,
        );
        let consumer = parse_module(
            r#"
module consumer

use bridge::{hidden_issue}

action run(amount: u64) -> u64 {
    verification
        return hidden_issue(amount)
}
"#,
        );

        let mut resolver = ModuleResolver::new();
        resolver.register_module(dep).unwrap();
        resolver.register_module(bridge).unwrap();
        resolver.register_module(consumer.clone()).unwrap();

        let error = generate_with_resolver(&consumer, &resolver, "consumer").unwrap_err();
        assert!(
            error.message.contains("declared effect Pure is too weak for function 'hidden_issue'")
                && error.message.contains("inferred effect is Mutating"),
            "unexpected error: {}",
            error.message
        );
    }

    #[test]
    fn unique_lifecycle_operations_cannot_hide_behind_pure_effects() {
        let source = r#"
module test

resource Token has store, create
    identity(field(id))
{
    id: u64
}

#[effect(Pure)]
action issue(id: u64) -> Token {
    verification
        create_unique<Token>(identity = field(id)) { id: id }
}
"#;
        let ast = parse(&lex(source).unwrap()).unwrap();
        crate::types::check(&ast).unwrap();
        crate::flow::check(&ast).unwrap();
        let action = ast
            .items
            .iter()
            .find_map(|item| match item {
                Item::Action(action) if action.name == "issue" => Some(action),
                _ => None,
            })
            .expect("issue action");

        assert_eq!(infer_action_effect_without_call_graph(action), EffectClass::Creating);
        let error = generate(&ast).unwrap_err();
        assert!(
            error.message.contains("declared effect Pure is too weak for action 'issue'")
                && error.message.contains("inferred effect is Creating"),
            "unexpected error: {}",
            error.message
        );
    }

    #[test]
    fn imported_concrete_payload_enum_keeps_layout_and_constructor_lowering() {
        fn parse_module(source: &str) -> Module {
            parse(&lex(source).unwrap()).unwrap()
        }

        let dep = parse_module(
            r#"
module dep
enum Limit { None, Some(u64) }
"#,
        );
        let consumer = parse_module(
            r#"
module consumer
use dep::{Limit}
fn make() -> Limit { Limit::Some(7) }
"#,
        );
        let mut resolver = ModuleResolver::new();
        resolver.register_module(dep).unwrap();
        resolver.register_module(consumer.clone()).unwrap();

        let ir = generate_with_resolver(&consumer, &resolver, "consumer").unwrap();
        let layout = ir.enum_layouts.get("Limit").expect("imported enum layout");
        assert_eq!(layout.encoded_size, 9);
        assert!(ir.items.iter().any(|item| matches!(item, IrItem::PureFn(function) if function.body.blocks.iter().any(|block| block.instructions.iter().any(|instruction| matches!(instruction, IrInstruction::EnumConstruct { enum_name, variant, .. } if enum_name == "Limit" && variant == "Some"))))));
    }
}
