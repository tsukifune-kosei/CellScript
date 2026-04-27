use crate::error::Span;

#[derive(Debug, Clone)]
pub struct Module {
    pub name: String,
    pub items: Vec<Item>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum Item {
    Resource(ResourceDef),
    Shared(SharedDef),
    Receipt(ReceiptDef),
    Struct(StructDef),
    Const(ConstDef),
    Enum(EnumDef),
    Action(ActionDef),
    Function(FnDef),
    Lock(LockDef),
    Use(UseStmt),
}

#[derive(Debug, Clone)]
pub struct ResourceDef {
    pub name: String,
    pub type_id: Option<TypeIdentity>,
    pub default_hash_type: Option<HashTypeDecl>,
    pub capacity_floor: Option<CapacityFloorDecl>,
    pub capabilities: Vec<Capability>,
    pub fields: Vec<Field>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct SharedDef {
    pub name: String,
    pub type_id: Option<TypeIdentity>,
    pub default_hash_type: Option<HashTypeDecl>,
    pub capacity_floor: Option<CapacityFloorDecl>,
    pub capabilities: Vec<Capability>,
    pub fields: Vec<Field>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ReceiptDef {
    pub name: String,
    pub type_id: Option<TypeIdentity>,
    pub default_hash_type: Option<HashTypeDecl>,
    pub capacity_floor: Option<CapacityFloorDecl>,
    pub claim_output: Option<Type>,
    pub lifecycle: Option<Lifecycle>,
    pub capabilities: Vec<Capability>,
    pub fields: Vec<Field>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct StructDef {
    pub name: String,
    pub type_id: Option<TypeIdentity>,
    pub default_hash_type: Option<HashTypeDecl>,
    pub capacity_floor: Option<CapacityFloorDecl>,
    pub fields: Vec<Field>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeIdentity {
    pub value: String,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashTypeDecl {
    pub value: String,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityFloorDecl {
    pub shannons: u64,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ConstDef {
    pub name: String,
    pub ty: Type,
    pub value: Expr,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct EnumDef {
    pub name: String,
    pub variants: Vec<EnumVariant>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct EnumVariant {
    pub name: String,
    pub fields: Vec<Type>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct Lifecycle {
    pub states: Vec<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    Store,
    Transfer,
    Destroy,
}

#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub ty: Type,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ActionDef {
    pub name: String,
    pub params: Vec<Param>,
    pub return_type: Option<Type>,
    pub body: Vec<Stmt>,
    pub effect: EffectClass,
    pub effect_declared: bool,
    pub scheduler_hint: Option<SchedulerHint>,
    pub doc_comment: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct FnDef {
    pub name: String,
    pub params: Vec<Param>,
    pub return_type: Option<Type>,
    pub body: Vec<Stmt>,
    pub doc_comment: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct LockDef {
    pub name: String,
    pub params: Vec<Param>,
    pub return_type: Type,
    pub body: Vec<Stmt>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct UseStmt {
    pub module_path: Vec<String>,
    pub imports: Vec<UseImport>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct UseImport {
    pub name: String,
    pub alias: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub ty: Type,
    pub is_mut: bool,
    pub is_ref: bool,
    pub is_read_ref: bool,
    pub source: ParamSource,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParamSource {
    Default,
    Protected,
    Witness,
    LockArgs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    U8,
    U16,
    U32,
    U64,
    U128,
    Bool,
    Unit,
    Address,
    Hash,
    Array(Box<Type>, usize),
    Tuple(Vec<Type>),
    Named(String),
    Ref(Box<Type>),
    MutRef(Box<Type>),
}

#[derive(Debug, Clone)]
pub enum Stmt {
    Let(LetStmt),
    Expr(Expr),
    Return(Option<Expr>),
    If(IfStmt),
    For(ForStmt),
    While(WhileStmt),
}

#[derive(Debug, Clone)]
pub enum BindingPattern {
    Name(String),
    Tuple(Vec<BindingPattern>),
    Wildcard,
}

#[derive(Debug, Clone)]
pub struct LetStmt {
    pub pattern: BindingPattern,
    pub ty: Option<Type>,
    pub value: Expr,
    pub is_mut: bool,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct IfStmt {
    pub condition: Expr,
    pub then_branch: Vec<Stmt>,
    pub else_branch: Option<Vec<Stmt>>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ForStmt {
    pub pattern: BindingPattern,
    pub iterable: Expr,
    pub body: Vec<Stmt>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct WhileStmt {
    pub condition: Expr,
    pub body: Vec<Stmt>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum Expr {
    Integer(u64),
    Bool(bool),
    String(String),
    ByteString(Vec<u8>),
    Identifier(String),
    Assign(AssignExpr),
    Binary(BinaryExpr),
    Unary(UnaryExpr),
    Call(CallExpr),
    FieldAccess(FieldAccessExpr),
    Index(IndexExpr),
    Create(CreateExpr),
    Consume(ConsumeExpr),
    Transfer(TransferExpr),
    Destroy(DestroyExpr),
    ReadRef(ReadRefExpr),
    Claim(ClaimExpr),
    Settle(SettleExpr),
    Assert(AssertExpr),
    Require(RequireExpr),
    Block(Vec<Stmt>),
    Tuple(Vec<Expr>),
    Array(Vec<Expr>),
    If(IfExpr),
    Cast(CastExpr),
    Range(RangeExpr),
    StructInit(StructInitExpr),
    Match(MatchExpr),
}

#[derive(Debug, Clone)]
pub struct AssignExpr {
    pub target: Box<Expr>,
    pub op: AssignOp,
    pub value: Box<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignOp {
    Assign,
    AddAssign,
}

#[derive(Debug, Clone)]
pub struct BinaryExpr {
    pub op: BinaryOp,
    pub left: Box<Expr>,
    pub right: Box<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
}

#[derive(Debug, Clone)]
pub struct UnaryExpr {
    pub op: UnaryOp,
    pub expr: Box<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Neg,
    Not,
    Ref,
    Deref,
}

#[derive(Debug, Clone)]
pub struct CallExpr {
    pub func: Box<Expr>,
    pub args: Vec<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct FieldAccessExpr {
    pub expr: Box<Expr>,
    pub field: String,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct IndexExpr {
    pub expr: Box<Expr>,
    pub index: Box<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct CreateExpr {
    pub ty: String,
    pub fields: Vec<(String, Expr)>,
    pub lock: Option<Box<Expr>>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ConsumeExpr {
    pub expr: Box<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct TransferExpr {
    pub expr: Box<Expr>,
    pub to: Box<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct DestroyExpr {
    pub expr: Box<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ReadRefExpr {
    pub ty: String,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ClaimExpr {
    pub receipt: Box<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct SettleExpr {
    pub expr: Box<Expr>,
    pub span: Span,
}

/// Assert / assert_invariant expression
#[derive(Debug, Clone)]
pub struct AssertExpr {
    pub condition: Box<Expr>,
    pub message: Box<Expr>,
    pub span: Span,
}

/// Lock/action failure requirement expression.
#[derive(Debug, Clone)]
pub struct RequireExpr {
    pub condition: Box<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct IfExpr {
    pub condition: Box<Expr>,
    pub then_branch: Box<Expr>,
    pub else_branch: Box<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct CastExpr {
    pub expr: Box<Expr>,
    pub ty: Type,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct RangeExpr {
    pub start: Box<Expr>,
    pub end: Box<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct StructInitExpr {
    pub ty: String,
    pub fields: Vec<(String, Expr)>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct MatchExpr {
    pub expr: Box<Expr>,
    pub arms: Vec<MatchArm>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct MatchArm {
    pub pattern: String,
    pub value: Expr,
    pub span: Span,
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
pub struct SchedulerHint {
    pub parallelizable: bool,
    pub estimated_cycles: u64,
}
