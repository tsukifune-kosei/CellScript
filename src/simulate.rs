use crate::ast::*;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum SimValue {
    Integer(u128),
    Bool(bool),
    String(String),
    Unit,
    Simulated { ty: String, description: String },
    Struct { name: String, fields: Vec<(String, SimValue)> },
    Array(Vec<SimValue>),
    Tuple(Vec<SimValue>),
    LoopBreak(Option<String>),
    LoopContinue(Option<String>),
}

impl std::fmt::Display for SimValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SimValue::Integer(n) => write!(f, "{}", n),
            SimValue::Bool(b) => write!(f, "{}", b),
            SimValue::String(s) => write!(f, "\"{}\"", s),
            SimValue::Unit => write!(f, "()"),
            SimValue::Simulated { ty, description } => write!(f, "<simulated {} ({})>", ty, description),
            SimValue::Struct { name, fields } => {
                write!(f, "{} {{ ", name)?;
                let parts: Vec<String> = fields.iter().map(|(n, v)| format!("{}: {}", n, v)).collect();
                write!(f, "{}", parts.join(", "))?;
                write!(f, " }}")
            }
            SimValue::Array(items) => {
                write!(f, "[")?;
                let parts: Vec<String> = items.iter().map(|v| v.to_string()).collect();
                write!(f, "{}", parts.join(", "))?;
                write!(f, "]")
            }
            SimValue::Tuple(items) => {
                write!(f, "(")?;
                let parts: Vec<String> = items.iter().map(|v| v.to_string()).collect();
                write!(f, "{}", parts.join(", "))?;
                write!(f, ")")
            }
            SimValue::LoopBreak(label) => write!(f, "<break{}>", label.as_ref().map_or(String::new(), |label| format!(" {label}"))),
            SimValue::LoopContinue(label) => {
                write!(f, "<continue{}>", label.as_ref().map_or(String::new(), |label| format!(" {label}")))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum TraceEvent {
    Bind { name: String, value: SimValue },
    Create { ty: String, fields: Vec<(String, String)> },
    Consume { description: String },
    Destroy { description: String },
    ReadRef { ty: String },
    Claim { description: String },
    Settle { description: String },
    Call { name: String, args: Vec<String> },
    Return { value: SimValue },
    Branch { condition: SimValue, taken: bool },
    Assert { condition: SimValue, message: String },
}

impl std::fmt::Display for TraceEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TraceEvent::Bind { name, value } => write!(f, "  let {} = {}", name, value),
            TraceEvent::Create { ty, fields } => {
                write!(f, "  create {} {{ ", ty)?;
                let parts: Vec<String> = fields.iter().map(|(n, v)| format!("{}: {}", n, v)).collect();
                write!(f, "{}", parts.join(", "))?;
                write!(f, " }}")
            }
            TraceEvent::Consume { description } => write!(f, "  consume {}", description),
            TraceEvent::Destroy { description } => write!(f, "  destroy {}", description),
            TraceEvent::ReadRef { ty } => write!(f, "  read_ref<{}>()", ty),
            TraceEvent::Claim { description } => write!(f, "  claim {}", description),
            TraceEvent::Settle { description } => write!(f, "  settle {}", description),
            TraceEvent::Call { name, args } => write!(f, "  call {}({})", name, args.join(", ")),
            TraceEvent::Return { value } => write!(f, "  return {}", value),
            TraceEvent::Branch { condition, taken } => write!(f, "  if {} -> {}", condition, if *taken { "then" } else { "else" }),
            TraceEvent::Assert { condition, message } => write!(f, "  assert!({}, \"{}\")", condition, message),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SimulateResult {
    pub entry_name: String,
    pub return_value: SimValue,
    pub trace: Vec<TraceEvent>,
    pub has_cell_ops: bool,
    pub steps: u64,
}

impl std::fmt::Display for SimulateResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Simulated entry: {}", self.entry_name)?;
        writeln!(f, "Steps: {}", self.steps)?;
        if self.has_cell_ops {
            writeln!(f, "Cell operations: yes (simulated)")?;
        } else {
            writeln!(f, "Cell operations: none (pure computation)")?;
        }
        writeln!(f, "Trace:")?;
        for event in &self.trace {
            writeln!(f, "{}", event)?;
        }
        write!(f, "Result: {}", self.return_value)
    }
}

pub struct SimulateInterpreter {
    env: HashMap<String, SimValue>,
    bounded_collection_limits: HashMap<String, usize>,
    trace: Vec<TraceEvent>,
    functions: HashMap<String, (Vec<Param>, Vec<Stmt>)>,
    has_cell_ops: bool,
    steps: u64,
    max_steps: u64,
}

#[derive(Debug, Clone)]
pub enum SimulateError {
    StepLimitExceeded { max: u64 },
    UndefinedVariable { name: String },
    UndefinedFunction { name: String },
    TypeError { expected: String, got: String },
    Unsupported { description: String },
    RuntimeError { code: u64, name: String },
}

impl std::fmt::Display for SimulateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SimulateError::StepLimitExceeded { max } => write!(f, "simulation exceeded maximum step limit ({})", max),
            SimulateError::UndefinedVariable { name } => write!(f, "undefined variable '{}'", name),
            SimulateError::UndefinedFunction { name } => write!(f, "undefined function '{}'", name),
            SimulateError::TypeError { expected, got } => write!(f, "type error: expected {}, got {}", expected, got),
            SimulateError::Unsupported { description } => write!(f, "unsupported: {}", description),
            SimulateError::RuntimeError { code, name } => write!(f, "CellScript runtime error {} ({})", code, name),
        }
    }
}

impl SimulateInterpreter {
    pub fn new(module: &Module, max_steps: u64) -> Self {
        let mut functions = HashMap::new();

        for item in &module.items {
            match item {
                Item::Function(f) => {
                    functions.insert(f.name.clone(), (f.params.clone(), f.body.clone()));
                }
                Item::Action(a) => {
                    functions.insert(format!("action::{}", a.name), (a.params.clone(), a.body.clone()));
                }
                Item::Lock(l) => {
                    functions.insert(format!("lock::{}", l.name), (l.params.clone(), l.body.clone()));
                }
                _ => {}
            }
        }

        Self {
            env: HashMap::new(),
            bounded_collection_limits: HashMap::new(),
            trace: Vec::new(),
            functions,
            has_cell_ops: false,
            steps: 0,
            max_steps,
        }
    }

    pub fn simulate_action(&mut self, name: &str, args: &[SimValue]) -> Result<SimulateResult, SimulateError> {
        self.simulate_entry("action", name, args)
    }

    pub fn simulate_lock(&mut self, name: &str, args: &[SimValue]) -> Result<SimulateResult, SimulateError> {
        self.simulate_entry("lock", name, args)
    }

    fn simulate_entry(&mut self, kind: &str, name: &str, args: &[SimValue]) -> Result<SimulateResult, SimulateError> {
        let key = format!("{}::{}", kind, name);
        let (params, body) = self.functions.get(&key).cloned().ok_or(SimulateError::UndefinedFunction { name: key })?;

        for (param, arg) in params.iter().zip(args.iter()) {
            self.env.insert(param.name.clone(), arg.clone());
            if let Some(collection) = parse_bounded_collection_type(&param.ty) {
                self.bounded_collection_limits.insert(param.name.clone(), collection.max_elements);
            }
        }

        let result = self.exec_stmts(&body)?;
        let return_value = self.finish_entry_flow(result)?;

        Ok(SimulateResult {
            entry_name: name.to_string(),
            return_value: return_value.clone(),
            trace: self.trace.clone(),
            has_cell_ops: self.has_cell_ops,
            steps: self.steps,
        })
    }

    pub fn simulate_function(&mut self, name: &str, args: &[SimValue]) -> Result<SimValue, SimulateError> {
        let (params, body) =
            self.functions.get(name).cloned().ok_or_else(|| SimulateError::UndefinedFunction { name: name.to_string() })?;

        let saved_env = self.env.clone();
        let saved_collection_limits = self.bounded_collection_limits.clone();
        self.env.clear();
        self.bounded_collection_limits.clear();

        for (param, arg) in params.iter().zip(args.iter()) {
            self.env.insert(param.name.clone(), arg.clone());
            if let Some(collection) = parse_bounded_collection_type(&param.ty) {
                self.bounded_collection_limits.insert(param.name.clone(), collection.max_elements);
            }
        }

        let result = self.exec_stmts(&body)?;
        let value = self.finish_entry_flow(result)?;

        self.env = saved_env;
        self.bounded_collection_limits = saved_collection_limits;

        Ok(value)
    }

    fn exec_stmts(&mut self, stmts: &[Stmt]) -> Result<Option<SimValue>, SimulateError> {
        for stmt in stmts {
            if let Some(value) = self.exec_stmt(stmt)? {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    fn exec_stmt(&mut self, stmt: &Stmt) -> Result<Option<SimValue>, SimulateError> {
        self.bump_steps()?;

        match stmt {
            Stmt::Let(let_stmt) => {
                let value = self.eval_expr(&let_stmt.value)?;
                self.bind_pattern(&let_stmt.pattern, value.clone());
                Ok(None)
            }
            Stmt::Return(ReturnStmt { value: expr, .. }) => {
                let value = match expr {
                    Some(e) => self.eval_expr(e)?,
                    None => SimValue::Unit,
                };
                self.trace.push(TraceEvent::Return { value: value.clone() });
                Ok(Some(value))
            }
            Stmt::Expr(expr) => {
                let value = self.eval_expr(expr)?;
                Ok(if matches!(value, SimValue::Unit) { None } else { Some(value) })
            }
            Stmt::If(if_stmt) => {
                let cond = self.eval_expr(&if_stmt.condition)?;
                let taken = self.is_truthy(&cond);
                self.trace.push(TraceEvent::Branch { condition: cond, taken });
                if taken {
                    self.exec_stmts(&if_stmt.then_branch)
                } else if let Some(else_branch) = &if_stmt.else_branch {
                    self.exec_stmts(else_branch)
                } else {
                    Ok(None)
                }
            }
            Stmt::For(for_stmt) => {
                let iterable = self.eval_expr(&for_stmt.iterable)?;
                let items = match &iterable {
                    SimValue::Array(items) => items.clone(),
                    _ => vec![iterable],
                };
                for item in items.iter().take(10) {
                    self.bind_pattern(&for_stmt.pattern, item.clone());
                    if let Some(value) = self.exec_stmts(&for_stmt.body)? {
                        match value {
                            SimValue::LoopBreak(label)
                                if label.as_ref().is_none_or(|label| for_stmt.label.as_ref() == Some(label)) =>
                            {
                                break;
                            }
                            SimValue::LoopContinue(label)
                                if label.as_ref().is_none_or(|label| for_stmt.label.as_ref() == Some(label)) =>
                            {
                                continue;
                            }
                            value => return Ok(Some(value)),
                        }
                    }
                }
                Ok(None)
            }
            Stmt::While(while_stmt) => {
                for _ in 0..100 {
                    self.bump_steps()?;
                    let cond = self.eval_expr(&while_stmt.condition)?;
                    if !self.is_truthy(&cond) {
                        break;
                    }
                    if let Some(value) = self.exec_stmts(&while_stmt.body)? {
                        match value {
                            SimValue::LoopBreak(label)
                                if label.as_ref().is_none_or(|label| while_stmt.label.as_ref() == Some(label)) =>
                            {
                                break;
                            }
                            SimValue::LoopContinue(label)
                                if label.as_ref().is_none_or(|label| while_stmt.label.as_ref() == Some(label)) =>
                            {
                                continue;
                            }
                            value => return Ok(Some(value)),
                        }
                    }
                }
                Ok(None)
            }
            Stmt::Break(control) => Ok(Some(SimValue::LoopBreak(control.label.clone()))),
            Stmt::Continue(control) => Ok(Some(SimValue::LoopContinue(control.label.clone()))),
            Stmt::Borrow(borrow_stmt) => {
                let root = self
                    .env
                    .get(&borrow_stmt.root)
                    .cloned()
                    .ok_or_else(|| SimulateError::UndefinedVariable { name: borrow_stmt.root.clone() })?;
                let previous = self.env.insert(borrow_stmt.binding.clone(), root);
                let result = self.exec_stmts(&borrow_stmt.body);
                if let Some(previous) = previous {
                    self.env.insert(borrow_stmt.binding.clone(), previous);
                } else {
                    self.env.remove(&borrow_stmt.binding);
                }
                result
            }
        }
    }

    fn finish_entry_flow(&self, flow: Option<SimValue>) -> Result<SimValue, SimulateError> {
        match flow.unwrap_or(SimValue::Unit) {
            SimValue::LoopBreak(label) => Err(SimulateError::Unsupported {
                description: format!("break{} escaped its loop", label.map_or(String::new(), |label| format!(" {label}"))),
            }),
            SimValue::LoopContinue(label) => Err(SimulateError::Unsupported {
                description: format!("continue{} escaped its loop", label.map_or(String::new(), |label| format!(" {label}"))),
            }),
            value => Ok(value),
        }
    }

    fn eval_expr(&mut self, expr: &Expr) -> Result<SimValue, SimulateError> {
        self.bump_steps()?;

        match expr {
            Expr::Integer(n) => Ok(SimValue::Integer(*n)),
            Expr::Bool(b) => Ok(SimValue::Bool(*b)),
            Expr::String(s) => Ok(SimValue::String(s.clone())),
            Expr::ByteString(bytes) => Ok(SimValue::String(format!("0x{}", crate::hex_encode(bytes)))),
            Expr::Identifier(name) => {
                self.env.get(name).cloned().ok_or_else(|| SimulateError::UndefinedVariable { name: name.clone() })
            }
            Expr::Binary(bin) => {
                let left = self.eval_expr(&bin.left)?;
                let right = self.eval_expr(&bin.right)?;
                self.eval_binary(&bin.op, &left, &right)
            }
            Expr::Unary(unary) => {
                let value = self.eval_expr(&unary.expr)?;
                self.eval_unary(&unary.op, &value)
            }
            Expr::Call(call) => self.eval_call(call),
            Expr::FieldAccess(access) => {
                let obj = self.eval_expr(&access.expr)?;
                match &obj {
                    SimValue::Struct { fields, .. } => fields
                        .iter()
                        .find(|(n, _)| n == &access.field)
                        .map(|(_, v)| v.clone())
                        .ok_or_else(|| SimulateError::UndefinedVariable { name: access.field.clone() }),
                    _ => Ok(SimValue::Simulated { ty: "field".to_string(), description: format!("{}.{}", obj, access.field) }),
                }
            }
            Expr::Index(index) => {
                let obj = self.eval_expr(&index.expr)?;
                let idx = self.eval_expr(&index.index)?;
                match (&obj, &idx) {
                    (SimValue::Array(items), SimValue::Integer(i)) => usize::try_from(*i)
                        .ok()
                        .and_then(|index| items.get(index).cloned())
                        .ok_or_else(|| SimulateError::UndefinedVariable { name: format!("[{}]", i) }),
                    _ => Ok(SimValue::Simulated { ty: "index".to_string(), description: format!("{}[{}]", obj, idx) }),
                }
            }
            Expr::Create(create) => {
                self.has_cell_ops = true;
                let fields: Vec<(String, String)> = create
                    .fields
                    .iter()
                    .map(|(name, expr)| {
                        let value = self
                            .eval_expr(expr)
                            .unwrap_or_else(|_| SimValue::Simulated { ty: "unknown".to_string(), description: "...".to_string() });
                        (name.clone(), value.to_string())
                    })
                    .collect();
                self.trace.push(TraceEvent::Create { ty: create.ty.clone(), fields: fields.clone() });
                Ok(SimValue::Simulated { ty: create.ty.clone(), description: "created cell".to_string() })
            }
            Expr::Consume(consume) => {
                self.has_cell_ops = true;
                let value = self.eval_expr(&consume.expr)?;
                let desc = value.to_string();
                self.trace.push(TraceEvent::Consume { description: desc.clone() });
                Ok(SimValue::Simulated { ty: "consumed".to_string(), description: desc })
            }
            Expr::Destroy(destroy) => {
                self.has_cell_ops = true;
                let value = self.eval_expr(&destroy.expr)?;
                self.trace.push(TraceEvent::Destroy { description: value.to_string() });
                Ok(SimValue::Unit)
            }
            Expr::ReadRef(read_ref) => {
                self.has_cell_ops = true;
                self.trace.push(TraceEvent::ReadRef { ty: read_ref.ty.clone() });
                Ok(SimValue::Simulated { ty: read_ref.ty.clone(), description: "read_ref cell dep".to_string() })
            }
            Expr::Claim(claim) => {
                self.has_cell_ops = true;
                let value = self.eval_expr(&claim.receipt)?;
                self.trace.push(TraceEvent::Claim { description: value.to_string() });
                Ok(SimValue::Simulated { ty: "claimed".to_string(), description: "claim".to_string() })
            }
            Expr::Settle(settle) => {
                self.has_cell_ops = true;
                let value = self.eval_expr(&settle.expr)?;
                self.trace.push(TraceEvent::Settle { description: value.to_string() });
                Ok(SimValue::Simulated { ty: "settled".to_string(), description: "settle".to_string() })
            }
            Expr::CreateUnique(_) | Expr::ReplaceUnique(_) => {
                self.has_cell_ops = true;
                Ok(SimValue::Simulated { ty: "unique".to_string(), description: "identity-aware".to_string() })
            }
            Expr::Assert(assert) => {
                let cond = self.eval_expr(&assert.condition)?;
                let msg = self.eval_expr(&assert.message)?;
                self.trace.push(TraceEvent::Assert { condition: cond.clone(), message: msg.to_string() });
                if !self.is_truthy(&cond) {
                    let error = crate::runtime_errors::CellScriptRuntimeError::AssertionFailed;
                    Err(SimulateError::RuntimeError { code: error.code(), name: error.name().to_string() })
                } else {
                    Ok(SimValue::Unit)
                }
            }
            Expr::Require(require) => {
                let cond = self.eval_expr(&require.condition)?;
                self.trace.push(TraceEvent::Assert { condition: cond.clone(), message: "require failed".to_string() });
                if !self.is_truthy(&cond) {
                    let error = crate::runtime_errors::CellScriptRuntimeError::AssertionFailed;
                    Err(SimulateError::RuntimeError { code: error.code(), name: error.name().to_string() })
                } else {
                    Ok(SimValue::Unit)
                }
            }
            Expr::Block(stmts) => {
                let result = self.exec_stmts(stmts)?;
                Ok(result.unwrap_or(SimValue::Unit))
            }
            Expr::Tuple(exprs) => {
                let values: Vec<SimValue> = exprs.iter().map(|e| self.eval_expr(e)).collect::<Result<_, _>>()?;
                Ok(SimValue::Tuple(values))
            }
            Expr::Array(exprs) => {
                let values: Vec<SimValue> = exprs.iter().map(|e| self.eval_expr(e)).collect::<Result<_, _>>()?;
                Ok(SimValue::Array(values))
            }
            Expr::If(if_expr) => {
                let cond = self.eval_expr(&if_expr.condition)?;
                let taken = self.is_truthy(&cond);
                if taken {
                    self.eval_expr(&if_expr.then_branch)
                } else {
                    self.eval_expr(&if_expr.else_branch)
                }
            }
            Expr::Cast(cast) => {
                let value = self.eval_expr(&cast.expr)?;
                match &value {
                    SimValue::Integer(n) => Ok(SimValue::Integer(*n)),
                    _ => Ok(value),
                }
            }
            Expr::Range(_range) => Ok(SimValue::Simulated { ty: "range".to_string(), description: "range".to_string() }),
            Expr::StructInit(init) => {
                let fields: Vec<(String, SimValue)> = init
                    .fields
                    .iter()
                    .map(|(name, expr)| {
                        let value = self
                            .eval_expr(expr)
                            .unwrap_or_else(|_| SimValue::Simulated { ty: "unknown".to_string(), description: "...".to_string() });
                        (name.clone(), value)
                    })
                    .collect();
                Ok(SimValue::Struct { name: init.ty.clone(), fields })
            }
            Expr::Match(_match) => Ok(SimValue::Simulated { ty: "match".to_string(), description: "match expression".to_string() }),
            Expr::Assign(assign) => {
                let rhs = self.eval_expr(&assign.value)?;
                let value = match (&assign.op, assign.target.as_ref()) {
                    (AssignOp::AddAssign, Expr::Identifier(name)) => {
                        let previous =
                            self.env.get(name).cloned().ok_or_else(|| SimulateError::UndefinedVariable { name: name.clone() })?;
                        self.eval_binary(&BinaryOp::Add, &previous, &rhs)?
                    }
                    _ => rhs,
                };
                if let Expr::Identifier(name) = assign.target.as_ref() {
                    self.env.insert(name.clone(), value.clone());
                }
                Ok(value)
            }
            Expr::RequireBlock(require_block) => {
                let mut result = Ok(SimValue::Unit);
                for expr in &require_block.expressions {
                    result = self.eval_expr(expr);
                    if result.is_err() {
                        break;
                    }
                }
                result
            }
            Expr::Preserve(preserve) => {
                self.trace.push(TraceEvent::Assert {
                    condition: SimValue::Bool(true),
                    message: format!("preserve {} from {}", preserve.output_name, preserve.input_name),
                });
                Ok(SimValue::Bool(true))
            }
            Expr::ReplaceRelation(relation) => {
                self.trace.push(TraceEvent::Assert {
                    condition: SimValue::Bool(true),
                    message: format!("replace {} -> {}", relation.before, relation.after),
                });
                Ok(SimValue::Bool(true))
            }
            Expr::StdlibCall(call) => {
                let qualified = format!("std::{}::{}", call.namespace, call.name);
                self.trace.push(TraceEvent::Assert { condition: SimValue::Bool(true), message: format!("stdlib: {}", qualified) });
                Ok(SimValue::Bool(true))
            }
        }
    }

    fn eval_binary(&self, op: &BinaryOp, left: &SimValue, right: &SimValue) -> Result<SimValue, SimulateError> {
        match (left, right) {
            (SimValue::Integer(l), SimValue::Integer(r)) => Ok(match op {
                BinaryOp::Add => SimValue::Integer(l.wrapping_add(*r)),
                BinaryOp::Sub => SimValue::Integer(l.wrapping_sub(*r)),
                BinaryOp::Mul => SimValue::Integer(l.wrapping_mul(*r)),
                BinaryOp::Div => {
                    if *r == 0 {
                        SimValue::Simulated { ty: "div_zero".to_string(), description: "division by zero".to_string() }
                    } else {
                        SimValue::Integer(l / r)
                    }
                }
                BinaryOp::Mod => {
                    if *r == 0 {
                        SimValue::Simulated { ty: "mod_zero".to_string(), description: "modulo by zero".to_string() }
                    } else {
                        SimValue::Integer(l % r)
                    }
                }
                BinaryOp::Eq => SimValue::Bool(l == r),
                BinaryOp::Ne => SimValue::Bool(l != r),
                BinaryOp::Lt => SimValue::Bool(l < r),
                BinaryOp::Le => SimValue::Bool(l <= r),
                BinaryOp::Gt => SimValue::Bool(l > r),
                BinaryOp::Ge => SimValue::Bool(l >= r),
                BinaryOp::And => SimValue::Bool(*l != 0 && *r != 0),
                BinaryOp::Or => SimValue::Bool(*l != 0 || *r != 0),
                BinaryOp::BitAnd => SimValue::Integer(l & r),
                BinaryOp::BitOr => SimValue::Integer(l | r),
                BinaryOp::BitXor => SimValue::Integer(l ^ r),
                BinaryOp::Shl if *r < 128 => SimValue::Integer(l << r),
                BinaryOp::Shr if *r < 128 => SimValue::Integer(l >> r),
                BinaryOp::Shl | BinaryOp::Shr => {
                    SimValue::Simulated { ty: "shift_range".to_string(), description: "shift amount out of range".to_string() }
                }
            }),
            (SimValue::Bool(l), SimValue::Bool(r)) => Ok(match op {
                BinaryOp::Eq => SimValue::Bool(l == r),
                BinaryOp::Ne => SimValue::Bool(l != r),
                BinaryOp::And => SimValue::Bool(*l && *r),
                BinaryOp::Or => SimValue::Bool(*l || *r),
                BinaryOp::BitAnd | BinaryOp::BitOr | BinaryOp::BitXor | BinaryOp::Shl | BinaryOp::Shr => {
                    return Err(SimulateError::TypeError { expected: "integer".to_string(), got: "bool".to_string() });
                }
                _ => return Err(SimulateError::TypeError { expected: "integer".to_string(), got: "bool".to_string() }),
            }),
            _ => Ok(SimValue::Simulated { ty: "binary".to_string(), description: format!("{:?} {:?} {:?}", left, op, right) }),
        }
    }

    fn eval_unary(&self, op: &UnaryOp, value: &SimValue) -> Result<SimValue, SimulateError> {
        match (op, value) {
            (UnaryOp::Neg, SimValue::Integer(n)) => Ok(SimValue::Integer(n.wrapping_neg())),
            (UnaryOp::Not, SimValue::Bool(b)) => Ok(SimValue::Bool(!b)),
            (UnaryOp::Not, SimValue::Integer(n)) => Ok(SimValue::Bool(*n == 0)),
            _ => Ok(SimValue::Simulated { ty: "unary".to_string(), description: format!("{:?} {:?}", op, value) }),
        }
    }

    fn eval_call(&mut self, call: &CallExpr) -> Result<SimValue, SimulateError> {
        let func_name = match call.func.as_ref() {
            Expr::Identifier(name) => name.clone(),
            _ => return Ok(SimValue::Simulated { ty: "call".to_string(), description: "indirect call".to_string() }),
        };

        if func_name == "__cellscript_consume_each" {
            return self.eval_bounded_consume_each(call);
        }
        if func_name == "__cellscript_create_each" {
            return self.eval_bounded_create_each(call);
        }

        if matches!(
            func_name.as_str(),
            "witness::count"
                | "witness::byte"
                | "witness::u32_le"
                | "witness::u64_le"
                | "ckb::cell_data_u8"
                | "ckb::cell_data_hash_field"
                | "ckb::cell_lock_size"
                | "ckb::cell_type_size"
                | "ckb::cell_lock_u8"
                | "ckb::cell_type_u8"
                | "ckb::input_since_at"
                | "ckb::input_since_raw"
                | "ckb::exec_cell_dep_u8_args"
                | "ckb::exec_cell_dep_hex4"
                | "ckb::spawn_wait_cell_dep_hex4"
                | "ckb::trusted_exec_cell_dep_u8_args"
                | "ckb::trusted_exec_cell_dep_hex4"
                | "ckb::trusted_spawn_wait_cell_dep_hex4"
                | "ckb::transaction_u32_le"
                | "ckb::transaction_blake2b_gather"
                | "witness::blake2b_select_chunks"
                | "witness::bytes32"
                | "witness::blake2b_span"
                | "ckb::cell_data_blake2b_span"
                | "ckb::raw_transaction_hash_without_cell_deps"
        ) {
            return Err(SimulateError::Unsupported {
                description: format!("{func_name} requires CKB transaction bytes; run a CKB-VM transaction fixture"),
            });
        }

        let args: Vec<SimValue> = call.args.iter().map(|e| self.eval_expr(e)).collect::<Result<_, _>>()?;
        let arg_strs: Vec<String> = args.iter().map(|v| v.to_string()).collect();

        match func_name.as_str() {
            "vec_new" | "Vec::new" => return Ok(SimValue::Array(Vec::new())),
            "push" => {
                return Ok(SimValue::Unit);
            }
            "len" | "length" => {
                if let Some(SimValue::Array(items)) = args.first() {
                    return Ok(SimValue::Integer(items.len() as u128));
                }
                return Ok(SimValue::Simulated { ty: "len".to_string(), description: "len()".to_string() });
            }
            _ => {}
        }

        self.trace.push(TraceEvent::Call { name: func_name.clone(), args: arg_strs });

        if self.functions.contains_key(&func_name) {
            return self.simulate_function(&func_name, &args);
        }

        Ok(SimValue::Simulated { ty: "call_result".to_string(), description: format!("{}()", func_name) })
    }

    fn eval_bounded_consume_each(&mut self, call: &CallExpr) -> Result<SimValue, SimulateError> {
        let [Expr::Identifier(binding), Expr::Identifier(collection_binding), Expr::Block(body)] = call.args.as_slice() else {
            return Err(SimulateError::Unsupported {
                description: "consume_each has an invalid internal bounded-collection shape".to_string(),
            });
        };
        let collection = self
            .env
            .get(collection_binding)
            .cloned()
            .ok_or_else(|| SimulateError::UndefinedVariable { name: collection_binding.clone() })?;
        let SimValue::Array(items) = collection else {
            return Err(SimulateError::TypeError {
                expected: "BoundedCellSet simulation array".to_string(),
                got: collection.to_string(),
            });
        };
        let max_elements = self.bounded_collection_limits.get(collection_binding).copied().ok_or_else(|| {
            SimulateError::Unsupported { description: format!("consume_each collection '{collection_binding}' has no declared bound") }
        })?;
        if items.len() > max_elements {
            let error = crate::runtime_errors::CellScriptRuntimeError::CollectionBoundsInvalid;
            return Err(SimulateError::RuntimeError { code: error.code(), name: error.name().to_string() });
        }

        self.has_cell_ops = true;
        let previous = self.env.get(binding).cloned();
        for item in items {
            self.bump_steps()?;
            self.trace.push(TraceEvent::Consume { description: item.to_string() });
            self.env.insert(binding.clone(), item);
            for stmt in body {
                let flow = match self.exec_stmt(stmt) {
                    Ok(flow) => flow,
                    Err(error) => {
                        self.restore_binding(binding, previous);
                        return Err(error);
                    }
                };
                if flow.is_some_and(|flow| matches!(flow, SimValue::LoopBreak(_) | SimValue::LoopContinue(_))) {
                    self.restore_binding(binding, previous);
                    return Err(SimulateError::Unsupported {
                        description: "loop control is not supported inside consume_each".to_string(),
                    });
                }
            }
        }
        self.restore_binding(binding, previous);
        Ok(SimValue::Unit)
    }

    fn eval_bounded_create_each(&mut self, call: &CallExpr) -> Result<SimValue, SimulateError> {
        let [Expr::Identifier(binding), Expr::Identifier(collection_binding), Expr::Block(body)] = call.args.as_slice() else {
            return Err(SimulateError::Unsupported {
                description: "create_each has an invalid internal bounded-collection shape".to_string(),
            });
        };
        let collection = self
            .env
            .get(collection_binding)
            .cloned()
            .ok_or_else(|| SimulateError::UndefinedVariable { name: collection_binding.clone() })?;
        let SimValue::Array(items) = collection else {
            return Err(SimulateError::TypeError {
                expected: "BoundedList simulation array".to_string(),
                got: collection.to_string(),
            });
        };
        let max_elements = self.bounded_collection_limits.get(collection_binding).copied().ok_or_else(|| {
            SimulateError::Unsupported { description: format!("create_each collection '{collection_binding}' has no declared bound") }
        })?;
        if items.len() > max_elements {
            let error = crate::runtime_errors::CellScriptRuntimeError::CollectionBoundsInvalid;
            return Err(SimulateError::RuntimeError { code: error.code(), name: error.name().to_string() });
        }

        self.has_cell_ops = true;
        let previous = self.env.get(binding).cloned();
        for item in items {
            self.bump_steps()?;
            self.env.insert(binding.clone(), item);
            for stmt in body {
                let flow = match self.exec_stmt(stmt) {
                    Ok(flow) => flow,
                    Err(error) => {
                        self.restore_binding(binding, previous);
                        return Err(error);
                    }
                };
                if flow.is_some_and(|flow| matches!(flow, SimValue::LoopBreak(_) | SimValue::LoopContinue(_))) {
                    self.restore_binding(binding, previous);
                    return Err(SimulateError::Unsupported {
                        description: "loop control is not supported inside create_each".to_string(),
                    });
                }
            }
        }
        self.restore_binding(binding, previous);
        Ok(SimValue::Unit)
    }

    fn restore_binding(&mut self, binding: &str, previous: Option<SimValue>) {
        if let Some(previous) = previous {
            self.env.insert(binding.to_string(), previous);
        } else {
            self.env.remove(binding);
        }
    }

    fn bind_pattern(&mut self, pattern: &BindingPattern, value: SimValue) {
        match pattern {
            BindingPattern::Name(name) => {
                self.trace.push(TraceEvent::Bind { name: name.clone(), value: value.clone() });
                self.env.insert(name.clone(), value);
            }
            BindingPattern::Tuple(patterns) => {
                if let SimValue::Tuple(values) = value {
                    for (p, v) in patterns.iter().zip(values) {
                        self.bind_pattern(p, v);
                    }
                }
            }
            BindingPattern::Wildcard => {}
        }
    }

    fn is_truthy(&self, value: &SimValue) -> bool {
        match value {
            SimValue::Bool(b) => *b,
            SimValue::Integer(n) => *n != 0,
            SimValue::Unit => false,
            SimValue::Simulated { .. } => true,
            _ => true,
        }
    }

    fn bump_steps(&mut self) -> Result<(), SimulateError> {
        self.steps += 1;
        if self.steps > self.max_steps {
            return Err(SimulateError::StepLimitExceeded { max: self.max_steps });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;
    use crate::parser;

    fn parse_module(source: &str) -> Module {
        let tokens = lexer::lex(source).expect("lex");
        parser::parse(&tokens).expect("parse")
    }

    #[test]
    fn simulate_pure_arithmetic_action() {
        let source = r#"
module sim_test

action add(a: u64, b: u64) -> u64 {
    verification
        let result = a + b
        return result
}
"#;
        let module = parse_module(source);
        let mut interp = SimulateInterpreter::new(&module, 1000);
        let result = interp.simulate_action("add", &[SimValue::Integer(3), SimValue::Integer(5)]).unwrap();
        assert_eq!(result.return_value, SimValue::Integer(8));
        assert!(!result.has_cell_ops);
    }

    #[test]
    fn simulate_cell_operation_traces() {
        let source = r#"
module cell_test

resource Token has store, replace, relock, consume, burn {
    amount: u64,
}

action mint(amount: u64) -> u64 {
    verification
        let token = create Token { amount: amount }
        consume token
        return amount
}
"#;
        let module = parse_module(source);
        let mut interp = SimulateInterpreter::new(&module, 1000);
        let result = interp.simulate_action("mint", &[SimValue::Integer(100)]).unwrap();
        assert!(result.has_cell_ops);
        assert!(result.trace.iter().any(|e| matches!(e, TraceEvent::Create { .. })));
        assert!(result.trace.iter().any(|e| matches!(e, TraceEvent::Consume { .. })));
    }

    #[test]
    fn simulate_read_ref_traces() {
        let source = r#"
module ref_test

shared Config {
    threshold: u64,
}

action check() -> u64 {
    verification
        let cfg = read_ref<Config>()
        cfg.threshold
}
"#;
        let module = parse_module(source);
        let mut interp = SimulateInterpreter::new(&module, 1000);
        let result = interp.simulate_action("check", &[]).unwrap();
        assert!(result.has_cell_ops);
        assert!(result.trace.iter().any(|e| matches!(e, TraceEvent::ReadRef { .. })));
    }

    #[test]
    fn simulate_if_branch() {
        let source = r#"
module branch_test

action classify(x: u64) -> u64 {
    verification
        let result = 0
        if x > 10 {
            return 1
        }
        return 0
}
"#;
        let module = parse_module(source);
        let mut interp = SimulateInterpreter::new(&module, 1000);
        let result = interp.simulate_action("classify", &[SimValue::Integer(15)]).unwrap();
        assert_eq!(result.return_value, SimValue::Integer(1));
    }

    fn bounded_token(amount: u128) -> SimValue {
        SimValue::Struct { name: "Token".to_string(), fields: vec![("amount".to_string(), SimValue::Integer(amount))] }
    }

    #[test]
    fn simulate_bounded_consume_each_observes_cardinality_and_every_predicate() {
        let source = r#"
module bounded_sim

resource Token has store, consume { amount: u64 }

action verify(input inputs: BoundedCellSet<Token, 2>, witness minimum: u64) -> u64 {
    verification
        let mut total: u64 = 0
        consume_each token in inputs {
            require token.amount >= minimum
            total += token.amount
        }
        require total <= 4
        return 0
}
"#;
        let module = parse_module(source);
        for values in [vec![], vec![bounded_token(1)], vec![bounded_token(1), bounded_token(2)]] {
            let expected_count = values.len();
            let mut interp = SimulateInterpreter::new(&module, 1000);
            let result = interp
                .simulate_action("verify", &[SimValue::Array(values), SimValue::Integer(1)])
                .expect("0..=N valid elements must simulate");
            assert_eq!(result.return_value, SimValue::Integer(0));
            assert_eq!(
                result.trace.iter().filter(|event| matches!(event, TraceEvent::Consume { .. })).count(),
                expected_count,
                "every selected element must be consumed exactly once"
            );
        }
    }

    #[test]
    fn simulate_bounded_consume_each_fails_closed_above_the_declared_bound() {
        let source = r#"
module bounded_sim

resource Token has store, consume { amount: u64 }

action verify(input inputs: BoundedCellSet<Token, 2>) -> u64 {
    verification
        consume_each token in inputs { require token.amount > 0 }
        return 0
}
"#;
        let module = parse_module(source);
        let mut interp = SimulateInterpreter::new(&module, 1000);
        let error = interp
            .simulate_action("verify", &[SimValue::Array(vec![bounded_token(1), bounded_token(2), bounded_token(3)])])
            .expect_err("N+1 elements must fail closed");
        assert!(matches!(error, SimulateError::RuntimeError { code: 21, .. }));
    }

    #[test]
    fn simulate_bounded_consume_each_rejects_predicate_failure_at_every_position() {
        let source = r#"
module bounded_sim

resource Token has store, consume { amount: u64 }

action verify(input inputs: BoundedCellSet<Token, 3>) -> u64 {
    verification
        consume_each token in inputs { require token.amount > 0 }
        return 0
}
"#;
        let module = parse_module(source);
        for amounts in [[0, 1, 1], [1, 0, 1], [1, 1, 0]] {
            let mut interp = SimulateInterpreter::new(&module, 1000);
            let values = amounts.into_iter().map(bounded_token).collect();
            let error = interp
                .simulate_action("verify", &[SimValue::Array(values)])
                .expect_err("a false predicate must reject the full collection");
            assert!(matches!(error, SimulateError::RuntimeError { code: 5, .. }));
        }
    }

    #[test]
    fn simulate_bounded_create_each_observes_cardinality_and_every_predicate() {
        let source = r#"
module bounded_create_sim

struct Plan { amount: u64 }
resource Token has store, consume { amount: u64 }

action mint(witness plans: BoundedList<Plan, 2>, witness minimum: u64) -> u64 {
    verification
        create_each plan in plans {
            require plan.amount >= minimum
            create Token { amount: plan.amount }
        }
        return 0
}
"#;
        let module = parse_module(source);
        for values in [vec![], vec![bounded_token(1)], vec![bounded_token(1), bounded_token(2)]] {
            let expected_count = values.len();
            let mut interp = SimulateInterpreter::new(&module, 1000);
            let result = interp
                .simulate_action("mint", &[SimValue::Array(values), SimValue::Integer(1)])
                .expect("0..=N valid plans must simulate");
            assert_eq!(result.return_value, SimValue::Integer(0));
            assert_eq!(
                result.trace.iter().filter(|event| matches!(event, TraceEvent::Create { .. })).count(),
                expected_count,
                "every plan must create exactly one output"
            );
        }
    }

    #[test]
    fn simulate_bounded_create_each_fails_closed_above_the_declared_bound() {
        let source = r#"
module bounded_create_sim

struct Plan { amount: u64 }
resource Token has store, consume { amount: u64 }

action mint(witness plans: BoundedList<Plan, 2>) -> u64 {
    verification
        create_each plan in plans { create Token { amount: plan.amount } }
        return 0
}
"#;
        let module = parse_module(source);
        let mut interp = SimulateInterpreter::new(&module, 1000);
        let error = interp
            .simulate_action("mint", &[SimValue::Array(vec![bounded_token(1), bounded_token(2), bounded_token(3)])])
            .expect_err("N+1 plans must fail closed");
        assert!(matches!(error, SimulateError::RuntimeError { code: 21, .. }));
    }

    #[test]
    fn simulate_bounded_create_each_rejects_predicate_failure_at_every_position() {
        let source = r#"
module bounded_create_sim

struct Plan { amount: u64 }
resource Token has store, consume { amount: u64 }

action mint(witness plans: BoundedList<Plan, 3>) -> u64 {
    verification
        create_each plan in plans {
            require plan.amount > 0
            create Token { amount: plan.amount }
        }
        return 0
}
"#;
        let module = parse_module(source);
        for amounts in [[0, 1, 1], [1, 0, 1], [1, 1, 0]] {
            let mut interp = SimulateInterpreter::new(&module, 1000);
            let values = amounts.into_iter().map(bounded_token).collect();
            let error =
                interp.simulate_action("mint", &[SimValue::Array(values)]).expect_err("a false predicate must reject the full plan");
            assert!(matches!(error, SimulateError::RuntimeError { code: 5, .. }));
        }
    }

    #[test]
    fn simulate_step_limit() {
        let source = r#"
module limit_test

action infinite() -> u64 {
    verification
        let x = 0
        return x
}
"#;
        let module = parse_module(source);
        let mut interp = SimulateInterpreter::new(&module, 2);
        let result = interp.simulate_action("infinite", &[]);
        match result {
            Ok(r) => assert!(r.steps <= 3),
            Err(SimulateError::StepLimitExceeded { .. }) => {} // ok
            Err(e) => panic!("unexpected error: {}", e),
        }
    }
}
