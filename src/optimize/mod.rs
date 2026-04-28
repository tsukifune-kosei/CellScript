//! AST optimizer for CellScript.
//! The optimizer is intentionally conservative: it only rewrites expressions
//! whose value can be determined from syntax-local constants. Protocol and
//! Cell-state operations are preserved so linear/resource semantics remain
//! visible to type checking, IR lowering, and metadata generation.

use crate::ast::*;
use crate::error::Result;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConstValue {
    U64(u64),
    Bool(bool),
    String(String),
    Bytes(Vec<u8>),
}

/// Optimize a module in place.
pub fn optimize_module(module: &mut Module, level: u8) -> Result<()> {
    Optimizer::new(level).optimize_module(module)
}

/// Syntax-local optimizer.
pub struct Optimizer {
    level: u8,
    scopes: Vec<HashMap<String, ConstValue>>,
    inline_functions: HashMap<String, InlineFunction>,
}

#[derive(Debug, Clone)]
struct InlineFunction {
    params: Vec<String>,
    body: Expr,
}

impl Optimizer {
    pub fn new(level: u8) -> Self {
        Self { level, scopes: vec![HashMap::new()], inline_functions: HashMap::new() }
    }

    pub fn optimize_module(&mut self, module: &mut Module) -> Result<()> {
        if self.level == 0 {
            return Ok(());
        }

        self.seed_top_level_constants(module);
        if self.level >= 1 {
            self.seed_inline_functions(module);
        }

        for item in &mut module.items {
            match item {
                Item::Const(def) => {
                    def.value = self.optimize_expr(&def.value)?;
                    if let Some(value) = self.try_eval_const(&def.value) {
                        self.insert_const(&def.name, value);
                    }
                }
                Item::Action(action) => {
                    action.body = self.with_child_scope(|this| this.optimize_stmts(&action.body))?;
                }
                Item::Function(function) => {
                    function.body = self.with_child_scope(|this| this.optimize_stmts(&function.body))?;
                }
                Item::Lock(lock) => {
                    lock.body = self.with_child_scope(|this| this.optimize_stmts(&lock.body))?;
                }
                Item::Resource(_)
                | Item::Shared(_)
                | Item::Receipt(_)
                | Item::Struct(_)
                | Item::Invariant(_)
                | Item::Enum(_)
                | Item::Use(_) => {}
            }
        }

        if self.level >= 2 {
            eliminate_unused_functions(module);
        }

        Ok(())
    }

    fn optimize_stmts(&mut self, stmts: &[Stmt]) -> Result<Vec<Stmt>> {
        let mut optimized = Vec::new();
        for stmt in stmts {
            optimized.extend(self.optimize_stmt(stmt)?);
        }
        if self.level >= 2 {
            Ok(eliminate_unused_lets(optimized))
        } else {
            Ok(optimized)
        }
    }

    fn optimize_stmt(&mut self, stmt: &Stmt) -> Result<Vec<Stmt>> {
        match stmt {
            Stmt::Let(let_stmt) => Ok(vec![Stmt::Let(LetStmt {
                pattern: let_stmt.pattern.clone(),
                ty: let_stmt.ty.clone(),
                value: {
                    let value = self.optimize_expr(&let_stmt.value)?;
                    if !let_stmt.is_mut {
                        if let BindingPattern::Name(name) = &let_stmt.pattern {
                            if let Some(constant) = self.try_eval_const(&value) {
                                self.insert_const(name, constant);
                            }
                        }
                    }
                    value
                },
                is_mut: let_stmt.is_mut,
                span: let_stmt.span,
            })]),
            Stmt::Expr(expr) => Ok(vec![Stmt::Expr(self.optimize_expr(expr)?)]),
            Stmt::Return(Some(expr)) => Ok(vec![Stmt::Return(Some(self.optimize_expr(expr)?))]),
            Stmt::Return(None) => Ok(vec![Stmt::Return(None)]),
            Stmt::If(if_stmt) => {
                let condition = self.optimize_expr(&if_stmt.condition)?;
                let then_branch = self.with_child_scope(|this| this.optimize_stmts(&if_stmt.then_branch))?;
                let else_branch = if let Some(branch) = &if_stmt.else_branch {
                    Some(self.with_child_scope(|this| this.optimize_stmts(branch))?)
                } else {
                    None
                };

                if let Some(ConstValue::Bool(value)) = self.try_eval_const(&condition) {
                    if value {
                        return Ok(then_branch);
                    }
                    return Ok(else_branch.unwrap_or_default());
                }

                Ok(vec![Stmt::If(IfStmt { condition, then_branch, else_branch, span: if_stmt.span })])
            }
            Stmt::For(for_stmt) => Ok(vec![Stmt::For(ForStmt {
                pattern: for_stmt.pattern.clone(),
                iterable: self.optimize_expr(&for_stmt.iterable)?,
                body: self.with_child_scope(|this| this.optimize_stmts(&for_stmt.body))?,
                span: for_stmt.span,
            })]),
            Stmt::While(while_stmt) => {
                let condition = self.optimize_expr(&while_stmt.condition)?;
                if matches!(self.try_eval_const(&condition), Some(ConstValue::Bool(false))) {
                    return Ok(Vec::new());
                }
                Ok(vec![Stmt::While(WhileStmt {
                    condition,
                    body: self.with_child_scope(|this| this.optimize_stmts(&while_stmt.body))?,
                    span: while_stmt.span,
                })])
            }
        }
    }

    fn optimize_expr(&mut self, expr: &Expr) -> Result<Expr> {
        match expr {
            Expr::Integer(_) | Expr::Bool(_) | Expr::String(_) | Expr::ByteString(_) => Ok(expr.clone()),
            Expr::Identifier(name) => Ok(self.lookup_const(name).map(const_to_expr).unwrap_or_else(|| expr.clone())),
            Expr::Assign(assign) => Ok(Expr::Assign(AssignExpr {
                target: Box::new(self.optimize_assignment_target(&assign.target)?),
                op: assign.op,
                value: Box::new(self.optimize_expr(&assign.value)?),
                span: assign.span,
            })),
            Expr::Binary(bin) => {
                let left = self.optimize_expr(&bin.left)?;
                let right = self.optimize_expr(&bin.right)?;
                if let (Some(left_const), Some(right_const)) = (self.try_eval_const(&left), self.try_eval_const(&right)) {
                    if let Some(value) = fold_binary(bin.op, &left_const, &right_const) {
                        return Ok(const_to_expr(value));
                    }
                }
                if let Some(simplified) = simplify_binary(bin.op, &left, &right) {
                    return Ok(simplified);
                }
                Ok(Expr::Binary(BinaryExpr { op: bin.op, left: Box::new(left), right: Box::new(right), span: bin.span }))
            }
            Expr::Unary(unary) => {
                let inner = self.optimize_expr(&unary.expr)?;
                if let Some(value) = self.try_eval_const(&inner).and_then(|value| fold_unary(unary.op, &value)) {
                    return Ok(const_to_expr(value));
                }
                if unary.op == UnaryOp::Not {
                    if let Expr::Unary(nested) = &inner {
                        if nested.op == UnaryOp::Not {
                            return Ok(*nested.expr.clone());
                        }
                    }
                }
                Ok(Expr::Unary(UnaryExpr { op: unary.op, expr: Box::new(inner), span: unary.span }))
            }
            Expr::Call(call) => {
                let mut args = Vec::with_capacity(call.args.len());
                for arg in &call.args {
                    args.push(self.optimize_expr(arg)?);
                }
                let func = self.optimize_expr(&call.func)?;
                if let Expr::Identifier(name) = &func {
                    if let Some(inlined) = self.inline_call(name, &args)? {
                        return Ok(inlined);
                    }
                }
                Ok(Expr::Call(CallExpr { func: Box::new(func), args, span: call.span }))
            }
            Expr::FieldAccess(field) => Ok(Expr::FieldAccess(FieldAccessExpr {
                expr: Box::new(self.optimize_expr(&field.expr)?),
                field: field.field.clone(),
                span: field.span,
            })),
            Expr::Index(index) => Ok(Expr::Index(IndexExpr {
                expr: Box::new(self.optimize_expr(&index.expr)?),
                index: Box::new(self.optimize_expr(&index.index)?),
                span: index.span,
            })),
            Expr::Create(create) => {
                let mut fields = Vec::with_capacity(create.fields.len());
                for (name, value) in &create.fields {
                    fields.push((name.clone(), self.optimize_expr(value)?));
                }
                let lock = create.lock.as_ref().map(|lock| self.optimize_expr(lock)).transpose()?.map(Box::new);
                Ok(Expr::Create(CreateExpr { ty: create.ty.clone(), fields, lock, span: create.span }))
            }
            Expr::Consume(consume) => {
                Ok(Expr::Consume(ConsumeExpr { expr: Box::new(self.optimize_expr(&consume.expr)?), span: consume.span }))
            }
            Expr::Transfer(transfer) => Ok(Expr::Transfer(TransferExpr {
                expr: Box::new(self.optimize_expr(&transfer.expr)?),
                to: Box::new(self.optimize_expr(&transfer.to)?),
                span: transfer.span,
            })),
            Expr::Destroy(destroy) => {
                Ok(Expr::Destroy(DestroyExpr { expr: Box::new(self.optimize_expr(&destroy.expr)?), span: destroy.span }))
            }
            Expr::ReadRef(_) => Ok(expr.clone()),
            Expr::Claim(claim) => {
                Ok(Expr::Claim(ClaimExpr { receipt: Box::new(self.optimize_expr(&claim.receipt)?), span: claim.span }))
            }
            Expr::Settle(settle) => {
                Ok(Expr::Settle(SettleExpr { expr: Box::new(self.optimize_expr(&settle.expr)?), span: settle.span }))
            }
            Expr::Assert(assert) => Ok(Expr::Assert(AssertExpr {
                condition: Box::new(self.optimize_expr(&assert.condition)?),
                message: Box::new(self.optimize_expr(&assert.message)?),
                span: assert.span,
            })),
            Expr::Require(require) => {
                Ok(Expr::Require(RequireExpr { condition: Box::new(self.optimize_expr(&require.condition)?), span: require.span }))
            }
            Expr::Block(stmts) => Ok(Expr::Block(self.with_child_scope(|this| this.optimize_stmts(stmts))?)),
            Expr::Tuple(items) => {
                let mut optimized = Vec::with_capacity(items.len());
                for item in items {
                    optimized.push(self.optimize_expr(item)?);
                }
                Ok(Expr::Tuple(optimized))
            }
            Expr::Array(items) => {
                let mut optimized = Vec::with_capacity(items.len());
                for item in items {
                    optimized.push(self.optimize_expr(item)?);
                }
                Ok(Expr::Array(optimized))
            }
            Expr::If(if_expr) => {
                let condition = self.optimize_expr(&if_expr.condition)?;
                let then_branch = self.optimize_expr(&if_expr.then_branch)?;
                let else_branch = self.optimize_expr(&if_expr.else_branch)?;
                if let Some(ConstValue::Bool(value)) = self.try_eval_const(&condition) {
                    return Ok(if value { then_branch } else { else_branch });
                }
                Ok(Expr::If(IfExpr {
                    condition: Box::new(condition),
                    then_branch: Box::new(then_branch),
                    else_branch: Box::new(else_branch),
                    span: if_expr.span,
                }))
            }
            Expr::Cast(cast) => {
                Ok(Expr::Cast(CastExpr { expr: Box::new(self.optimize_expr(&cast.expr)?), ty: cast.ty.clone(), span: cast.span }))
            }
            Expr::Range(range) => Ok(Expr::Range(RangeExpr {
                start: Box::new(self.optimize_expr(&range.start)?),
                end: Box::new(self.optimize_expr(&range.end)?),
                span: range.span,
            })),
            Expr::StructInit(init) => {
                let mut fields = Vec::with_capacity(init.fields.len());
                for (name, value) in &init.fields {
                    fields.push((name.clone(), self.optimize_expr(value)?));
                }
                Ok(Expr::StructInit(StructInitExpr { ty: init.ty.clone(), fields, span: init.span }))
            }
            Expr::Match(match_expr) => {
                let expr = self.optimize_expr(&match_expr.expr)?;
                let mut arms = Vec::with_capacity(match_expr.arms.len());
                for arm in &match_expr.arms {
                    arms.push(MatchArm { pattern: arm.pattern.clone(), value: self.optimize_expr(&arm.value)?, span: arm.span });
                }
                Ok(Expr::Match(MatchExpr { expr: Box::new(expr), arms, span: match_expr.span }))
            }
        }
    }

    fn optimize_assignment_target(&mut self, expr: &Expr) -> Result<Expr> {
        match expr {
            Expr::FieldAccess(field) => Ok(Expr::FieldAccess(FieldAccessExpr {
                expr: Box::new(self.optimize_assignment_target(&field.expr)?),
                field: field.field.clone(),
                span: field.span,
            })),
            Expr::Index(index) => Ok(Expr::Index(IndexExpr {
                expr: Box::new(self.optimize_assignment_target(&index.expr)?),
                index: Box::new(self.optimize_expr(&index.index)?),
                span: index.span,
            })),
            Expr::Unary(unary) if unary.op == UnaryOp::Deref => Ok(Expr::Unary(UnaryExpr {
                op: unary.op,
                expr: Box::new(self.optimize_assignment_target(&unary.expr)?),
                span: unary.span,
            })),
            _ => Ok(expr.clone()),
        }
    }

    fn try_eval_const(&self, expr: &Expr) -> Option<ConstValue> {
        match expr {
            Expr::Integer(value) => Some(ConstValue::U64(*value)),
            Expr::Bool(value) => Some(ConstValue::Bool(*value)),
            Expr::String(value) => Some(ConstValue::String(value.clone())),
            Expr::ByteString(value) => Some(ConstValue::Bytes(value.clone())),
            _ => None,
        }
    }

    fn seed_top_level_constants(&mut self, module: &Module) {
        for item in &module.items {
            if let Item::Const(def) = item {
                if let Some(value) = self.try_eval_const(&def.value) {
                    self.insert_const(&def.name, value);
                }
            }
        }
    }

    fn seed_inline_functions(&mut self, module: &Module) {
        for item in &module.items {
            let Item::Function(function) = item else {
                continue;
            };
            if function.params.iter().any(|param| param.is_mut || param.is_ref || param.is_read_ref) {
                continue;
            }
            let Some(body) = inlineable_function_body(&function.body) else {
                continue;
            };
            if !expr_is_pure_inlineable(body) {
                continue;
            }
            self.inline_functions.insert(
                function.name.clone(),
                InlineFunction { params: function.params.iter().map(|param| param.name.clone()).collect(), body: body.clone() },
            );
        }
    }

    fn inline_call(&mut self, name: &str, args: &[Expr]) -> Result<Option<Expr>> {
        let Some(function) = self.inline_functions.get(name).cloned() else {
            return Ok(None);
        };
        if function.params.len() != args.len() {
            return Ok(None);
        }
        let substitutions = function.params.into_iter().zip(args.iter().cloned()).collect::<HashMap<_, _>>();
        let substituted = substitute_expr(&function.body, &substitutions);
        Ok(Some(self.optimize_expr(&substituted)?))
    }

    fn insert_const(&mut self, name: &str, value: ConstValue) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name.to_string(), value);
        }
    }

    fn lookup_const(&self, name: &str) -> Option<ConstValue> {
        self.scopes.iter().rev().find_map(|scope| scope.get(name).cloned())
    }

    fn with_child_scope<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        self.scopes.push(HashMap::new());
        let result = f(self);
        self.scopes.pop();
        result
    }
}

fn inlineable_function_body(body: &[Stmt]) -> Option<&Expr> {
    match body {
        [Stmt::Return(Some(expr))] | [Stmt::Expr(expr)] => Some(expr),
        _ => None,
    }
}

fn fold_binary(op: BinaryOp, left: &ConstValue, right: &ConstValue) -> Option<ConstValue> {
    use ConstValue::*;

    match (op, left, right) {
        (BinaryOp::Add, U64(left), U64(right)) => Some(U64(left.wrapping_add(*right))),
        (BinaryOp::Sub, U64(left), U64(right)) => Some(U64(left.wrapping_sub(*right))),
        (BinaryOp::Mul, U64(left), U64(right)) => Some(U64(left.wrapping_mul(*right))),
        (BinaryOp::Div, U64(_), U64(0)) | (BinaryOp::Mod, U64(_), U64(0)) => None,
        (BinaryOp::Div, U64(left), U64(right)) => Some(U64(left / right)),
        (BinaryOp::Mod, U64(left), U64(right)) => Some(U64(left % right)),
        (BinaryOp::Eq, U64(left), U64(right)) => Some(Bool(left == right)),
        (BinaryOp::Ne, U64(left), U64(right)) => Some(Bool(left != right)),
        (BinaryOp::Lt, U64(left), U64(right)) => Some(Bool(left < right)),
        (BinaryOp::Le, U64(left), U64(right)) => Some(Bool(left <= right)),
        (BinaryOp::Gt, U64(left), U64(right)) => Some(Bool(left > right)),
        (BinaryOp::Ge, U64(left), U64(right)) => Some(Bool(left >= right)),
        (BinaryOp::And, Bool(left), Bool(right)) => Some(Bool(*left && *right)),
        (BinaryOp::Or, Bool(left), Bool(right)) => Some(Bool(*left || *right)),
        (BinaryOp::Eq, Bool(left), Bool(right)) => Some(Bool(left == right)),
        (BinaryOp::Ne, Bool(left), Bool(right)) => Some(Bool(left != right)),
        (BinaryOp::Eq, String(left), String(right)) => Some(Bool(left == right)),
        (BinaryOp::Ne, String(left), String(right)) => Some(Bool(left != right)),
        (BinaryOp::Eq, Bytes(left), Bytes(right)) => Some(Bool(left == right)),
        (BinaryOp::Ne, Bytes(left), Bytes(right)) => Some(Bool(left != right)),
        _ => None,
    }
}

fn fold_unary(op: UnaryOp, value: &ConstValue) -> Option<ConstValue> {
    match (op, value) {
        (UnaryOp::Not, ConstValue::Bool(value)) => Some(ConstValue::Bool(!value)),
        (UnaryOp::Neg, ConstValue::U64(value)) => Some(ConstValue::U64(value.wrapping_neg())),
        _ => None,
    }
}

fn simplify_binary(op: BinaryOp, left: &Expr, right: &Expr) -> Option<Expr> {
    match (op, left, right) {
        (BinaryOp::Add, _, Expr::Integer(0))
        | (BinaryOp::Sub, _, Expr::Integer(0))
        | (BinaryOp::Mul, _, Expr::Integer(1))
        | (BinaryOp::Div, _, Expr::Integer(1)) => Some(left.clone()),
        (BinaryOp::Add, Expr::Integer(0), _) | (BinaryOp::Mul, Expr::Integer(1), _) => Some(right.clone()),
        _ => None,
    }
}

fn const_to_expr(value: ConstValue) -> Expr {
    match value {
        ConstValue::U64(value) => Expr::Integer(value),
        ConstValue::Bool(value) => Expr::Bool(value),
        ConstValue::String(value) => Expr::String(value),
        ConstValue::Bytes(value) => Expr::ByteString(value),
    }
}

fn eliminate_unused_functions(module: &mut Module) {
    let mut reachable = HashSet::new();
    let mut pending = Vec::new();
    for item in &module.items {
        match item {
            Item::Action(action) => collect_call_names_from_stmts(&action.body, &mut pending),
            Item::Lock(lock) => collect_call_names_from_stmts(&lock.body, &mut pending),
            _ => {}
        }
    }

    while let Some(name) = pending.pop() {
        if !reachable.insert(name.clone()) {
            continue;
        }
        if let Some(function) = module.items.iter().find_map(|item| match item {
            Item::Function(function) if function.name == name => Some(function),
            _ => None,
        }) {
            collect_call_names_from_stmts(&function.body, &mut pending);
        }
    }

    module.items.retain(|item| match item {
        Item::Function(function) => reachable.contains(&function.name),
        _ => true,
    });
}

fn eliminate_unused_lets(stmts: Vec<Stmt>) -> Vec<Stmt> {
    let mut used = HashSet::new();
    for stmt in &stmts {
        collect_used_names_from_stmt(stmt, &mut used);
    }

    stmts
        .into_iter()
        .filter(|stmt| match stmt {
            Stmt::Let(let_stmt) if !let_stmt.is_mut && expr_is_pure_inlineable(&let_stmt.value) => match &let_stmt.pattern {
                BindingPattern::Name(name) => used.contains(name),
                BindingPattern::Wildcard => false,
                BindingPattern::Tuple(_) => true,
            },
            _ => true,
        })
        .collect()
}

fn collect_call_names_from_stmts(stmts: &[Stmt], names: &mut Vec<String>) {
    for stmt in stmts {
        collect_call_names_from_stmt(stmt, names);
    }
}

fn collect_call_names_from_stmt(stmt: &Stmt, names: &mut Vec<String>) {
    match stmt {
        Stmt::Let(let_stmt) => collect_call_names_from_expr(&let_stmt.value, names),
        Stmt::Expr(expr) | Stmt::Return(Some(expr)) => collect_call_names_from_expr(expr, names),
        Stmt::Return(None) => {}
        Stmt::If(if_stmt) => {
            collect_call_names_from_expr(&if_stmt.condition, names);
            collect_call_names_from_stmts(&if_stmt.then_branch, names);
            if let Some(branch) = &if_stmt.else_branch {
                collect_call_names_from_stmts(branch, names);
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
    }
}

fn collect_call_names_from_expr(expr: &Expr, names: &mut Vec<String>) {
    match expr {
        Expr::Call(call) => {
            if let Expr::Identifier(name) = call.func.as_ref() {
                names.push(name.clone());
            }
            collect_call_names_from_expr(&call.func, names);
            for arg in &call.args {
                collect_call_names_from_expr(arg, names);
            }
        }
        _ => walk_expr_children_for_calls(expr, names),
    }
}

fn walk_expr_children_for_calls(expr: &Expr, names: &mut Vec<String>) {
    match expr {
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
        Expr::ReadRef(_) => {}
        Expr::Claim(claim) => collect_call_names_from_expr(&claim.receipt, names),
        Expr::Settle(settle) => collect_call_names_from_expr(&settle.expr, names),
        Expr::Assert(assert) => {
            collect_call_names_from_expr(&assert.condition, names);
            collect_call_names_from_expr(&assert.message, names);
        }
        Expr::Require(require) => collect_call_names_from_expr(&require.condition, names),
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
        Expr::Integer(_) | Expr::Bool(_) | Expr::String(_) | Expr::ByteString(_) | Expr::Identifier(_) | Expr::Call(_) => {}
    }
}

fn collect_used_names_from_stmt(stmt: &Stmt, names: &mut HashSet<String>) {
    match stmt {
        Stmt::Let(let_stmt) => collect_used_names_from_expr(&let_stmt.value, names),
        Stmt::Expr(expr) | Stmt::Return(Some(expr)) => collect_used_names_from_expr(expr, names),
        Stmt::Return(None) => {}
        Stmt::If(if_stmt) => {
            collect_used_names_from_expr(&if_stmt.condition, names);
            for stmt in &if_stmt.then_branch {
                collect_used_names_from_stmt(stmt, names);
            }
            if let Some(branch) = &if_stmt.else_branch {
                for stmt in branch {
                    collect_used_names_from_stmt(stmt, names);
                }
            }
        }
        Stmt::For(for_stmt) => {
            collect_used_names_from_expr(&for_stmt.iterable, names);
            for stmt in &for_stmt.body {
                collect_used_names_from_stmt(stmt, names);
            }
        }
        Stmt::While(while_stmt) => {
            collect_used_names_from_expr(&while_stmt.condition, names);
            for stmt in &while_stmt.body {
                collect_used_names_from_stmt(stmt, names);
            }
        }
    }
}

fn collect_used_names_from_expr(expr: &Expr, names: &mut HashSet<String>) {
    if let Expr::Identifier(name) = expr {
        names.insert(name.clone());
        return;
    }
    collect_names_by_walking_expr(expr, names);
}

fn collect_names_by_walking_expr(expr: &Expr, names: &mut HashSet<String>) {
    match expr {
        Expr::Identifier(name) => {
            names.insert(name.clone());
        }
        Expr::Assign(assign) => {
            collect_names_by_walking_expr(&assign.target, names);
            collect_names_by_walking_expr(&assign.value, names);
        }
        Expr::Binary(binary) => {
            collect_names_by_walking_expr(&binary.left, names);
            collect_names_by_walking_expr(&binary.right, names);
        }
        Expr::Unary(unary) => collect_names_by_walking_expr(&unary.expr, names),
        Expr::Call(call) => {
            collect_names_by_walking_expr(&call.func, names);
            for arg in &call.args {
                collect_names_by_walking_expr(arg, names);
            }
        }
        Expr::FieldAccess(field) => collect_names_by_walking_expr(&field.expr, names),
        Expr::Index(index) => {
            collect_names_by_walking_expr(&index.expr, names);
            collect_names_by_walking_expr(&index.index, names);
        }
        Expr::Create(create) => {
            for (_, value) in &create.fields {
                collect_names_by_walking_expr(value, names);
            }
            if let Some(lock) = &create.lock {
                collect_names_by_walking_expr(lock, names);
            }
        }
        Expr::Consume(consume) => collect_names_by_walking_expr(&consume.expr, names),
        Expr::Transfer(transfer) => {
            collect_names_by_walking_expr(&transfer.expr, names);
            collect_names_by_walking_expr(&transfer.to, names);
        }
        Expr::Destroy(destroy) => collect_names_by_walking_expr(&destroy.expr, names),
        Expr::ReadRef(_) => {}
        Expr::Claim(claim) => collect_names_by_walking_expr(&claim.receipt, names),
        Expr::Settle(settle) => collect_names_by_walking_expr(&settle.expr, names),
        Expr::Assert(assert) => {
            collect_names_by_walking_expr(&assert.condition, names);
            collect_names_by_walking_expr(&assert.message, names);
        }
        Expr::Require(require) => collect_names_by_walking_expr(&require.condition, names),
        Expr::Block(stmts) => {
            for stmt in stmts {
                collect_used_names_from_stmt(stmt, names);
            }
        }
        Expr::Tuple(items) | Expr::Array(items) => {
            for item in items {
                collect_names_by_walking_expr(item, names);
            }
        }
        Expr::If(if_expr) => {
            collect_names_by_walking_expr(&if_expr.condition, names);
            collect_names_by_walking_expr(&if_expr.then_branch, names);
            collect_names_by_walking_expr(&if_expr.else_branch, names);
        }
        Expr::Cast(cast) => collect_names_by_walking_expr(&cast.expr, names),
        Expr::Range(range) => {
            collect_names_by_walking_expr(&range.start, names);
            collect_names_by_walking_expr(&range.end, names);
        }
        Expr::StructInit(init) => {
            for (_, value) in &init.fields {
                collect_names_by_walking_expr(value, names);
            }
        }
        Expr::Match(match_expr) => {
            collect_names_by_walking_expr(&match_expr.expr, names);
            for arm in &match_expr.arms {
                collect_names_by_walking_expr(&arm.value, names);
            }
        }
        Expr::Integer(_) | Expr::Bool(_) | Expr::String(_) | Expr::ByteString(_) => {}
    }
}

fn expr_is_pure_inlineable(expr: &Expr) -> bool {
    match expr {
        Expr::Integer(_) | Expr::Bool(_) | Expr::String(_) | Expr::ByteString(_) | Expr::Identifier(_) => true,
        Expr::Binary(binary) => expr_is_pure_inlineable(&binary.left) && expr_is_pure_inlineable(&binary.right),
        Expr::Unary(unary) => expr_is_pure_inlineable(&unary.expr),
        Expr::Call(call) => expr_is_pure_inlineable(&call.func) && call.args.iter().all(expr_is_pure_inlineable),
        Expr::FieldAccess(field) => expr_is_pure_inlineable(&field.expr),
        Expr::Index(index) => expr_is_pure_inlineable(&index.expr) && expr_is_pure_inlineable(&index.index),
        Expr::Tuple(items) | Expr::Array(items) => items.iter().all(expr_is_pure_inlineable),
        Expr::If(if_expr) => {
            expr_is_pure_inlineable(&if_expr.condition)
                && expr_is_pure_inlineable(&if_expr.then_branch)
                && expr_is_pure_inlineable(&if_expr.else_branch)
        }
        Expr::Cast(cast) => expr_is_pure_inlineable(&cast.expr),
        Expr::Range(range) => expr_is_pure_inlineable(&range.start) && expr_is_pure_inlineable(&range.end),
        Expr::StructInit(init) => init.fields.iter().all(|(_, value)| expr_is_pure_inlineable(value)),
        Expr::Block(stmts) => stmts.iter().all(stmt_is_pure_inlineable),
        Expr::Match(match_expr) => {
            expr_is_pure_inlineable(&match_expr.expr) && match_expr.arms.iter().all(|arm| expr_is_pure_inlineable(&arm.value))
        }
        Expr::Assign(_)
        | Expr::Create(_)
        | Expr::Consume(_)
        | Expr::Transfer(_)
        | Expr::Destroy(_)
        | Expr::ReadRef(_)
        | Expr::Claim(_)
        | Expr::Settle(_)
        | Expr::Assert(_)
        | Expr::Require(_) => false,
    }
}

fn stmt_is_pure_inlineable(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Let(let_stmt) => !let_stmt.is_mut && expr_is_pure_inlineable(&let_stmt.value),
        Stmt::Expr(expr) | Stmt::Return(Some(expr)) => expr_is_pure_inlineable(expr),
        Stmt::Return(None) => true,
        Stmt::If(if_stmt) => {
            expr_is_pure_inlineable(&if_stmt.condition)
                && if_stmt.then_branch.iter().all(stmt_is_pure_inlineable)
                && if_stmt.else_branch.as_ref().is_none_or(|branch| branch.iter().all(stmt_is_pure_inlineable))
        }
        Stmt::For(_) | Stmt::While(_) => false,
    }
}

fn substitute_expr(expr: &Expr, substitutions: &HashMap<String, Expr>) -> Expr {
    match expr {
        Expr::Identifier(name) => substitutions.get(name).cloned().unwrap_or_else(|| expr.clone()),
        Expr::Assign(assign) => Expr::Assign(AssignExpr {
            target: Box::new(substitute_expr(&assign.target, substitutions)),
            op: assign.op,
            value: Box::new(substitute_expr(&assign.value, substitutions)),
            span: assign.span,
        }),
        Expr::Binary(binary) => Expr::Binary(BinaryExpr {
            op: binary.op,
            left: Box::new(substitute_expr(&binary.left, substitutions)),
            right: Box::new(substitute_expr(&binary.right, substitutions)),
            span: binary.span,
        }),
        Expr::Unary(unary) => {
            Expr::Unary(UnaryExpr { op: unary.op, expr: Box::new(substitute_expr(&unary.expr, substitutions)), span: unary.span })
        }
        Expr::Call(call) => Expr::Call(CallExpr {
            func: Box::new(substitute_expr(&call.func, substitutions)),
            args: call.args.iter().map(|arg| substitute_expr(arg, substitutions)).collect(),
            span: call.span,
        }),
        Expr::FieldAccess(field) => Expr::FieldAccess(FieldAccessExpr {
            expr: Box::new(substitute_expr(&field.expr, substitutions)),
            field: field.field.clone(),
            span: field.span,
        }),
        Expr::Index(index) => Expr::Index(IndexExpr {
            expr: Box::new(substitute_expr(&index.expr, substitutions)),
            index: Box::new(substitute_expr(&index.index, substitutions)),
            span: index.span,
        }),
        Expr::Tuple(items) => Expr::Tuple(items.iter().map(|item| substitute_expr(item, substitutions)).collect()),
        Expr::Array(items) => Expr::Array(items.iter().map(|item| substitute_expr(item, substitutions)).collect()),
        Expr::If(if_expr) => Expr::If(IfExpr {
            condition: Box::new(substitute_expr(&if_expr.condition, substitutions)),
            then_branch: Box::new(substitute_expr(&if_expr.then_branch, substitutions)),
            else_branch: Box::new(substitute_expr(&if_expr.else_branch, substitutions)),
            span: if_expr.span,
        }),
        Expr::Cast(cast) => {
            Expr::Cast(CastExpr { expr: Box::new(substitute_expr(&cast.expr, substitutions)), ty: cast.ty.clone(), span: cast.span })
        }
        Expr::Range(range) => Expr::Range(RangeExpr {
            start: Box::new(substitute_expr(&range.start, substitutions)),
            end: Box::new(substitute_expr(&range.end, substitutions)),
            span: range.span,
        }),
        Expr::StructInit(init) => Expr::StructInit(StructInitExpr {
            ty: init.ty.clone(),
            fields: init.fields.iter().map(|(name, value)| (name.clone(), substitute_expr(value, substitutions))).collect(),
            span: init.span,
        }),
        Expr::Match(match_expr) => Expr::Match(MatchExpr {
            expr: Box::new(substitute_expr(&match_expr.expr, substitutions)),
            arms: match_expr
                .arms
                .iter()
                .map(|arm| MatchArm {
                    pattern: arm.pattern.clone(),
                    value: substitute_expr(&arm.value, substitutions),
                    span: arm.span,
                })
                .collect(),
            span: match_expr.span,
        }),
        Expr::Require(require) => {
            Expr::Require(RequireExpr { condition: Box::new(substitute_expr(&require.condition, substitutions)), span: require.span })
        }
        Expr::Create(_)
        | Expr::Consume(_)
        | Expr::Transfer(_)
        | Expr::Destroy(_)
        | Expr::ReadRef(_)
        | Expr::Claim(_)
        | Expr::Settle(_)
        | Expr::Assert(_)
        | Expr::Block(_)
        | Expr::Integer(_)
        | Expr::Bool(_)
        | Expr::String(_)
        | Expr::ByteString(_) => expr.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Span;

    #[test]
    fn folds_integer_arithmetic() {
        let mut optimizer = Optimizer::new(1);
        let expr = Expr::Binary(BinaryExpr {
            op: BinaryOp::Add,
            left: Box::new(Expr::Integer(2)),
            right: Box::new(Expr::Integer(3)),
            span: Span::default(),
        });

        assert!(matches!(optimizer.optimize_expr(&expr).unwrap(), Expr::Integer(5)));
    }

    #[test]
    fn folds_boolean_expressions() {
        let mut optimizer = Optimizer::new(1);
        let expr = Expr::Unary(UnaryExpr {
            op: UnaryOp::Not,
            expr: Box::new(Expr::Binary(BinaryExpr {
                op: BinaryOp::And,
                left: Box::new(Expr::Bool(true)),
                right: Box::new(Expr::Bool(false)),
                span: Span::default(),
            })),
            span: Span::default(),
        });

        assert!(matches!(optimizer.optimize_expr(&expr).unwrap(), Expr::Bool(true)));
    }

    #[test]
    fn folds_literal_if_statements_without_touching_cell_ops() {
        let mut module = Module {
            name: "test".to_string(),
            items: vec![Item::Action(ActionDef {
                name: "run".to_string(),
                params: Vec::new(),
                return_type: None,
                body: vec![Stmt::If(IfStmt {
                    condition: Expr::Bool(false),
                    then_branch: vec![Stmt::Expr(Expr::Destroy(DestroyExpr {
                        expr: Box::new(Expr::Identifier("token".to_string())),
                        span: Span::default(),
                    }))],
                    else_branch: Some(vec![Stmt::Expr(Expr::Integer(1))]),
                    span: Span::default(),
                })],
                effect: EffectClass::Pure,
                effect_declared: false,
                scheduler_hint: None,
                doc_comment: None,
                span: Span::default(),
            })],
            span: Span::default(),
        };

        optimize_module(&mut module, 1).unwrap();

        let Item::Action(action) = &module.items[0] else {
            panic!("expected action");
        };
        assert_eq!(action.body.len(), 1);
        assert!(matches!(action.body[0], Stmt::Expr(Expr::Integer(1))));
    }

    #[test]
    fn propagates_constants_inlines_small_functions_and_removes_dead_code() {
        let mut module = Module {
            name: "test".to_string(),
            items: vec![
                Item::Const(ConstDef { name: "STEP".to_string(), ty: Type::U64, value: Expr::Integer(2), span: Span::default() }),
                Item::Function(FnDef {
                    name: "add_step".to_string(),
                    params: vec![Param {
                        name: "x".to_string(),
                        ty: Type::U64,
                        is_mut: false,
                        is_ref: false,
                        is_read_ref: false,
                        source: ParamSource::Default,
                        span: Span::default(),
                    }],
                    return_type: Some(Type::U64),
                    body: vec![Stmt::Return(Some(Expr::Binary(BinaryExpr {
                        op: BinaryOp::Add,
                        left: Box::new(Expr::Identifier("x".to_string())),
                        right: Box::new(Expr::Identifier("STEP".to_string())),
                        span: Span::default(),
                    })))],
                    doc_comment: None,
                    span: Span::default(),
                }),
                Item::Function(FnDef {
                    name: "unused".to_string(),
                    params: Vec::new(),
                    return_type: Some(Type::U64),
                    body: vec![Stmt::Return(Some(Expr::Integer(99)))],
                    doc_comment: None,
                    span: Span::default(),
                }),
                Item::Action(ActionDef {
                    name: "run".to_string(),
                    params: Vec::new(),
                    return_type: Some(Type::U64),
                    body: vec![
                        Stmt::Let(LetStmt {
                            pattern: BindingPattern::Name("unused_local".to_string()),
                            ty: Some(Type::U64),
                            value: Expr::Integer(7),
                            is_mut: false,
                            span: Span::default(),
                        }),
                        Stmt::Return(Some(Expr::Call(CallExpr {
                            func: Box::new(Expr::Identifier("add_step".to_string())),
                            args: vec![Expr::Integer(40)],
                            span: Span::default(),
                        }))),
                    ],
                    effect: EffectClass::Pure,
                    effect_declared: false,
                    scheduler_hint: None,
                    doc_comment: None,
                    span: Span::default(),
                }),
            ],
            span: Span::default(),
        };

        optimize_module(&mut module, 2).unwrap();

        assert!(
            module.items.iter().all(|item| !matches!(item, Item::Function(function) if function.name == "unused")),
            "unused pure helper should be removed"
        );
        let action = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Action(action) => Some(action),
                _ => None,
            })
            .unwrap();
        assert_eq!(action.body.len(), 1, "unused local binding should be removed");
        assert!(matches!(action.body[0], Stmt::Return(Some(Expr::Integer(42)))));
    }
}
