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
    U128(u128),
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
    // A None entry is a lexical binding, not a missing constant. It prevents
    // a parameter or a nonconstant local from exposing an outer constant.
    scopes: Vec<HashMap<String, Option<ConstValue>>>,
    pure_functions: HashSet<String>,
    inline_functions: HashMap<String, InlineFunction>,
}

#[derive(Debug, Clone)]
struct InlineFunction {
    params: Vec<String>,
    body: Expr,
    constant_only: bool,
}

impl Optimizer {
    pub fn new(level: u8) -> Self {
        Self { level, scopes: vec![HashMap::new()], pure_functions: HashSet::new(), inline_functions: HashMap::new() }
    }

    pub fn optimize_module(&mut self, module: &mut Module) -> Result<()> {
        if self.level == 0 {
            return Ok(());
        }

        self.seed_top_level_constants(module);
        self.seed_pure_functions(module);
        if self.level >= 1 {
            self.seed_inline_functions(module);
        }

        for item in &mut module.items {
            match item {
                Item::Const(def) => {
                    def.value = self.optimize_expr(&def.value)?;
                    if let Some(value) = self.propagatable_const(&def.value, Some(&def.ty)) {
                        self.insert_const(&def.name, value);
                    }
                }
                Item::Action(action) => {
                    action.body = self.optimize_callable_body(&action.params, &action.body)?;
                }
                Item::Function(function) => {
                    function.body = self.optimize_callable_body(&function.params, &function.body)?;
                }
                Item::Lock(lock) => {
                    lock.body = self.optimize_callable_body(&lock.params, &lock.body)?;
                }
                Item::Resource(_)
                | Item::Shared(_)
                | Item::Receipt(_)
                | Item::Struct(_)
                | Item::Flow(_)
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

    fn optimize_callable_body(&mut self, params: &[Param], body: &[Stmt]) -> Result<Vec<Stmt>> {
        self.with_child_scope(|this| {
            for param in params {
                this.shadow_const(&param.name);
            }
            this.optimize_stmts(body)
        })
    }

    fn optimize_stmts(&mut self, stmts: &[Stmt]) -> Result<Vec<Stmt>> {
        let mut optimized = Vec::new();
        for stmt in stmts {
            optimized.extend(self.optimize_stmt(stmt)?);
        }
        if self.level >= 2 {
            Ok(eliminate_unused_lets(optimized, &self.pure_functions))
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
                    self.shadow_binding_pattern(&let_stmt.pattern);
                    if !let_stmt.is_mut
                        && let BindingPattern::Name(name) = &let_stmt.pattern
                        && let Some(constant) = self.propagatable_const(&value, let_stmt.ty.as_ref())
                    {
                        self.insert_const(name, constant);
                    }
                    value
                },
                is_mut: let_stmt.is_mut,
                span: let_stmt.span,
            })]),
            Stmt::Expr(expr) => Ok(vec![Stmt::Expr(self.optimize_expr(expr)?)]),
            Stmt::Return(ReturnStmt { value: Some(expr), span }) => {
                Ok(vec![Stmt::Return(ReturnStmt { value: Some(self.optimize_expr(expr)?), span: *span })])
            }
            Stmt::Return(ReturnStmt { value: None, span }) => Ok(vec![Stmt::Return(ReturnStmt { value: None, span: *span })]),
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
                label: for_stmt.label.clone(),
                pattern: for_stmt.pattern.clone(),
                iterable: self.optimize_expr(&for_stmt.iterable)?,
                body: self.with_child_scope(|this| {
                    this.shadow_binding_pattern(&for_stmt.pattern);
                    this.optimize_stmts(&for_stmt.body)
                })?,
                span: for_stmt.span,
            })]),
            Stmt::While(while_stmt) => {
                let condition = self.optimize_expr(&while_stmt.condition)?;
                if matches!(self.try_eval_const(&condition), Some(ConstValue::Bool(false))) {
                    return Ok(Vec::new());
                }
                Ok(vec![Stmt::While(WhileStmt {
                    label: while_stmt.label.clone(),
                    condition,
                    body: self.with_child_scope(|this| this.optimize_stmts(&while_stmt.body))?,
                    span: while_stmt.span,
                })])
            }
            Stmt::Borrow(borrow_stmt) => Ok(vec![Stmt::Borrow(BorrowStmt {
                root: borrow_stmt.root.clone(),
                path: borrow_stmt.path.clone(),
                binding: borrow_stmt.binding.clone(),
                body: self.with_child_scope(|this| {
                    this.shadow_const(&borrow_stmt.binding);
                    this.optimize_stmts(&borrow_stmt.body)
                })?,
                span: borrow_stmt.span,
            })]),
            Stmt::Break(_) | Stmt::Continue(_) => Ok(vec![stmt.clone()]),
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
                if let (Some(left_const), Some(right_const)) = (self.try_eval_const(&left), self.try_eval_const(&right))
                    && let Some(value) = fold_binary(bin.op, &left_const, &right_const)
                {
                    return Ok(const_to_expr(value));
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
                if unary.op == UnaryOp::Not
                    && let Expr::Unary(nested) = &inner
                    && nested.op == UnaryOp::Not
                {
                    return Ok(*nested.expr.clone());
                }
                Ok(Expr::Unary(UnaryExpr { op: unary.op, expr: Box::new(inner), span: unary.span }))
            }
            Expr::Call(call) => {
                let mut args = Vec::with_capacity(call.args.len());
                for arg in &call.args {
                    args.push(self.optimize_expr(arg)?);
                }
                let func = self.optimize_expr(&call.func)?;
                if let Expr::Identifier(name) = &func
                    && let Some(inlined) = self.inline_call(name, &args)?
                {
                    return Ok(inlined);
                }
                Ok(Expr::Call(CallExpr { func: Box::new(func), type_args: call.type_args.clone(), args, span: call.span }))
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
                Ok(Expr::Create(CreateExpr { target: create.target.clone(), ty: create.ty.clone(), fields, lock, span: create.span }))
            }
            Expr::Consume(consume) => {
                Ok(Expr::Consume(ConsumeExpr { expr: Box::new(self.optimize_expr(&consume.expr)?), span: consume.span }))
            }
            Expr::Destroy(destroy) => Ok(Expr::Destroy(DestroyExpr {
                expr: Box::new(self.optimize_expr(&destroy.expr)?),
                policy: destroy.policy.clone(),
                span: destroy.span,
            })),
            Expr::ReadRef(_) => Ok(expr.clone()),
            Expr::Claim(claim) => {
                Ok(Expr::Claim(ClaimExpr { receipt: Box::new(self.optimize_expr(&claim.receipt)?), span: claim.span }))
            }
            Expr::Settle(settle) => {
                Ok(Expr::Settle(SettleExpr { expr: Box::new(self.optimize_expr(&settle.expr)?), span: settle.span }))
            }
            Expr::CreateUnique(_) | Expr::ReplaceUnique(_) => Ok(expr.clone()),
            Expr::Assert(assert) => Ok(Expr::Assert(AssertExpr {
                condition: Box::new(self.optimize_expr(&assert.condition)?),
                message: Box::new(self.optimize_expr(&assert.message)?),
                span: assert.span,
            })),
            Expr::Require(require) => Ok(Expr::Require(RequireExpr {
                condition: Box::new(self.optimize_expr(&require.condition)?),
                message: require.message.as_ref().map(|message| self.optimize_expr(message)).transpose()?.map(Box::new),
                span: require.span,
            })),
            Expr::RequireBlock(require_block) => {
                let mut optimized = Vec::with_capacity(require_block.expressions.len());
                for expr in &require_block.expressions {
                    optimized.push(self.optimize_expr(expr)?);
                }
                Ok(Expr::RequireBlock(RequireBlockExpr { expressions: optimized, span: require_block.span }))
            }
            Expr::Preserve(preserve) => Ok(Expr::Preserve(preserve.clone())),
            Expr::ReplaceRelation(relation) => Ok(Expr::ReplaceRelation(relation.clone())),
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
                    let value = self.with_child_scope(|this| {
                        this.shadow_match_pattern(&arm.pattern);
                        this.optimize_expr(&arm.value)
                    })?;
                    arms.push(MatchArm { pattern: arm.pattern.clone(), value, span: arm.span });
                }
                Ok(Expr::Match(MatchExpr { expr: Box::new(expr), arms, span: match_expr.span }))
            }
            Expr::StdlibCall(_) => Ok(expr.clone()),
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
            Expr::Integer(value) => Some(u64::try_from(*value).map(ConstValue::U64).unwrap_or(ConstValue::U128(*value))),
            Expr::Bool(value) => Some(ConstValue::Bool(*value)),
            Expr::String(value) => Some(ConstValue::String(value.clone())),
            Expr::ByteString(value) => Some(ConstValue::Bytes(value.clone())),
            _ => None,
        }
    }

    fn seed_top_level_constants(&mut self, module: &Module) {
        for item in &module.items {
            if let Item::Const(def) = item
                && let Some(value) = self.propagatable_const(&def.value, Some(&def.ty))
            {
                self.insert_const(&def.name, value);
            }
        }
    }

    fn seed_inline_functions(&mut self, module: &Module) {
        self.inline_functions.clear();
        // Candidates form an acyclic, module-local closure. A partial helper
        // may be specialized only for literal u64 arguments and only when the
        // entire result becomes a literal. Its checked operations never move
        // into a caller's possibly narrower/wider contextual numeric type.
        loop {
            let mut changed = false;
            for item in &module.items {
                let Item::Function(function) = item else { continue };
                if self.inline_functions.contains_key(&function.name)
                    || !function.type_params.is_empty()
                    || function
                        .params
                        .iter()
                        .any(|param| param.is_mut || param.is_ref || param.is_read_ref || !matches!(param.ty, Type::U64 | Type::Bool))
                    || !matches!(function.return_type, Some(Type::U64 | Type::Bool))
                {
                    continue;
                }
                let Some(body) = inlineable_function_body(&function.body) else {
                    continue;
                };
                let params = function.params.iter().map(|param| param.name.clone()).collect::<Vec<_>>();
                let captures = self.scopes[0]
                    .iter()
                    .filter(|(name, _)| !params.contains(name))
                    .filter_map(|(name, value)| value.clone().map(|value| (name.clone(), const_to_expr(value))))
                    .collect::<HashMap<_, _>>();
                let body = substitute_expr(&body, &captures);
                if !expr_is_closed_inline_candidate(&body, &params, &self.inline_functions) {
                    continue;
                }
                let constant_only =
                    !self.pure_functions.contains(&function.name) || !expr_is_pure_inlineable(&body, &self.pure_functions);
                if constant_only
                    && (function.return_type != Some(Type::U64) || function.params.iter().any(|param| param.ty != Type::U64))
                {
                    continue;
                }
                self.inline_functions.insert(function.name.clone(), InlineFunction { params, body, constant_only });
                changed = true;
            }
            if !changed {
                break;
            }
        }
    }

    fn inline_call(&mut self, name: &str, args: &[Expr]) -> Result<Option<Expr>> {
        let Some(function) = self.inline_functions.get(name).cloned() else {
            return Ok(None);
        };
        // Substitution can discard an unused parameter or duplicate one. Both
        // would change evaluation of a deferred failure or an unresolved call.
        if function.params.len() != args.len() || args.iter().any(|arg| !expr_is_pure_inlineable(arg, &self.pure_functions)) {
            return Ok(None);
        }
        if function.constant_only && args.iter().any(|arg| !matches!(self.try_eval_const(arg), Some(ConstValue::U64(_)))) {
            return Ok(None);
        }
        let substitutions = function.params.into_iter().zip(args.iter().cloned()).collect::<HashMap<_, _>>();
        let substituted = substitute_expr(&function.body, &substitutions);
        let optimized = self.optimize_expr(&substituted)?;
        if function.constant_only && !matches!(self.try_eval_const(&optimized), Some(ConstValue::U64(_))) {
            return Ok(None);
        }
        Ok(Some(optimized))
    }

    fn seed_pure_functions(&mut self, module: &Module) {
        self.pure_functions.clear();
        // The module-local optimizer has no imported callable body/effect
        // proof. Admit only the local call-graph closure of total bodies;
        // unknown, imported, recursive, and deferred calls retain evaluation.
        loop {
            let mut changed = false;
            for item in &module.items {
                let Item::Function(function) = item else { continue };
                if !self.pure_functions.contains(&function.name)
                    && function.params.iter().all(|param| !param.is_mut && !param.is_ref && !param.is_read_ref)
                    && function.body.iter().all(|stmt| stmt_is_pure_inlineable(stmt, &self.pure_functions))
                {
                    self.pure_functions.insert(function.name.clone());
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    fn insert_const(&mut self, name: &str, value: ConstValue) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name.to_string(), Some(value));
        }
    }

    fn lookup_const(&self, name: &str) -> Option<ConstValue> {
        self.scopes.iter().rev().find_map(|scope| scope.get(name)).cloned().flatten()
    }

    fn propagatable_const(&self, expr: &Expr, ty: Option<&Type>) -> Option<ConstValue> {
        let value = self.try_eval_const(expr)?;
        // Replacing a typed local by an untyped literal must not erase its
        // width (notably a narrow shift's bound or signed interpretation).
        match (ty, &value) {
            (None, _)
            | (Some(Type::U64), ConstValue::U64(_))
            | (Some(Type::Bool), ConstValue::Bool(_))
            | (Some(Type::U128), ConstValue::U128(_)) => Some(value),
            _ => None,
        }
    }

    fn shadow_const(&mut self, name: &str) {
        self.scopes.last_mut().expect("optimizer scope").insert(name.to_string(), None);
    }

    fn shadow_binding_pattern(&mut self, pattern: &BindingPattern) {
        match pattern {
            BindingPattern::Name(name) => self.shadow_const(name),
            BindingPattern::Tuple(items) => items.iter().for_each(|item| self.shadow_binding_pattern(item)),
            BindingPattern::Wildcard => {}
        }
    }

    fn shadow_match_pattern(&mut self, pattern: &MatchPattern) {
        match pattern {
            MatchPattern::Binding(name) => self.shadow_const(name),
            MatchPattern::Tuple(items) | MatchPattern::Variant { fields: items, .. } | MatchPattern::Or(items) => {
                items.iter().for_each(|item| self.shadow_match_pattern(item));
            }
            MatchPattern::Struct { fields, .. } => fields.iter().for_each(|(_, item)| self.shadow_match_pattern(item)),
            MatchPattern::Wildcard => {}
        }
    }

    fn with_child_scope<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        self.scopes.push(HashMap::new());
        let result = f(self);
        self.scopes.pop();
        result
    }
}

fn inlineable_function_body(body: &[Stmt]) -> Option<Expr> {
    if let [Stmt::Expr(expr)] = body {
        return Some(expr.clone());
    }
    let (last, prefix) = body.split_last()?;
    let Stmt::Return(ReturnStmt { value: Some(final_value), .. }) = last else {
        return None;
    };
    let mut result = final_value.clone();
    for statement in prefix.iter().rev() {
        let Stmt::If(IfStmt { condition, then_branch, else_branch: None, span }) = statement else {
            return None;
        };
        let [Stmt::Return(ReturnStmt { value: Some(early_value), .. })] = then_branch.as_slice() else {
            return None;
        };
        result = Expr::If(IfExpr {
            condition: Box::new(condition.clone()),
            then_branch: Box::new(early_value.clone()),
            else_branch: Box::new(result),
            span: *span,
        });
    }
    Some(result)
}

fn expr_is_closed_inline_candidate(expr: &Expr, params: &[String], functions: &HashMap<String, InlineFunction>) -> bool {
    let closed = |expr: &Expr| expr_is_closed_inline_candidate(expr, params, functions);
    match expr {
        Expr::Integer(_) | Expr::Bool(_) => true,
        Expr::Identifier(name) => params.contains(name),
        Expr::Binary(binary) => closed(&binary.left) && closed(&binary.right),
        Expr::Unary(unary) => unary.op == UnaryOp::Not && closed(&unary.expr),
        Expr::If(branch) => closed(&branch.condition) && closed(&branch.then_branch) && closed(&branch.else_branch),
        Expr::Call(call) => {
            call.type_args.is_empty()
                && matches!(call.func.as_ref(), Expr::Identifier(name) if functions.contains_key(name))
                && call.args.iter().all(closed)
        }
        // Substitution does not implement alpha-renaming or local type
        // inference. Binding scopes, schema operations and casts stay calls.
        _ => false,
    }
}

fn fold_binary(op: BinaryOp, left: &ConstValue, right: &ConstValue) -> Option<ConstValue> {
    use ConstValue::*;

    match (op, left, right) {
        // Integer literals are optimized before contextual type inference.  If
        // syntax-local arithmetic exceeds u64, leave it for typed lowering:
        // the same literals may be a checked u128 expression rather than a
        // wrapping u64 expression.
        (BinaryOp::Add, U64(left), U64(right)) => left.checked_add(*right).map(U64),
        (BinaryOp::Sub, U64(left), U64(right)) => left.checked_sub(*right).map(U64),
        (BinaryOp::Mul, U64(left), U64(right)) => left.checked_mul(*right).map(U64),
        (BinaryOp::Div, U64(_), U64(0)) | (BinaryOp::Mod, U64(_), U64(0)) => None,
        (BinaryOp::Div, U64(left), U64(right)) => Some(U64(left / right)),
        (BinaryOp::Mod, U64(left), U64(right)) => Some(U64(left % right)),
        (BinaryOp::Eq, U64(left), U64(right)) => Some(Bool(left == right)),
        (BinaryOp::Ne, U64(left), U64(right)) => Some(Bool(left != right)),
        (BinaryOp::Lt, U64(left), U64(right)) => Some(Bool(left < right)),
        (BinaryOp::Le, U64(left), U64(right)) => Some(Bool(left <= right)),
        (BinaryOp::Gt, U64(left), U64(right)) => Some(Bool(left > right)),
        (BinaryOp::Ge, U64(left), U64(right)) => Some(Bool(left >= right)),
        (BinaryOp::BitAnd, U64(left), U64(right)) => Some(U64(left & right)),
        (BinaryOp::BitOr, U64(left), U64(right)) => Some(U64(left | right)),
        (BinaryOp::BitXor, U64(left), U64(right)) => Some(U64(left ^ right)),
        // A u64-sized literal may acquire a u128 context later. Truncating it
        // here can turn a subsequent checked u128 overflow into success.
        (BinaryOp::Shl, U64(left), U64(right)) if *right < 64 && *left <= (u64::MAX >> right) => Some(U64(left << right)),
        (BinaryOp::Shr, U64(left), U64(right)) if *right < 64 => Some(U64(left >> right)),
        // Runtime u128 arithmetic traps on overflow.  Folding must preserve
        // that behavior instead of replacing the expression with a wrapped
        // constant that can pass production code generation.
        (BinaryOp::Add, U128(left), U128(right)) => left.checked_add(*right).map(U128),
        (BinaryOp::Sub, U128(left), U128(right)) => left.checked_sub(*right).map(U128),
        (BinaryOp::Mul, U128(left), U128(right)) => left.checked_mul(*right).map(U128),
        (BinaryOp::Div, U128(_), U128(0)) | (BinaryOp::Mod, U128(_), U128(0)) => None,
        (BinaryOp::Div, U128(left), U128(right)) => Some(U128(left / right)),
        (BinaryOp::Mod, U128(left), U128(right)) => Some(U128(left % right)),
        (BinaryOp::Eq, U128(left), U128(right)) => Some(Bool(left == right)),
        (BinaryOp::Ne, U128(left), U128(right)) => Some(Bool(left != right)),
        (BinaryOp::Lt, U128(left), U128(right)) => Some(Bool(left < right)),
        (BinaryOp::Le, U128(left), U128(right)) => Some(Bool(left <= right)),
        (BinaryOp::Gt, U128(left), U128(right)) => Some(Bool(left > right)),
        (BinaryOp::Ge, U128(left), U128(right)) => Some(Bool(left >= right)),
        (BinaryOp::BitAnd, U128(left), U128(right)) => Some(U128(left & right)),
        (BinaryOp::BitOr, U128(left), U128(right)) => Some(U128(left | right)),
        (BinaryOp::BitXor, U128(left), U128(right)) => Some(U128(left ^ right)),
        (BinaryOp::Shl, U128(left), U64(right)) if *right < 128 => Some(U128(left << right)),
        (BinaryOp::Shr, U128(left), U64(right)) if *right < 128 => Some(U128(left >> right)),
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
        (UnaryOp::Neg, ConstValue::U128(value)) => Some(ConstValue::U128(value.wrapping_neg())),
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
        ConstValue::U64(value) => Expr::Integer(value.into()),
        ConstValue::U128(value) => Expr::Integer(value),
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
            Item::Resource(resource) => collect_call_names_from_validity(resource.validity.as_ref(), &mut pending),
            Item::Shared(shared) => collect_call_names_from_validity(shared.validity.as_ref(), &mut pending),
            Item::Receipt(receipt) => collect_call_names_from_validity(receipt.validity.as_ref(), &mut pending),
            Item::Struct(struct_def) => collect_call_names_from_validity(struct_def.validity.as_ref(), &mut pending),
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

fn collect_call_names_from_validity(validity: Option<&ValidityBlock>, names: &mut Vec<String>) {
    if let Some(validity) = validity {
        for predicate in &validity.predicates {
            collect_call_names_from_expr(predicate, names);
        }
    }
}

fn eliminate_unused_lets(stmts: Vec<Stmt>, pure_functions: &HashSet<String>) -> Vec<Stmt> {
    let mut used = HashSet::new();
    for stmt in &stmts {
        collect_used_names_from_stmt(stmt, &mut used);
    }

    stmts
        .into_iter()
        .filter(|stmt| match stmt {
            Stmt::Let(let_stmt) if !let_stmt.is_mut && expr_is_pure_inlineable(&let_stmt.value, pure_functions) => {
                match &let_stmt.pattern {
                    BindingPattern::Name(name) => used.contains(name),
                    BindingPattern::Wildcard => false,
                    BindingPattern::Tuple(_) => true,
                }
            }
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
        Stmt::Expr(expr) | Stmt::Return(ReturnStmt { value: Some(expr), .. }) => collect_call_names_from_expr(expr, names),
        Stmt::Return(ReturnStmt { value: None, .. }) => {}
        Stmt::Break(_) | Stmt::Continue(_) => {}
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
        Stmt::Borrow(borrow_stmt) => collect_call_names_from_stmts(&borrow_stmt.body, names),
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
        Expr::ReplaceRelation(relation) => {
            for value in relation.value_exprs() {
                walk_expr_children_for_calls(value, names);
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
        Expr::ReadRef(_) => {}
        Expr::Claim(claim) => collect_call_names_from_expr(&claim.receipt, names),
        Expr::Settle(settle) => collect_call_names_from_expr(&settle.expr, names),
        Expr::CreateUnique(_) | Expr::ReplaceUnique(_) => {}
        Expr::Assert(assert) => {
            collect_call_names_from_expr(&assert.condition, names);
            collect_call_names_from_expr(&assert.message, names);
        }
        Expr::Require(require) => {
            collect_call_names_from_expr(&require.condition, names);
            if let Some(message) = &require.message {
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
        Expr::Integer(_)
        | Expr::Bool(_)
        | Expr::String(_)
        | Expr::ByteString(_)
        | Expr::Identifier(_)
        | Expr::Call(_)
        | Expr::StdlibCall(_) => {}
    }
}

fn collect_used_names_from_stmt(stmt: &Stmt, names: &mut HashSet<String>) {
    match stmt {
        Stmt::Let(let_stmt) => collect_used_names_from_expr(&let_stmt.value, names),
        Stmt::Expr(expr) | Stmt::Return(ReturnStmt { value: Some(expr), .. }) => collect_used_names_from_expr(expr, names),
        Stmt::Return(ReturnStmt { value: None, .. }) => {}
        Stmt::Break(_) | Stmt::Continue(_) => {}
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
        Stmt::Borrow(borrow_stmt) => {
            names.insert(borrow_stmt.root.clone());
            for stmt in &borrow_stmt.body {
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
        Expr::ReplaceRelation(relation) => {
            names.insert(relation.before.clone());
            names.insert(relation.after.clone());
            for value in relation.value_exprs() {
                collect_names_by_walking_expr(value, names);
            }
        }
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
        Expr::Destroy(destroy) => collect_names_by_walking_expr(&destroy.expr, names),
        Expr::ReadRef(_) => {}
        Expr::Claim(claim) => collect_names_by_walking_expr(&claim.receipt, names),
        Expr::Settle(settle) => collect_names_by_walking_expr(&settle.expr, names),
        Expr::CreateUnique(_) | Expr::ReplaceUnique(_) => {}
        Expr::Assert(assert) => {
            collect_names_by_walking_expr(&assert.condition, names);
            collect_names_by_walking_expr(&assert.message, names);
        }
        Expr::Require(require) => {
            collect_names_by_walking_expr(&require.condition, names);
            if let Some(message) = &require.message {
                collect_names_by_walking_expr(message, names);
            }
        }
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
        Expr::RequireBlock(require_block) => {
            for expr in &require_block.expressions {
                collect_names_by_walking_expr(expr, names);
            }
        }
        Expr::Preserve(_) => {}
        Expr::Integer(_) | Expr::Bool(_) | Expr::String(_) | Expr::ByteString(_) | Expr::StdlibCall(_) => {}
    }
}

fn expr_is_pure_inlineable(expr: &Expr, pure_functions: &HashSet<String>) -> bool {
    // This is stronger than "no mutation": every admitted evaluation must be
    // safe to discard or duplicate. Checked arithmetic, schema decoding and
    // bounds/conversion checks remain observable even when their value is not.
    let pure = |expr: &Expr| expr_is_pure_inlineable(expr, pure_functions);
    match expr {
        Expr::Integer(_) | Expr::Bool(_) | Expr::String(_) | Expr::ByteString(_) | Expr::Identifier(_) => true,
        // A relation consumes its predecessor and binds its successor; it is
        // never pure-inlineable even when its value is discarded.
        Expr::ReplaceRelation(_) => false,
        Expr::Binary(binary) => {
            matches!(
                binary.op,
                BinaryOp::Lt
                    | BinaryOp::Le
                    | BinaryOp::Gt
                    | BinaryOp::Ge
                    | BinaryOp::And
                    | BinaryOp::Or
                    | BinaryOp::BitAnd
                    | BinaryOp::BitOr
                    | BinaryOp::BitXor
            ) && pure(&binary.left)
                && pure(&binary.right)
        }
        Expr::Unary(unary) => unary.op == UnaryOp::Not && pure(&unary.expr),
        Expr::Call(call) => {
            matches!(call.func.as_ref(), Expr::Identifier(name)
                if crate::ir::IrDeferredRuntimeFeature::from_source_name(name).is_none() && pure_functions.contains(name))
                && call.args.iter().all(pure)
        }
        Expr::Tuple(items) | Expr::Array(items) => items.iter().all(pure),
        Expr::If(if_expr) => pure(&if_expr.condition) && pure(&if_expr.then_branch) && pure(&if_expr.else_branch),
        Expr::FieldAccess(_)
        | Expr::Index(_)
        | Expr::Cast(_)
        | Expr::Range(_)
        | Expr::StructInit(_)
        | Expr::Block(_)
        | Expr::Match(_)
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
        | Expr::StdlibCall(_) => false,
    }
}

fn stmt_is_pure_inlineable(stmt: &Stmt, pure_functions: &HashSet<String>) -> bool {
    let pure = |expr: &Expr| expr_is_pure_inlineable(expr, pure_functions);
    match stmt {
        Stmt::Let(let_stmt) => !let_stmt.is_mut && pure(&let_stmt.value),
        Stmt::Expr(expr) | Stmt::Return(ReturnStmt { value: Some(expr), .. }) => pure(expr),
        Stmt::Return(ReturnStmt { value: None, .. }) => true,
        Stmt::If(if_stmt) => {
            pure(&if_stmt.condition)
                && if_stmt.then_branch.iter().all(|stmt| stmt_is_pure_inlineable(stmt, pure_functions))
                && if_stmt
                    .else_branch
                    .as_ref()
                    .is_none_or(|branch| branch.iter().all(|stmt| stmt_is_pure_inlineable(stmt, pure_functions)))
        }
        Stmt::For(_) | Stmt::While(_) | Stmt::Break(_) | Stmt::Continue(_) | Stmt::Borrow(_) => false,
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
            type_args: call.type_args.clone(),
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
        Expr::Require(require) => Expr::Require(RequireExpr {
            condition: Box::new(substitute_expr(&require.condition, substitutions)),
            message: require.message.as_ref().map(|message| Box::new(substitute_expr(message, substitutions))),
            span: require.span,
        }),
        Expr::RequireBlock(require_block) => Expr::RequireBlock(RequireBlockExpr {
            expressions: require_block.expressions.iter().map(|e| substitute_expr(e, substitutions)).collect(),
            span: require_block.span,
        }),
        Expr::Preserve(preserve) => Expr::Preserve(PreserveExpr {
            output_name: preserve.output_name.clone(),
            input_name: preserve.input_name.clone(),
            fields: preserve.fields.clone(),
            span: preserve.span,
        }),
        Expr::ReplaceRelation(relation) => {
            let lock = match &relation.lock {
                ReplaceLockTreatment::Same => ReplaceLockTreatment::Same,
                ReplaceLockTreatment::Exact(lock) => ReplaceLockTreatment::Exact(Box::new(substitute_expr(lock, substitutions))),
                ReplaceLockTreatment::ExactHash(lock) => {
                    ReplaceLockTreatment::ExactHash(Box::new(substitute_expr(lock, substitutions)))
                }
            };
            let data = match &relation.data {
                ReplaceDataTreatment::Fields(treatments) => ReplaceDataTreatment::Fields(
                    treatments
                        .iter()
                        .map(|treatment| match treatment {
                            ReplaceFieldTreatment::Same(field) => ReplaceFieldTreatment::Same(field.clone()),
                            ReplaceFieldTreatment::Assign(field, value) => {
                                ReplaceFieldTreatment::Assign(field.clone(), substitute_expr(value, substitutions))
                            }
                        })
                        .collect(),
                ),
                ReplaceDataTreatment::SameExcept(assigned) => ReplaceDataTreatment::SameExcept(
                    assigned.iter().map(|(field, value)| (field.clone(), substitute_expr(value, substitutions))).collect(),
                ),
            };
            Expr::ReplaceRelation(ReplaceRelation {
                before: relation.before.clone(),
                after: relation.after.clone(),
                data,
                lock,
                capacity: relation.capacity,
                identity: relation.identity,
                span: relation.span,
            })
        }
        Expr::Create(_)
        | Expr::Consume(_)
        | Expr::Destroy(_)
        | Expr::ReadRef(_)
        | Expr::Claim(_)
        | Expr::Settle(_)
        | Expr::CreateUnique(_)
        | Expr::ReplaceUnique(_)
        | Expr::Assert(_)
        | Expr::Block(_)
        | Expr::Integer(_)
        | Expr::Bool(_)
        | Expr::String(_)
        | Expr::ByteString(_)
        | Expr::StdlibCall(_) => expr.clone(),
    }
}

#[cfg(test)]
mod evaluation_tests;

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
    fn leaves_overflowing_integer_arithmetic_for_contextual_typed_lowering() {
        for (op, left, right) in [
            (BinaryOp::Add, u64::MAX as u128, 1),
            (BinaryOp::Sub, 0, 1),
            (BinaryOp::Mul, u64::MAX as u128, 2),
            (BinaryOp::Add, u128::MAX, u128::MAX),
            (BinaryOp::Sub, u64::MAX as u128 + 1, u128::MAX),
            (BinaryOp::Mul, u128::MAX, u128::MAX),
        ] {
            let mut optimizer = Optimizer::new(1);
            let expr = Expr::Binary(BinaryExpr {
                op,
                left: Box::new(Expr::Integer(left)),
                right: Box::new(Expr::Integer(right)),
                span: Span::default(),
            });

            assert!(
                matches!(optimizer.optimize_expr(&expr).unwrap(), Expr::Binary(_)),
                "overflowing {left:?} {op:?} {right:?} must remain for typed runtime semantics"
            );
        }
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
            interface_templates: Vec::new(),
            visibilities: Default::default(),
            items: vec![Item::Action(ActionDef {
                name: "run".to_string(),
                params: Vec::new(),
                return_type: None,
                outputs: Vec::new(),
                state_edges: Vec::new(),
                body: vec![Stmt::If(IfStmt {
                    condition: Expr::Bool(false),
                    then_branch: vec![Stmt::Expr(Expr::Destroy(DestroyExpr {
                        expr: Box::new(Expr::Identifier("token".to_string())),
                        policy: DestructionPolicy::Default,
                        span: Span::default(),
                    }))],
                    else_branch: Some(vec![Stmt::Expr(Expr::Integer(1))]),
                    span: Span::default(),
                })],
                effect: EffectClass::Pure,
                effect_declared: false,
                scheduler_hint: None,
                next_surface: None,
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
            interface_templates: Vec::new(),
            visibilities: Default::default(),
            items: vec![
                Item::Const(ConstDef { name: "STEP".to_string(), ty: Type::U64, value: Expr::Integer(2), span: Span::default() }),
                Item::Function(FnDef {
                    name: "add_step".to_string(),
                    type_params: Vec::new(),
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
                    body: vec![Stmt::Return(ReturnStmt {
                        value: Some(Expr::Binary(BinaryExpr {
                            op: BinaryOp::Add,
                            left: Box::new(Expr::Identifier("x".to_string())),
                            right: Box::new(Expr::Identifier("STEP".to_string())),
                            span: Span::default(),
                        })),
                        span: Span::default(),
                    })],
                    effect: EffectClass::Pure,
                    effect_declared: false,
                    doc_comment: None,
                    span: Span::default(),
                }),
                Item::Function(FnDef {
                    name: "unused".to_string(),
                    type_params: Vec::new(),
                    params: Vec::new(),
                    return_type: Some(Type::U64),
                    body: vec![Stmt::Return(ReturnStmt { value: Some(Expr::Integer(99)), span: Span::default() })],
                    effect: EffectClass::Pure,
                    effect_declared: false,
                    doc_comment: None,
                    span: Span::default(),
                }),
                Item::Action(ActionDef {
                    name: "run".to_string(),
                    params: Vec::new(),
                    return_type: Some(Type::U64),
                    outputs: Vec::new(),
                    state_edges: Vec::new(),
                    body: vec![
                        Stmt::Let(LetStmt {
                            pattern: BindingPattern::Name("unused_local".to_string()),
                            ty: Some(Type::U64),
                            value: Expr::Integer(7),
                            is_mut: false,
                            span: Span::default(),
                        }),
                        Stmt::Return(ReturnStmt {
                            value: Some(Expr::Call(CallExpr {
                                func: Box::new(Expr::Identifier("add_step".to_string())),
                                type_args: Vec::new(),
                                args: vec![Expr::Integer(40)],
                                span: Span::default(),
                            })),
                            span: Span::default(),
                        }),
                    ],
                    effect: EffectClass::Pure,
                    effect_declared: false,
                    scheduler_hint: None,
                    next_surface: None,
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
        assert!(matches!(action.body[0], Stmt::Return(ReturnStmt { value: Some(Expr::Integer(42)), .. })));
    }

    #[test]
    fn preserves_discarded_deferred_calls_and_transitive_helpers() {
        let source = r#"
module deferred_optimizer
fn wrapper() -> Hash { return digest() }
fn digest() -> Hash { return env::sighash_all(source::group_input(0)) }
action check() {
    verification
    let _ = env::sighash_all(source::group_input(0))
    let unused_digest = env::sighash_all(source::group_input(0))
    let _ = wrapper()
    let unused_wrapper = wrapper()
}
"#;
        for level in [2, 3, 0, 1] {
            let mut module = crate::frontend::parse(source, crate::CellScriptEdition::Edition2026).unwrap();
            optimize_module(&mut module, level).unwrap();
            let action = module
                .items
                .iter()
                .find_map(|item| match item {
                    Item::Action(action) => Some(action),
                    _ => None,
                })
                .unwrap();
            assert_eq!(action.body.len(), 4, "deferred calls disappeared at optimization level {level}");
            let mut calls = Vec::new();
            collect_call_names_from_stmts(&action.body, &mut calls);
            assert_eq!(calls.iter().filter(|name| *name == "env::sighash_all").count(), 2);
            assert_eq!(calls.iter().filter(|name| *name == "wrapper").count(), 2);
            assert!(module.items.iter().any(|item| matches!(item, Item::Function(function) if function.name == "digest")));
            assert!(module.items.iter().any(|item| matches!(item, Item::Function(function) if function.name == "wrapper")));
        }
    }

    #[test]
    fn inline_substitution_cannot_erase_deferred_argument_evaluation() {
        let source = r#"
module deferred_arguments
fn ignore(value: Hash) -> u64 { return 7 }
fn wrapper() -> Hash { return env::sighash_all(source::group_input(0)) }
action check() -> u64 {
    verification
    let _ = ignore(env::sighash_all(source::group_input(0)))
    return ignore(wrapper())
}
"#;
        for level in 0..=3 {
            let mut module = crate::frontend::parse(source, crate::CellScriptEdition::Edition2026).unwrap();
            optimize_module(&mut module, level).unwrap();
            let action = module
                .items
                .iter()
                .find_map(|item| match item {
                    Item::Action(action) => Some(action),
                    _ => None,
                })
                .unwrap();
            assert_eq!(action.body.len(), 2, "deferred argument disappeared at optimization level {level}");
            let mut calls = Vec::new();
            collect_call_names_from_stmts(&action.body, &mut calls);
            assert!(calls.iter().any(|name| name == "env::sighash_all"));
            assert!(calls.iter().any(|name| name == "wrapper"));
            assert_eq!(calls.iter().filter(|name| *name == "ignore").count(), 2);
        }
    }

    #[test]
    fn imported_callable_effects_are_not_inferred_from_call_syntax() {
        let source = r#"
module imported_effects
use dependency::digest as imported_digest
fn wrapper() -> Hash { return imported_digest() }
fn ignore(value: Hash) -> u64 { return 7 }
action check() {
    verification
    let _ = imported_digest()
    let unused = wrapper()
    let _ = ignore(imported_digest())
}
"#;
        for level in 0..=3 {
            let mut module = crate::frontend::parse(source, crate::CellScriptEdition::Edition2026).unwrap();
            optimize_module(&mut module, level).unwrap();
            let action = module
                .items
                .iter()
                .find_map(|item| match item {
                    Item::Action(action) => Some(action),
                    _ => None,
                })
                .unwrap();
            assert_eq!(action.body.len(), 3, "imported calls disappeared at optimization level {level}");
            let mut calls = Vec::new();
            collect_call_names_from_stmts(&action.body, &mut calls);
            assert_eq!(calls.iter().filter(|name| *name == "imported_digest").count(), 2);
            assert!(calls.iter().any(|name| name == "wrapper"));
            assert!(calls.iter().any(|name| name == "ignore"));
        }
    }

    #[test]
    fn local_pure_call_closure_preserves_transitive_constant_optimizations() {
        let source = r#"
module pure_closure
fn wrapper(value: u64) -> u64 { return add_two(value) }
fn add_two(value: u64) -> u64 { return value + 2 }
action check() -> u64 {
    verification
    let _ = wrapper(40)
    return wrapper(40)
}
"#;
        for level in [2, 3] {
            let mut module = crate::frontend::parse(source, crate::CellScriptEdition::Edition2026).unwrap();
            optimize_module(&mut module, level).unwrap();
            assert!(module.items.iter().all(|item| !matches!(item, Item::Function(_))));
            let action = module
                .items
                .iter()
                .find_map(|item| match item {
                    Item::Action(action) => Some(action),
                    _ => None,
                })
                .unwrap();
            assert_eq!(action.body.len(), 1);
            assert!(matches!(action.body[0], Stmt::Return(ReturnStmt { value: Some(Expr::Integer(42)), .. })));
        }
    }
}
