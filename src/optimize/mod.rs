//! AST optimizer for CellScript.
//!
//! The optimizer is intentionally conservative: it only rewrites expressions
//! whose value can be determined from syntax-local constants. Protocol and
//! Cell-state operations are preserved so linear/resource semantics remain
//! visible to type checking, IR lowering, and metadata generation.

use crate::ast::*;
use crate::error::Result;

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
}

impl Optimizer {
    pub fn new(level: u8) -> Self {
        Self { level }
    }

    pub fn optimize_module(&mut self, module: &mut Module) -> Result<()> {
        if self.level == 0 {
            return Ok(());
        }

        for item in &mut module.items {
            match item {
                Item::Const(def) => {
                    def.value = self.optimize_expr(&def.value)?;
                }
                Item::Action(action) => {
                    action.body = self.optimize_stmts(&action.body)?;
                }
                Item::Function(function) => {
                    function.body = self.optimize_stmts(&function.body)?;
                }
                Item::Lock(lock) => {
                    lock.body = self.optimize_stmts(&lock.body)?;
                }
                Item::Resource(_) | Item::Shared(_) | Item::Receipt(_) | Item::Struct(_) | Item::Enum(_) | Item::Use(_) => {}
            }
        }

        Ok(())
    }

    fn optimize_stmts(&mut self, stmts: &[Stmt]) -> Result<Vec<Stmt>> {
        let mut optimized = Vec::new();
        for stmt in stmts {
            optimized.extend(self.optimize_stmt(stmt)?);
        }
        Ok(optimized)
    }

    fn optimize_stmt(&mut self, stmt: &Stmt) -> Result<Vec<Stmt>> {
        match stmt {
            Stmt::Let(let_stmt) => Ok(vec![Stmt::Let(LetStmt {
                pattern: let_stmt.pattern.clone(),
                ty: let_stmt.ty.clone(),
                value: self.optimize_expr(&let_stmt.value)?,
                is_mut: let_stmt.is_mut,
                span: let_stmt.span,
            })]),
            Stmt::Expr(expr) => Ok(vec![Stmt::Expr(self.optimize_expr(expr)?)]),
            Stmt::Return(Some(expr)) => Ok(vec![Stmt::Return(Some(self.optimize_expr(expr)?))]),
            Stmt::Return(None) => Ok(vec![Stmt::Return(None)]),
            Stmt::If(if_stmt) => {
                let condition = self.optimize_expr(&if_stmt.condition)?;
                let then_branch = self.optimize_stmts(&if_stmt.then_branch)?;
                let else_branch = if let Some(branch) = &if_stmt.else_branch { Some(self.optimize_stmts(branch)?) } else { None };

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
                body: self.optimize_stmts(&for_stmt.body)?,
                span: for_stmt.span,
            })]),
            Stmt::While(while_stmt) => {
                let condition = self.optimize_expr(&while_stmt.condition)?;
                if matches!(self.try_eval_const(&condition), Some(ConstValue::Bool(false))) {
                    return Ok(Vec::new());
                }
                Ok(vec![Stmt::While(WhileStmt { condition, body: self.optimize_stmts(&while_stmt.body)?, span: while_stmt.span })])
            }
        }
    }

    fn optimize_expr(&mut self, expr: &Expr) -> Result<Expr> {
        match expr {
            Expr::Integer(_) | Expr::Bool(_) | Expr::String(_) | Expr::ByteString(_) | Expr::Identifier(_) => Ok(expr.clone()),
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
                Ok(Expr::Call(CallExpr { func: Box::new(self.optimize_expr(&call.func)?), args, span: call.span }))
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
            Expr::Block(stmts) => Ok(Expr::Block(self.optimize_stmts(stmts)?)),
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
}
