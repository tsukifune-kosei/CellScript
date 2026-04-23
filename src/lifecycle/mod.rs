use crate::ast::*;
use crate::error::{CompileError, Result, Span};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
struct LifecycleSpec {
    states: Vec<String>,
    state_field_span: Option<Span>,
}

#[derive(Debug, Clone, Default)]
struct ActionLifecycleContext {
    variable_lifecycle_types: HashMap<String, String>,
    consumed_lifecycle_types: HashSet<String>,
    integer_aliases: HashMap<String, u64>,
}

/// Validate all lifecycle declarations and statically check lifecycle-aware
/// creates that can be decided from source.
pub fn check(module: &Module) -> Result<()> {
    let mut checker = LifecycleChecker::new();
    let mut specs = HashMap::new();

    for item in &module.items {
        let Item::Receipt(receipt) = item else {
            continue;
        };
        let Some(lifecycle) = extract_lifecycle(receipt) else {
            continue;
        };

        checker.register_lifecycle(&receipt.name, lifecycle)?;

        let state_field = receipt.fields.iter().find(|field| field.name == "state");
        if let Some(field) = state_field {
            if !is_lifecycle_state_type(&field.ty) {
                return Err(CompileError::new(
                    format!("lifecycle receipt '{}' state field must be an unsigned integer type", receipt.name),
                    field.span,
                ));
            }
        }

        specs.insert(
            receipt.name.clone(),
            LifecycleSpec { states: lifecycle.states.clone(), state_field_span: state_field.map(|field| field.span) },
        );
    }

    for item in &module.items {
        match item {
            Item::Action(action) => {
                let context = action_lifecycle_context(&specs, action);
                validate_stmt_list(&specs, &context, &action.body)?;
                checker.validate_action(action)?;
            }
            Item::Function(function) => {
                validate_stmt_list(&specs, &ActionLifecycleContext::default(), &function.body)?;
            }
            Item::Lock(lock) => validate_stmt_list(&specs, &ActionLifecycleContext::default(), &lock.body)?,
            _ => {}
        }
    }

    Ok(())
}

pub struct LifecycleChecker {
    states: HashMap<String, Vec<String>>,
    transitions: HashMap<String, HashMap<String, Vec<TransitionRule>>>,
}

#[derive(Debug, Clone)]
pub struct TransitionRule {
    pub from: String,
    pub to: String,
    pub condition: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LifecycleInfo {
    pub resource_name: String,
    pub states: Vec<String>,
    pub initial_state: String,
    pub final_states: Vec<String>,
}

impl Default for LifecycleChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl LifecycleChecker {
    pub fn new() -> Self {
        Self { states: HashMap::new(), transitions: HashMap::new() }
    }

    pub fn register_lifecycle(&mut self, resource_name: &str, lifecycle: &Lifecycle) -> Result<()> {
        let states = lifecycle.states.clone();

        if states.len() < 2 {
            return Err(CompileError::new("lifecycle must have at least 2 states", lifecycle.span));
        }

        let mut seen = HashSet::new();
        for state in &states {
            if !seen.insert(state.clone()) {
                return Err(CompileError::new(format!("duplicate lifecycle state: {}", state), lifecycle.span));
            }
        }

        let mut transitions = HashMap::new();
        for i in 0..states.len() - 1 {
            let from = states[i].clone();
            let to = states[i + 1].clone();

            transitions.entry(from.clone()).or_insert_with(Vec::new).push(TransitionRule {
                from: from.clone(),
                to: to.clone(),
                condition: None,
            });
        }

        self.states.insert(resource_name.to_string(), states);
        self.transitions.insert(resource_name.to_string(), transitions);

        Ok(())
    }

    pub fn validate_transition(&self, resource_name: &str, from: &str, to: &str, span: Span) -> Result<()> {
        let states = self
            .states
            .get(resource_name)
            .ok_or_else(|| CompileError::new(format!("resource '{}' has no lifecycle defined", resource_name), span))?;

        if !states.contains(&from.to_string()) {
            return Err(CompileError::new(format!("invalid from state: {}", from), span));
        }

        if !states.contains(&to.to_string()) {
            return Err(CompileError::new(format!("invalid to state: {}", to), span));
        }

        let transitions = self.transitions.get(resource_name).unwrap();

        if let Some(allowed) = transitions.get(from) {
            if allowed.iter().any(|t| t.to == to) {
                return Ok(());
            }
        }

        let from_idx = states.iter().position(|s| s == from).unwrap();
        let to_idx = states.iter().position(|s| s == to).unwrap();

        if to_idx < from_idx {
            return Err(CompileError::new(format!("invalid lifecycle transition: cannot go from '{}' back to '{}'", from, to), span));
        }

        if to_idx == from_idx {
            return Err(CompileError::new(format!("invalid lifecycle transition: '{}' to itself", from), span));
        }

        Err(CompileError::new(format!("invalid lifecycle transition: cannot skip from '{}' to '{}'", from, to), span))
    }

    pub fn get_lifecycle_info(&self, resource_name: &str) -> Option<LifecycleInfo> {
        let states = self.states.get(resource_name)?;

        Some(LifecycleInfo {
            resource_name: resource_name.to_string(),
            states: states.clone(),
            initial_state: states.first()?.clone(),
            final_states: vec![states.last()?.clone()],
        })
    }

    pub fn is_final_state(&self, resource_name: &str, state: &str) -> bool {
        if let Some(states) = self.states.get(resource_name) {
            if let Some(last) = states.last() {
                return last == state;
            }
        }
        false
    }

    pub fn get_next_states(&self, resource_name: &str, from: &str) -> Vec<String> {
        let mut next_states = Vec::new();

        if let Some(transitions) = self.transitions.get(resource_name) {
            if let Some(rules) = transitions.get(from) {
                for rule in rules {
                    next_states.push(rule.to.clone());
                }
            }
        }

        next_states
    }

    pub fn validate_action(&self, action: &ActionDef) -> Result<()> {
        for stmt in &action.body {
            self.validate_stmt(stmt)?;
        }

        Ok(())
    }

    fn validate_stmt(&self, stmt: &Stmt) -> Result<()> {
        match stmt {
            Stmt::Let(let_stmt) => {
                self.validate_expr(&let_stmt.value)?;
            }
            Stmt::Expr(expr) => {
                self.validate_expr(expr)?;
            }
            Stmt::Return(Some(expr)) => {
                self.validate_expr(expr)?;
            }
            Stmt::If(if_stmt) => {
                self.validate_expr(&if_stmt.condition)?;
                for stmt in &if_stmt.then_branch {
                    self.validate_stmt(stmt)?;
                }
                if let Some(else_branch) = &if_stmt.else_branch {
                    for stmt in else_branch {
                        self.validate_stmt(stmt)?;
                    }
                }
            }
            Stmt::For(for_stmt) => {
                self.validate_expr(&for_stmt.iterable)?;
                for stmt in &for_stmt.body {
                    self.validate_stmt(stmt)?;
                }
            }
            Stmt::While(while_stmt) => {
                self.validate_expr(&while_stmt.condition)?;
                for stmt in &while_stmt.body {
                    self.validate_stmt(stmt)?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn validate_expr(&self, expr: &Expr) -> Result<()> {
        match expr {
            Expr::Create(create) => {
                for (_, value) in &create.fields {
                    self.validate_expr(value)?;
                }
                if let Some(lock) = &create.lock {
                    self.validate_expr(lock)?;
                }
            }
            Expr::Assign(assign) => {
                self.validate_expr(&assign.target)?;
                self.validate_expr(&assign.value)?;
            }
            Expr::Consume(consume) => {
                self.validate_expr(&consume.expr)?;
            }
            Expr::Transfer(transfer) => {
                self.validate_expr(&transfer.expr)?;
                self.validate_expr(&transfer.to)?;
            }
            Expr::Destroy(destroy) => {
                self.validate_expr(&destroy.expr)?;
            }
            Expr::Claim(claim) => {
                self.validate_expr(&claim.receipt)?;
            }
            Expr::Settle(settle) => {
                self.validate_expr(&settle.expr)?;
            }
            Expr::Binary(bin) => {
                self.validate_expr(&bin.left)?;
                self.validate_expr(&bin.right)?;
            }
            Expr::Unary(unary) => {
                self.validate_expr(&unary.expr)?;
            }
            Expr::Call(call) => {
                for arg in &call.args {
                    self.validate_expr(arg)?;
                }
            }
            Expr::FieldAccess(field) => {
                self.validate_expr(&field.expr)?;
            }
            Expr::Index(index) => {
                self.validate_expr(&index.expr)?;
                self.validate_expr(&index.index)?;
            }
            Expr::If(if_expr) => {
                self.validate_expr(&if_expr.condition)?;
                self.validate_expr(&if_expr.then_branch)?;
                self.validate_expr(&if_expr.else_branch)?;
            }
            Expr::Cast(cast) => {
                self.validate_expr(&cast.expr)?;
            }
            Expr::Range(range) => {
                self.validate_expr(&range.start)?;
                self.validate_expr(&range.end)?;
            }
            Expr::StructInit(init) => {
                for (_, value) in &init.fields {
                    self.validate_expr(value)?;
                }
            }
            Expr::Match(match_expr) => {
                self.validate_expr(&match_expr.expr)?;
                for arm in &match_expr.arms {
                    self.validate_expr(&arm.value)?;
                }
            }
            Expr::Block(stmts) => {
                for stmt in stmts {
                    self.validate_stmt(stmt)?;
                }
            }
            Expr::Tuple(elems) | Expr::Array(elems) => {
                for elem in elems {
                    self.validate_expr(elem)?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    pub fn generate_validation_code(&self, resource_name: &str) -> String {
        let mut code = String::new();

        code.push_str(&format!("// Lifecycle validation for {}\n", resource_name));

        if let Some(states) = self.states.get(resource_name) {
            code.push_str("// Valid states:\n");
            for (i, state) in states.iter().enumerate() {
                code.push_str(&format!("//   {}: {}\n", i, state));
            }

            code.push_str("\n// Valid transitions:\n");
            if let Some(transitions) = self.transitions.get(resource_name) {
                for (from, rules) in transitions {
                    for rule in rules {
                        code.push_str(&format!("//   {} -> {}\n", from, rule.to));
                    }
                }
            }
        }

        code
    }
}

pub fn extract_lifecycle(receipt: &ReceiptDef) -> Option<&Lifecycle> {
    receipt.lifecycle.as_ref()
}

fn action_lifecycle_context(specs: &HashMap<String, LifecycleSpec>, action: &ActionDef) -> ActionLifecycleContext {
    let mut context = ActionLifecycleContext::default();

    for param in &action.params {
        if let Type::Named(ty) = &param.ty {
            if specs.contains_key(ty) {
                context.variable_lifecycle_types.insert(param.name.clone(), ty.clone());
            }
        }
    }

    collect_lifecycle_stmt_context(specs, &mut context, &action.body);
    context
}

fn collect_lifecycle_stmt_context(specs: &HashMap<String, LifecycleSpec>, context: &mut ActionLifecycleContext, stmts: &[Stmt]) {
    for stmt in stmts {
        match stmt {
            Stmt::Let(let_stmt) => {
                if let BindingPattern::Name(name) = &let_stmt.pattern {
                    if let Some(value) = integer_literal(&let_stmt.value) {
                        context.integer_aliases.insert(name.clone(), value);
                    }
                    if let Some(ty) = lifecycle_expr_type(specs, context, &let_stmt.value) {
                        context.variable_lifecycle_types.insert(name.clone(), ty);
                    } else if let Some(Type::Named(ty)) = &let_stmt.ty {
                        if specs.contains_key(ty) {
                            context.variable_lifecycle_types.insert(name.clone(), ty.clone());
                        }
                    }
                }
                collect_lifecycle_expr_context(specs, context, &let_stmt.value);
            }
            Stmt::Expr(expr) | Stmt::Return(Some(expr)) => collect_lifecycle_expr_context(specs, context, expr),
            Stmt::Return(None) => {}
            Stmt::If(if_stmt) => {
                collect_lifecycle_expr_context(specs, context, &if_stmt.condition);
                collect_lifecycle_stmt_context(specs, context, &if_stmt.then_branch);
                if let Some(else_branch) = &if_stmt.else_branch {
                    collect_lifecycle_stmt_context(specs, context, else_branch);
                }
            }
            Stmt::For(for_stmt) => {
                collect_lifecycle_expr_context(specs, context, &for_stmt.iterable);
                collect_lifecycle_stmt_context(specs, context, &for_stmt.body);
            }
            Stmt::While(while_stmt) => {
                collect_lifecycle_expr_context(specs, context, &while_stmt.condition);
                collect_lifecycle_stmt_context(specs, context, &while_stmt.body);
            }
        }
    }
}

fn collect_lifecycle_expr_context(specs: &HashMap<String, LifecycleSpec>, context: &mut ActionLifecycleContext, expr: &Expr) {
    match expr {
        Expr::Consume(consume) => {
            if let Expr::Identifier(name) = consume.expr.as_ref() {
                if let Some(ty) = context.variable_lifecycle_types.get(name) {
                    context.consumed_lifecycle_types.insert(ty.clone());
                }
            }
            collect_lifecycle_expr_context(specs, context, &consume.expr);
        }
        Expr::Create(create) => {
            for (_, value) in &create.fields {
                collect_lifecycle_expr_context(specs, context, value);
            }
            if let Some(lock) = &create.lock {
                collect_lifecycle_expr_context(specs, context, lock);
            }
        }
        Expr::Assign(assign) => {
            collect_lifecycle_expr_context(specs, context, &assign.target);
            collect_lifecycle_expr_context(specs, context, &assign.value);
        }
        Expr::Binary(bin) => {
            collect_lifecycle_expr_context(specs, context, &bin.left);
            collect_lifecycle_expr_context(specs, context, &bin.right);
        }
        Expr::Unary(unary) => collect_lifecycle_expr_context(specs, context, &unary.expr),
        Expr::Call(call) => {
            collect_lifecycle_expr_context(specs, context, &call.func);
            for arg in &call.args {
                collect_lifecycle_expr_context(specs, context, arg);
            }
        }
        Expr::FieldAccess(field) => collect_lifecycle_expr_context(specs, context, &field.expr),
        Expr::Index(index) => {
            collect_lifecycle_expr_context(specs, context, &index.expr);
            collect_lifecycle_expr_context(specs, context, &index.index);
        }
        Expr::Transfer(transfer) => {
            collect_lifecycle_expr_context(specs, context, &transfer.expr);
            collect_lifecycle_expr_context(specs, context, &transfer.to);
        }
        Expr::Destroy(destroy) => collect_lifecycle_expr_context(specs, context, &destroy.expr),
        Expr::Claim(claim) => collect_lifecycle_expr_context(specs, context, &claim.receipt),
        Expr::Settle(settle) => collect_lifecycle_expr_context(specs, context, &settle.expr),
        Expr::Assert(assert_expr) => {
            collect_lifecycle_expr_context(specs, context, &assert_expr.condition);
            collect_lifecycle_expr_context(specs, context, &assert_expr.message);
        }
        Expr::Block(stmts) => collect_lifecycle_stmt_context(specs, context, stmts),
        Expr::Tuple(items) | Expr::Array(items) => {
            for item in items {
                collect_lifecycle_expr_context(specs, context, item);
            }
        }
        Expr::If(if_expr) => {
            collect_lifecycle_expr_context(specs, context, &if_expr.condition);
            collect_lifecycle_expr_context(specs, context, &if_expr.then_branch);
            collect_lifecycle_expr_context(specs, context, &if_expr.else_branch);
        }
        Expr::Cast(cast) => collect_lifecycle_expr_context(specs, context, &cast.expr),
        Expr::Range(range) => {
            collect_lifecycle_expr_context(specs, context, &range.start);
            collect_lifecycle_expr_context(specs, context, &range.end);
        }
        Expr::StructInit(init) => {
            for (_, value) in &init.fields {
                collect_lifecycle_expr_context(specs, context, value);
            }
        }
        Expr::Match(match_expr) => {
            collect_lifecycle_expr_context(specs, context, &match_expr.expr);
            for arm in &match_expr.arms {
                collect_lifecycle_expr_context(specs, context, &arm.value);
            }
        }
        Expr::Integer(_) | Expr::Bool(_) | Expr::String(_) | Expr::ByteString(_) | Expr::Identifier(_) | Expr::ReadRef(_) => {}
    }
}

fn lifecycle_expr_type(specs: &HashMap<String, LifecycleSpec>, context: &ActionLifecycleContext, expr: &Expr) -> Option<String> {
    match expr {
        Expr::Identifier(name) => context.variable_lifecycle_types.get(name).cloned(),
        Expr::Create(create) if specs.contains_key(&create.ty) => Some(create.ty.clone()),
        Expr::Cast(cast) => lifecycle_expr_type(specs, context, &cast.expr),
        _ => None,
    }
}

fn validate_stmt_list(specs: &HashMap<String, LifecycleSpec>, context: &ActionLifecycleContext, stmts: &[Stmt]) -> Result<()> {
    for stmt in stmts {
        validate_lifecycle_stmt(specs, context, stmt)?;
    }
    Ok(())
}

fn validate_lifecycle_stmt(specs: &HashMap<String, LifecycleSpec>, context: &ActionLifecycleContext, stmt: &Stmt) -> Result<()> {
    match stmt {
        Stmt::Let(let_stmt) => validate_lifecycle_expr(specs, context, &let_stmt.value),
        Stmt::Expr(expr) => validate_lifecycle_expr(specs, context, expr),
        Stmt::Return(Some(expr)) => validate_lifecycle_expr(specs, context, expr),
        Stmt::Return(None) => Ok(()),
        Stmt::If(if_stmt) => {
            validate_lifecycle_expr(specs, context, &if_stmt.condition)?;
            validate_stmt_list(specs, context, &if_stmt.then_branch)?;
            if let Some(else_branch) = &if_stmt.else_branch {
                validate_stmt_list(specs, context, else_branch)?;
            }
            Ok(())
        }
        Stmt::For(for_stmt) => {
            validate_lifecycle_expr(specs, context, &for_stmt.iterable)?;
            validate_stmt_list(specs, context, &for_stmt.body)
        }
        Stmt::While(while_stmt) => {
            validate_lifecycle_expr(specs, context, &while_stmt.condition)?;
            validate_stmt_list(specs, context, &while_stmt.body)
        }
    }
}

fn validate_lifecycle_expr(specs: &HashMap<String, LifecycleSpec>, context: &ActionLifecycleContext, expr: &Expr) -> Result<()> {
    match expr {
        Expr::Create(create) => {
            validate_lifecycle_create(specs, context, create)?;
            for (_, value) in &create.fields {
                validate_lifecycle_expr(specs, context, value)?;
            }
            if let Some(lock) = &create.lock {
                validate_lifecycle_expr(specs, context, lock)?;
            }
            Ok(())
        }
        Expr::Assign(assign) => {
            validate_lifecycle_expr(specs, context, &assign.target)?;
            validate_lifecycle_expr(specs, context, &assign.value)
        }
        Expr::Binary(bin) => {
            validate_lifecycle_expr(specs, context, &bin.left)?;
            validate_lifecycle_expr(specs, context, &bin.right)
        }
        Expr::Unary(unary) => validate_lifecycle_expr(specs, context, &unary.expr),
        Expr::Call(call) => {
            validate_lifecycle_expr(specs, context, &call.func)?;
            for arg in &call.args {
                validate_lifecycle_expr(specs, context, arg)?;
            }
            Ok(())
        }
        Expr::FieldAccess(field) => validate_lifecycle_expr(specs, context, &field.expr),
        Expr::Index(index) => {
            validate_lifecycle_expr(specs, context, &index.expr)?;
            validate_lifecycle_expr(specs, context, &index.index)
        }
        Expr::Consume(consume) => validate_lifecycle_expr(specs, context, &consume.expr),
        Expr::Transfer(transfer) => {
            validate_lifecycle_expr(specs, context, &transfer.expr)?;
            validate_lifecycle_expr(specs, context, &transfer.to)
        }
        Expr::Destroy(destroy) => validate_lifecycle_expr(specs, context, &destroy.expr),
        Expr::Claim(claim) => validate_lifecycle_expr(specs, context, &claim.receipt),
        Expr::Settle(settle) => validate_lifecycle_expr(specs, context, &settle.expr),
        Expr::Assert(assert_expr) => {
            validate_lifecycle_expr(specs, context, &assert_expr.condition)?;
            validate_lifecycle_expr(specs, context, &assert_expr.message)
        }
        Expr::Block(stmts) => validate_stmt_list(specs, context, stmts),
        Expr::Tuple(items) | Expr::Array(items) => {
            for item in items {
                validate_lifecycle_expr(specs, context, item)?;
            }
            Ok(())
        }
        Expr::If(if_expr) => {
            validate_lifecycle_expr(specs, context, &if_expr.condition)?;
            validate_lifecycle_expr(specs, context, &if_expr.then_branch)?;
            validate_lifecycle_expr(specs, context, &if_expr.else_branch)
        }
        Expr::Cast(cast) => validate_lifecycle_expr(specs, context, &cast.expr),
        Expr::Range(range) => {
            validate_lifecycle_expr(specs, context, &range.start)?;
            validate_lifecycle_expr(specs, context, &range.end)
        }
        Expr::StructInit(init) => {
            for (_, value) in &init.fields {
                validate_lifecycle_expr(specs, context, value)?;
            }
            Ok(())
        }
        Expr::Match(match_expr) => {
            validate_lifecycle_expr(specs, context, &match_expr.expr)?;
            for arm in &match_expr.arms {
                validate_lifecycle_expr(specs, context, &arm.value)?;
            }
            Ok(())
        }
        Expr::Integer(_) | Expr::Bool(_) | Expr::String(_) | Expr::ByteString(_) | Expr::Identifier(_) | Expr::ReadRef(_) => Ok(()),
    }
}

fn validate_lifecycle_create(
    specs: &HashMap<String, LifecycleSpec>,
    context: &ActionLifecycleContext,
    create: &CreateExpr,
) -> Result<()> {
    let Some(spec) = specs.get(&create.ty) else {
        return Ok(());
    };

    if spec.state_field_span.is_none() {
        return Ok(());
    }

    let Some((_, state_expr)) = create.fields.iter().find(|(name, _)| name == "state") else {
        return Err(CompileError::new(format!("create of lifecycle receipt '{}' must set its state field", create.ty), create.span));
    };

    let updates_existing = context.consumed_lifecycle_types.contains(&create.ty);
    let Some(state_index) = static_integer_value(state_expr, context) else {
        if !updates_existing {
            return Err(CompileError::new(
                format!("initial create of lifecycle receipt '{}' must use statically known initial state index 0", create.ty),
                create.span,
            ));
        }
        return Ok(());
    };

    if state_index as usize >= spec.states.len() {
        return Err(CompileError::new(
            format!("lifecycle state index {} is out of range for '{}' with {} states", state_index, create.ty, spec.states.len()),
            create.span,
        ));
    }

    if updates_existing && state_index == 0 {
        return Err(CompileError::new(
            format!("lifecycle update of '{}' cannot reset to initial state index 0", create.ty),
            create.span,
        ));
    }
    if !updates_existing && state_index != 0 {
        return Err(CompileError::new(
            format!("initial create of lifecycle receipt '{}' must use initial state index 0, got {}", create.ty, state_index),
            create.span,
        ));
    }

    Ok(())
}

fn integer_literal(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Integer(value) => Some(*value),
        Expr::Cast(cast) => integer_literal(&cast.expr),
        _ => None,
    }
}

fn static_integer_value(expr: &Expr, context: &ActionLifecycleContext) -> Option<u64> {
    match expr {
        Expr::Identifier(name) => context.integer_aliases.get(name).copied(),
        _ => integer_literal(expr),
    }
}

fn is_lifecycle_state_type(ty: &Type) -> bool {
    matches!(ty, Type::U8 | Type::U16 | Type::U32 | Type::U64 | Type::U128)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_registration() {
        let mut checker = LifecycleChecker::new();

        let lifecycle =
            Lifecycle { states: vec!["Created".to_string(), "Active".to_string(), "Settled".to_string()], span: Span::default() };

        checker.register_lifecycle("VestingGrant", &lifecycle).unwrap();

        assert!(checker.validate_transition("VestingGrant", "Created", "Active", Span::default()).is_ok());
        assert!(checker.validate_transition("VestingGrant", "Active", "Settled", Span::default()).is_ok());

        assert!(checker.validate_transition("VestingGrant", "Settled", "Active", Span::default()).is_err());
        assert!(checker.validate_transition("VestingGrant", "Created", "Settled", Span::default()).is_err());
    }

    #[test]
    fn test_lifecycle_info() {
        let mut checker = LifecycleChecker::new();

        let lifecycle = Lifecycle {
            states: vec!["Granted".to_string(), "Claimable".to_string(), "FullyClaimed".to_string()],
            span: Span::default(),
        };

        checker.register_lifecycle("Grant", &lifecycle).unwrap();

        let info = checker.get_lifecycle_info("Grant").unwrap();
        assert_eq!(info.initial_state, "Granted");
        assert_eq!(info.final_states, vec!["FullyClaimed"]);
        assert!(checker.is_final_state("Grant", "FullyClaimed"));
        assert!(!checker.is_final_state("Grant", "Granted"));
    }
}
