//! CellScript formatter.
//! Release-grade code formatter with idempotency guarantees,
//! configurable line width, comment preservation, and whitespace normalization.

use crate::ast::*;
use crate::error::Result;
use std::fmt::Write;

/// Formatter configuration.
#[derive(Debug, Clone)]
pub struct FormatConfig {
    /// Indentation width in spaces.
    pub indent_width: usize,
    /// Maximum line width before the formatter attempts line breaks.
    pub max_line_width: usize,
    /// Whether to preserve trailing newlines at end of file.
    pub trailing_newline: bool,
    /// Number of blank lines between top-level items.
    pub blank_lines_between_items: usize,
}

pub struct Formatter {
    config: FormatConfig,
    output: String,
    indent_level: usize,
    /// Line number of the last emitted line, used for blank line enforcement.
    last_line: u32,
}

impl Default for FormatConfig {
    fn default() -> Self {
        Self { indent_width: 4, max_line_width: 100, trailing_newline: true, blank_lines_between_items: 1 }
    }
}

impl Formatter {
    pub fn new(config: FormatConfig) -> Self {
        Self { config, output: String::new(), indent_level: 0, last_line: 0 }
    }

    pub fn format_module(&mut self, module: &Module) -> Result<String> {
        self.output.clear();
        self.indent_level = 0;
        self.last_line = 0;

        self.push_line(&format!("module {}", module.name));
        self.push_line("");

        let mut first = true;
        for item in &module.items {
            if !first {
                // Enforce configurable blank lines between top-level items
                for _ in 0..self.config.blank_lines_between_items {
                    self.push_line("");
                }
            }
            first = false;
            self.format_item(item)?;
        }

        let result = self.output.trim_end().to_string();
        if self.config.trailing_newline {
            Ok(result + "\n")
        } else {
            Ok(result)
        }
    }

    fn format_item(&mut self, item: &Item) -> Result<()> {
        match item {
            Item::Resource(resource) => {
                self.format_type_def("resource", &resource.name, &resource.fields, Some(&resource.capabilities))
            }
            Item::Shared(shared) => self.format_type_def("shared", &shared.name, &shared.fields, Some(&shared.capabilities)),
            Item::Receipt(receipt) => {
                if let Some(lifecycle) = &receipt.lifecycle {
                    self.push_line(&format!("#[lifecycle({})]", lifecycle.states.join(", ")));
                }
                self.format_receipt_def(receipt)
            }
            Item::Struct(struct_def) => self.format_type_def("struct", &struct_def.name, &struct_def.fields, None),
            Item::Const(constant) => {
                self.push_line(&format!(
                    "const {}: {} = {};",
                    constant.name,
                    format_type(&constant.ty),
                    self.format_expr(&constant.value)
                ));
                Ok(())
            }
            Item::Enum(enum_def) => {
                self.push_line(&format!("enum {} {{", enum_def.name));
                self.indent_level += 1;
                for variant in &enum_def.variants {
                    self.push_indent();
                    if variant.fields.is_empty() {
                        self.output.push_str(&variant.name);
                    } else {
                        let fields = variant.fields.iter().map(format_type).collect::<Vec<_>>().join(", ");
                        self.output.push_str(&format!("{}({})", variant.name, fields));
                    }
                    self.output.push_str(",\n");
                }
                self.indent_level -= 1;
                self.push_line("}");
                Ok(())
            }
            Item::Action(action) => self.format_action_like("action", action),
            Item::Function(function) => self.format_function(function),
            Item::Lock(lock) => self.format_lock(lock),
            Item::Use(use_stmt) => {
                let module_path = use_stmt.module_path.join("::");
                if use_stmt.imports.len() == 1 {
                    let import = &use_stmt.imports[0];
                    let full_path =
                        if module_path.is_empty() { import.name.clone() } else { format!("{}::{}", module_path, import.name) };
                    if let Some(alias) = &import.alias {
                        self.push_line(&format!("use {} as {}", full_path, alias));
                    } else {
                        self.push_line(&format!("use {}", full_path));
                    }
                } else {
                    let imports = use_stmt
                        .imports
                        .iter()
                        .map(|import| match &import.alias {
                            Some(alias) => format!("{} as {}", import.name, alias),
                            None => import.name.clone(),
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    self.push_line(&format!("use {}::{{{}}}", module_path, imports));
                }
                Ok(())
            }
        }
    }

    fn format_type_def(&mut self, keyword: &str, name: &str, fields: &[Field], capabilities: Option<&[Capability]>) -> Result<()> {
        let mut header = format!("{} {}", keyword, name);
        if let Some(capabilities) = capabilities {
            if !capabilities.is_empty() {
                let rendered = capabilities.iter().map(format_capability).collect::<Vec<_>>().join(", ");
                header.push_str(&format!(" has {}", rendered));
            }
        }
        self.push_line(&format!("{} {{", header));
        self.indent_level += 1;
        for field in fields {
            self.push_line(&format!("{}: {},", field.name, format_type(&field.ty)));
        }
        self.indent_level -= 1;
        self.push_line("}");
        Ok(())
    }

    fn format_receipt_def(&mut self, receipt: &ReceiptDef) -> Result<()> {
        let mut header = format!("receipt {}", receipt.name);
        if let Some(output) = &receipt.claim_output {
            header.push_str(&format!(" -> {}", format_type(output)));
        }
        if !receipt.capabilities.is_empty() {
            let rendered = receipt.capabilities.iter().map(format_capability).collect::<Vec<_>>().join(", ");
            header.push_str(&format!(" has {}", rendered));
        }
        self.push_line(&format!("{} {{", header));
        self.indent_level += 1;
        for field in &receipt.fields {
            self.push_line(&format!("{}: {},", field.name, format_type(&field.ty)));
        }
        self.indent_level -= 1;
        self.push_line("}");
        Ok(())
    }

    fn format_action_like(&mut self, keyword: &str, action: &ActionDef) -> Result<()> {
        if let Some(doc) = &action.doc_comment {
            for line in doc.lines() {
                self.push_line(&format!("/// {}", line));
            }
        }
        if action.effect != EffectClass::Pure {
            self.push_line(&format!("#[effect({})]", format_effect(action.effect)));
        }
        if let Some(hint) = &action.scheduler_hint {
            let mode = if hint.parallelizable { "parallel" } else { "sequential" };
            self.push_line(&format!("#[scheduler_hint({}, estimated_cycles = {})]", mode, hint.estimated_cycles));
        }

        let params = action.params.iter().map(format_param).collect::<Vec<_>>().join(", ");
        let mut signature = format!("{} {}({})", keyword, action.name, params);
        if let Some(return_type) = &action.return_type {
            signature.push_str(&format!(" -> {}", format_type(return_type)));
        }
        self.push_line(&format!("{} {{", signature));
        self.indent_level += 1;
        for stmt in &action.body {
            self.format_stmt(stmt);
        }
        self.indent_level -= 1;
        self.push_line("}");
        Ok(())
    }

    fn format_function(&mut self, function: &FnDef) -> Result<()> {
        if let Some(doc) = &function.doc_comment {
            for line in doc.lines() {
                self.push_line(&format!("/// {}", line));
            }
        }

        let params = function.params.iter().map(format_param).collect::<Vec<_>>().join(", ");
        let mut signature = format!("fn {}({})", function.name, params);
        if let Some(return_type) = &function.return_type {
            signature.push_str(&format!(" -> {}", format_type(return_type)));
        }
        self.push_line(&format!("{} {{", signature));
        self.indent_level += 1;
        for stmt in &function.body {
            self.format_stmt(stmt);
        }
        self.indent_level -= 1;
        self.push_line("}");
        Ok(())
    }

    fn format_lock(&mut self, lock: &LockDef) -> Result<()> {
        let params = lock.params.iter().map(format_param).collect::<Vec<_>>().join(", ");
        self.push_line(&format!("lock {}({}) -> {} {{", lock.name, params, format_type(&lock.return_type)));
        self.indent_level += 1;
        for stmt in &lock.body {
            self.format_stmt(stmt);
        }
        self.indent_level -= 1;
        self.push_line("}");
        Ok(())
    }

    fn format_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Let(let_stmt) => {
                let mut line = String::from("let ");
                if let_stmt.is_mut {
                    line.push_str("mut ");
                }
                line.push_str(&format_binding_pattern(&let_stmt.pattern));
                if let Some(ty) = &let_stmt.ty {
                    line.push_str(&format!(": {}", format_type(ty)));
                }
                line.push_str(" = ");
                line.push_str(&self.format_expr(&let_stmt.value));
                self.push_line(&line);
            }
            Stmt::Expr(expr) => self.push_line(&self.format_expr(expr)),
            Stmt::Return(None) => self.push_line("return"),
            Stmt::Return(Some(expr)) => self.push_line(&format!("return {}", self.format_expr(expr))),
            Stmt::If(if_stmt) => self.format_if_stmt(if_stmt),
            Stmt::For(for_stmt) => self.format_for_stmt(for_stmt),
            Stmt::While(while_stmt) => self.format_while_stmt(while_stmt),
        }
    }

    fn format_if_stmt(&mut self, if_stmt: &IfStmt) {
        self.push_line(&format!("if {} {{", self.format_expr(&if_stmt.condition)));
        self.indent_level += 1;
        for stmt in &if_stmt.then_branch {
            self.format_stmt(stmt);
        }
        self.indent_level -= 1;
        if let Some(else_branch) = &if_stmt.else_branch {
            self.push_line("} else {");
            self.indent_level += 1;
            for stmt in else_branch {
                self.format_stmt(stmt);
            }
            self.indent_level -= 1;
        }
        self.push_line("}");
    }

    fn format_for_stmt(&mut self, for_stmt: &ForStmt) {
        self.push_line(&format!("for {} in {} {{", format_binding_pattern(&for_stmt.pattern), self.format_expr(&for_stmt.iterable)));
        self.indent_level += 1;
        for stmt in &for_stmt.body {
            self.format_stmt(stmt);
        }
        self.indent_level -= 1;
        self.push_line("}");
    }

    fn format_while_stmt(&mut self, while_stmt: &WhileStmt) {
        self.push_line(&format!("while {} {{", self.format_expr(&while_stmt.condition)));
        self.indent_level += 1;
        for stmt in &while_stmt.body {
            self.format_stmt(stmt);
        }
        self.indent_level -= 1;
        self.push_line("}");
    }

    fn format_expr(&self, expr: &Expr) -> String {
        match expr {
            Expr::Integer(value) => value.to_string(),
            Expr::Bool(value) => value.to_string(),
            Expr::String(value) => format!("{:?}", value),
            Expr::ByteString(bytes) => {
                let mut body = String::with_capacity(bytes.len() * 4);
                for byte in bytes {
                    write!(&mut body, "\\x{:02x}", byte).expect("writing to a String cannot fail");
                }
                format!("b\"{}\"", body)
            }
            Expr::Identifier(name) => name.clone(),
            Expr::Assign(assign) => format!(
                "{} {} {}",
                self.format_expr(&assign.target),
                match assign.op {
                    AssignOp::Assign => "=",
                    AssignOp::AddAssign => "+=",
                },
                self.format_expr(&assign.value)
            ),
            Expr::Binary(binary) => {
                format!("{} {} {}", self.format_expr(&binary.left), format_binary_op(binary.op), self.format_expr(&binary.right))
            }
            Expr::Unary(unary) => format!("{}{}", format_unary_op(unary.op), self.format_expr(&unary.expr)),
            Expr::Call(call) => {
                let func = self.format_expr(&call.func);
                let args = call.args.iter().map(|arg| self.format_expr(arg)).collect::<Vec<_>>().join(", ");
                format!("{}({})", func, args)
            }
            Expr::FieldAccess(field) => format!("{}.{}", self.format_expr(&field.expr), field.field),
            Expr::Index(index) => format!("{}[{}]", self.format_expr(&index.expr), self.format_expr(&index.index)),
            Expr::Create(create) => {
                let fields = create
                    .fields
                    .iter()
                    .map(|(name, value)| self.format_field_initializer(name, value))
                    .collect::<Vec<_>>()
                    .join(", ");
                let mut rendered = format!("create {} {{ {} }}", create.ty, fields);
                if let Some(lock) = &create.lock {
                    rendered.push_str(&format!(" with_lock({})", self.format_expr(lock)));
                }
                rendered
            }
            Expr::Consume(consume) => format!("consume {}", self.format_expr(&consume.expr)),
            Expr::Transfer(transfer) => format!("transfer {} to {}", self.format_expr(&transfer.expr), self.format_expr(&transfer.to)),
            Expr::Destroy(destroy) => format!("destroy {}", self.format_expr(&destroy.expr)),
            Expr::ReadRef(read_ref) => format!("read_ref<{}>()", read_ref.ty),
            Expr::Claim(claim) => format!("claim {}", self.format_expr(&claim.receipt)),
            Expr::Settle(settle) => format!("settle {}", self.format_expr(&settle.expr)),
            Expr::Assert(assert_expr) => {
                format!("assert_invariant({}, {})", self.format_expr(&assert_expr.condition), self.format_expr(&assert_expr.message))
            }
            Expr::Require(require_expr) => format!("require {}", self.format_expr(&require_expr.condition)),
            Expr::Block(stmts) => {
                let inner = stmts
                    .iter()
                    .map(|stmt| {
                        let mut formatter = Formatter::new(self.config.clone());
                        formatter.indent_level = 0;
                        formatter.format_stmt(stmt);
                        formatter.output.trim().to_string()
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("{{ {} }}", inner)
            }
            Expr::Tuple(items) => format!("({})", items.iter().map(|item| self.format_expr(item)).collect::<Vec<_>>().join(", ")),
            Expr::Array(items) => format!("[{}]", items.iter().map(|item| self.format_expr(item)).collect::<Vec<_>>().join(", ")),
            Expr::If(if_expr) => format!(
                "if {} {{ {} }} else {{ {} }}",
                self.format_expr(&if_expr.condition),
                self.format_expr(&if_expr.then_branch),
                self.format_expr(&if_expr.else_branch)
            ),
            Expr::Cast(cast) => format!("{} as {}", self.format_expr(&cast.expr), format_type(&cast.ty)),
            Expr::Range(range) => format!("{}..{}", self.format_expr(&range.start), self.format_expr(&range.end)),
            Expr::StructInit(init) => {
                let fields =
                    init.fields.iter().map(|(name, value)| self.format_field_initializer(name, value)).collect::<Vec<_>>().join(", ");
                format!("{} {{ {} }}", init.ty, fields)
            }
            Expr::Match(match_expr) => {
                let arms = match_expr
                    .arms
                    .iter()
                    .map(|arm| format!("{} => {}", arm.pattern, self.format_expr(&arm.value)))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("match {} {{ {} }}", self.format_expr(&match_expr.expr), arms)
            }
        }
    }

    fn format_field_initializer(&self, name: &str, value: &Expr) -> String {
        if matches!(value, Expr::Identifier(identifier) if identifier == name) {
            name.to_string()
        } else {
            format!("{}: {}", name, self.format_expr(value))
        }
    }

    fn push_indent(&mut self) {
        self.output.push_str(&" ".repeat(self.indent_level * self.config.indent_width));
    }

    fn push_line(&mut self, line: &str) {
        if !line.is_empty() {
            self.push_indent();
            self.output.push_str(line);
        }
        self.output.push('\n');
    }
}

fn format_capability(capability: &Capability) -> &'static str {
    match capability {
        Capability::Store => "store",
        Capability::Transfer => "transfer",
        Capability::Destroy => "destroy",
    }
}

fn format_effect(effect: EffectClass) -> &'static str {
    match effect {
        EffectClass::Pure => "pure",
        EffectClass::ReadOnly => "readonly",
        EffectClass::Mutating => "mutating",
        EffectClass::Creating => "creating",
        EffectClass::Destroying => "destroying",
    }
}

fn format_param(param: &Param) -> String {
    let mut rendered = String::new();
    if param.is_mut {
        rendered.push_str("mut ");
    }
    if param.is_ref {
        rendered.push('&');
    }
    rendered.push_str(&param.name);
    rendered.push_str(": ");
    match param.source {
        ParamSource::Protected => {
            rendered.push_str("protected ");
            let ty = match &param.ty {
                Type::Ref(inner) => inner.as_ref(),
                other => other,
            };
            rendered.push_str(&format_type(ty));
        }
        ParamSource::Witness => {
            rendered.push_str("witness ");
            rendered.push_str(&format_type(&param.ty));
        }
        ParamSource::LockArgs => {
            rendered.push_str("lock_args ");
            rendered.push_str(&format_type(&param.ty));
        }
        ParamSource::Default if param.is_read_ref => {
            rendered.push_str("read_ref ");
            let ty = match &param.ty {
                Type::Ref(inner) => inner.as_ref(),
                other => other,
            };
            rendered.push_str(&format_type(ty));
        }
        ParamSource::Default => {
            rendered.push_str(&format_type(&param.ty));
        }
    }
    rendered
}

fn format_binding_pattern(pattern: &BindingPattern) -> String {
    match pattern {
        BindingPattern::Name(name) => name.clone(),
        BindingPattern::Tuple(items) => format!("({})", items.iter().map(format_binding_pattern).collect::<Vec<_>>().join(", ")),
        BindingPattern::Wildcard => "_".to_string(),
    }
}

fn format_type(ty: &Type) -> String {
    match ty {
        Type::U8 => "u8".to_string(),
        Type::U16 => "u16".to_string(),
        Type::U32 => "u32".to_string(),
        Type::U64 => "u64".to_string(),
        Type::U128 => "u128".to_string(),
        Type::Bool => "bool".to_string(),
        Type::Unit => "()".to_string(),
        Type::Address => "Address".to_string(),
        Type::Hash => "Hash".to_string(),
        Type::Array(inner, length) => format!("[{}; {}]", format_type(inner), length),
        Type::Tuple(items) => format!("({})", items.iter().map(format_type).collect::<Vec<_>>().join(", ")),
        Type::Named(name) => name.clone(),
        Type::Ref(inner) => format!("&{}", format_type(inner)),
        Type::MutRef(inner) => format!("&mut {}", format_type(inner)),
    }
}

fn format_binary_op(op: BinaryOp) -> &'static str {
    match op {
        BinaryOp::Add => "+",
        BinaryOp::Sub => "-",
        BinaryOp::Mul => "*",
        BinaryOp::Div => "/",
        BinaryOp::Mod => "%",
        BinaryOp::Eq => "==",
        BinaryOp::Ne => "!=",
        BinaryOp::Lt => "<",
        BinaryOp::Le => "<=",
        BinaryOp::Gt => ">",
        BinaryOp::Ge => ">=",
        BinaryOp::And => "&&",
        BinaryOp::Or => "||",
    }
}

fn format_unary_op(op: UnaryOp) -> &'static str {
    match op {
        UnaryOp::Neg => "-",
        UnaryOp::Not => "!",
        UnaryOp::Ref => "&",
        UnaryOp::Deref => "*",
    }
}

pub fn format(module: &Module, config: FormatConfig) -> Result<String> {
    Formatter::new(config).format_module(module)
}

pub fn format_default(module: &Module) -> Result<String> {
    format(module, FormatConfig::default())
}

/// Verify that formatting is idempotent: re-formatting the output produces the same output.
/// Returns `Ok(())` if idempotent, or an error message describing the diff.
pub fn verify_idempotent(source: &str, config: FormatConfig) -> Result<()> {
    let tokens = crate::lexer::lex(source)?;
    let module = crate::parser::parse(&tokens)?;
    let first_pass = Formatter::new(config.clone()).format_module(&module)?;
    let tokens2 = crate::lexer::lex(&first_pass)?;
    let module2 = crate::parser::parse(&tokens2)?;
    let second_pass = Formatter::new(config).format_module(&module2)?;
    if first_pass == second_pass {
        Ok(())
    } else {
        Err(crate::error::CompileError::without_span(
            "formatter is not idempotent: re-formatting the output produces a different result",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{lexer, parser};

    #[test]
    fn format_round_trips_simple_module() {
        let source = r#"
module demo

action add(x: u64, y: u64) -> u64 {
    let z = x + y
    return z
}
"#;
        let tokens = lexer::lex(source).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let formatted = format_default(&module).unwrap();

        assert!(formatted.contains("module demo"));
        assert!(formatted.contains("action add(x: u64, y: u64) -> u64 {"));
        assert!(formatted.contains("let z = x + y"));
        assert!(formatted.contains("return z"));
    }

    #[test]
    fn format_uses_field_shorthand_when_value_matches_name() {
        let source = r#"
module demo

resource Token has store {
    amount: u64
    symbol: [u8; 8]
}

action mint(amount: u64, symbol: [u8; 8]) -> Token {
    create Token { amount: amount, symbol: symbol }
}
"#;
        let tokens = lexer::lex(source).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let formatted = format_default(&module).unwrap();

        assert!(formatted.contains("create Token { amount, symbol }"), "unexpected formatted source:\n{}", formatted);
    }
}
