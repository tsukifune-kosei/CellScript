use crate::ast::*;
use crate::error::{CompileError, Result, Span};
use crate::lexer::token::{Token, TokenKind};

const MAX_PARSE_RECURSION_DEPTH: usize = 32;

/// Entry-body grammar is selected by a frontend, not inferred from source
/// keywords or mixed into the shared expression/type grammar.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) enum EntryBodyGrammar {
    #[default]
    VerificationSection,
    ConstraintBlock,
}

pub struct Parser<'a> {
    tokens: &'a [Token],
    position: usize,
    recover: bool,
    diagnostics: Vec<CompileError>,
    expression_depth: usize,
    type_depth: usize,
    unary_depth: usize,
    statement_depth: usize,
    if_depth: usize,
    entry_body_grammar: EntryBodyGrammar,
}

#[derive(Debug, Default, Clone)]
struct PendingAttrs {
    type_id: Option<TypeIdentity>,
    capabilities: Option<Vec<Capability>>,
    effect: Option<EffectClass>,
    scheduler_hint: Option<SchedulerHint>,
}

#[derive(Debug, Default, Clone)]
struct TypePolicyDecls {
    default_hash_type: Option<HashTypeDecl>,
    capacity_floor: Option<CapacityFloorDecl>,
    identity: Option<IdentityPolicy>,
}

impl<'a> Parser<'a> {
    pub fn new(tokens: &'a [Token]) -> Self {
        Self {
            tokens,
            position: 0,
            recover: false,
            diagnostics: Vec::new(),
            expression_depth: 0,
            type_depth: 0,
            unary_depth: 0,
            statement_depth: 0,
            if_depth: 0,
            entry_body_grammar: EntryBodyGrammar::VerificationSection,
        }
    }

    pub fn new_recovering(tokens: &'a [Token]) -> Self {
        Self {
            tokens,
            position: 0,
            recover: true,
            diagnostics: Vec::new(),
            expression_depth: 0,
            type_depth: 0,
            unary_depth: 0,
            statement_depth: 0,
            if_depth: 0,
            entry_body_grammar: EntryBodyGrammar::VerificationSection,
        }
    }

    fn current(&self) -> &Token {
        &self.tokens[self.position.min(self.tokens.len() - 1)]
    }

    fn parse_verification_marker(&mut self) -> Result<()> {
        if self.check(&TokenKind::Verification) || matches!(self.entry_body_grammar, EntryBodyGrammar::VerificationSection) {
            self.expect(TokenKind::Verification)?;
        }
        self.skip_newlines();
        Ok(())
    }

    fn current_identifier(&self) -> Option<String> {
        match &self.current().kind {
            TokenKind::Identifier(name) => Some(name.clone()),
            _ => None,
        }
    }

    fn peek(&self, offset: usize) -> &Token {
        &self.tokens[(self.position + offset).min(self.tokens.len() - 1)]
    }

    fn advance(&mut self) -> &Token {
        let token = &self.tokens[self.position];
        if self.position < self.tokens.len() - 1 {
            self.position += 1;
        }
        token
    }

    fn previous_non_newline(&self) -> &Token {
        let mut index = self.position.saturating_sub(1).min(self.tokens.len() - 1);
        while index > 0 && matches!(self.tokens[index].kind, TokenKind::Newline) {
            index -= 1;
        }
        &self.tokens[index]
    }

    fn check(&self, kind: &TokenKind) -> bool {
        std::mem::discriminant(&self.current().kind) == std::mem::discriminant(kind)
    }

    fn expect(&mut self, kind: TokenKind) -> Result<&Token> {
        if self.check(&kind) {
            Ok(self.advance())
        } else {
            Err(CompileError::new(format!("expected {}, found {}", kind, self.current().kind), self.current().span))
        }
    }

    fn skip_newlines(&mut self) {
        while self.check(&TokenKind::Newline) {
            self.advance();
        }
    }

    fn consume_optional_semi(&mut self) {
        if self.check(&TokenKind::Semi) {
            self.advance();
        }
    }

    fn record_diagnostic(&mut self, error: CompileError) {
        self.diagnostics.push(error);
    }

    fn is_item_start(&self) -> bool {
        matches!(
            &self.current().kind,
            TokenKind::Pound
                | TokenKind::Use
                | TokenKind::Resource
                | TokenKind::Shared
                | TokenKind::Receipt
                | TokenKind::Struct
                | TokenKind::Invariant
                | TokenKind::Const
                | TokenKind::Enum
                | TokenKind::Action
                | TokenKind::Fn
                | TokenKind::Lock
        ) || matches!(&self.current().kind, TokenKind::Identifier(name) if name == "flow")
    }

    fn synchronize_item(&mut self, start_position: usize) {
        if self.position == start_position && !self.check(&TokenKind::Eof) {
            self.advance();
        }
        let mut brace_depth = 0usize;
        while !self.check(&TokenKind::Eof) {
            match &self.current().kind {
                TokenKind::LBrace => {
                    brace_depth = brace_depth.saturating_add(1);
                    self.advance();
                }
                TokenKind::RBrace => {
                    brace_depth = brace_depth.saturating_sub(1);
                    self.advance();
                    if brace_depth == 0 {
                        self.skip_newlines();
                        if self.is_item_start() {
                            break;
                        }
                    }
                }
                TokenKind::Newline | TokenKind::Semi if brace_depth == 0 => {
                    self.advance();
                    self.skip_newlines();
                    if self.is_item_start() {
                        break;
                    }
                }
                _ if brace_depth == 0 && self.position != start_position && self.is_item_start() => break,
                _ => {
                    self.advance();
                }
            }
        }
    }

    fn synchronize_stmt(&mut self, start_position: usize) {
        if self.position == start_position && !self.check(&TokenKind::Eof) {
            self.advance();
        }
        let mut paren_depth = 0usize;
        let mut bracket_depth = 0usize;
        let mut brace_depth = 0usize;
        while !self.check(&TokenKind::Eof) {
            match &self.current().kind {
                TokenKind::LParen => {
                    paren_depth = paren_depth.saturating_add(1);
                    self.advance();
                }
                TokenKind::RParen => {
                    paren_depth = paren_depth.saturating_sub(1);
                    self.advance();
                }
                TokenKind::LBracket => {
                    bracket_depth = bracket_depth.saturating_add(1);
                    self.advance();
                }
                TokenKind::RBracket => {
                    bracket_depth = bracket_depth.saturating_sub(1);
                    self.advance();
                }
                TokenKind::LBrace => {
                    brace_depth = brace_depth.saturating_add(1);
                    self.advance();
                }
                TokenKind::RBrace if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => break,
                TokenKind::RBrace => {
                    brace_depth = brace_depth.saturating_sub(1);
                    self.advance();
                }
                TokenKind::Newline | TokenKind::Semi if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                    self.advance();
                    self.skip_newlines();
                    break;
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    fn parse_stmt_recovering(&mut self) -> Result<Option<Stmt>> {
        let start_position = self.position;
        match self.parse_stmt() {
            Ok(stmt) => Ok(Some(stmt)),
            Err(error) if self.recover => {
                self.record_diagnostic(error);
                self.synchronize_stmt(start_position);
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn token_ident_like_name(kind: &TokenKind) -> Option<String> {
        match kind {
            TokenKind::Identifier(name) => Some(name.clone()),
            TokenKind::Module => Some("module".to_string()),
            TokenKind::Use => Some("use".to_string()),
            TokenKind::Resource => Some("resource".to_string()),
            TokenKind::Shared => Some("shared".to_string()),
            TokenKind::Receipt => Some("receipt".to_string()),
            TokenKind::Struct => Some("struct".to_string()),
            TokenKind::Const => Some("const".to_string()),
            TokenKind::Enum => Some("enum".to_string()),
            TokenKind::Invariant => Some("invariant".to_string()),
            TokenKind::Action => Some("action".to_string()),
            TokenKind::Lock => Some("lock".to_string()),
            TokenKind::Transition => Some("transition".to_string()),
            TokenKind::Verification => Some("verification".to_string()),
            TokenKind::Has => Some("has".to_string()),
            TokenKind::Store => Some("store".to_string()),
            TokenKind::Destroy | TokenKind::DestroyKw => Some("destroy".to_string()),
            TokenKind::Launch => Some("launch".to_string()),
            TokenKind::Assert => Some("assert".to_string()),
            TokenKind::Preserve => Some("preserve".to_string()),
            TokenKind::Address => Some("Address".to_string()),
            TokenKind::Hash => Some("Hash".to_string()),
            TokenKind::Env => Some("env".to_string()),
            TokenKind::Std => Some("std".to_string()),
            TokenKind::Self_ => Some("self".to_string()),
            _ => None,
        }
    }

    fn ident_like_name(&self) -> Option<String> {
        Self::token_ident_like_name(&self.current().kind)
    }

    fn parse_name(&mut self) -> Result<String> {
        let name = self.ident_like_name().ok_or_else(|| CompileError::new("expected identifier", self.current().span))?;
        self.advance();
        Ok(name)
    }

    fn parse_name_path(&mut self) -> Result<String> {
        let mut name = self.parse_name()?;

        while self.check(&TokenKind::ColonColon) && Self::token_ident_like_name(&self.peek(1).kind).is_some() {
            self.advance();
            let segment = self.ident_like_name().ok_or_else(|| CompileError::new("expected path segment", self.current().span))?;
            name.push_str("::");
            name.push_str(&segment);
            self.advance();
        }

        Ok(name)
    }

    fn parse_type_list(&mut self, end: TokenKind) -> Result<Vec<Type>> {
        let mut items = Vec::new();
        self.skip_newlines();
        while !self.check(&end) && !self.check(&TokenKind::Eof) {
            items.push(self.parse_type()?);
            self.skip_newlines();
            if self.check(&TokenKind::Comma) {
                self.advance();
                self.skip_newlines();
            } else {
                break;
            }
        }
        Ok(items)
    }

    fn looks_like_type_name(name: &str) -> bool {
        let Some(segment) = name.rsplit("::").next() else {
            return false;
        };
        segment.chars().next().is_some_and(|ch| ch.is_ascii_uppercase()) && !segment.contains('_')
    }

    fn parse_binding_pattern(&mut self) -> Result<BindingPattern> {
        self.skip_newlines();
        match &self.current().kind {
            TokenKind::Underscore => {
                self.advance();
                Ok(BindingPattern::Wildcard)
            }
            TokenKind::LParen => {
                self.advance();
                self.skip_newlines();
                let mut items = Vec::new();
                while !self.check(&TokenKind::RParen) && !self.check(&TokenKind::Eof) {
                    items.push(self.parse_binding_pattern()?);
                    self.skip_newlines();
                    if self.check(&TokenKind::Comma) {
                        self.advance();
                        self.skip_newlines();
                    } else {
                        break;
                    }
                }
                self.expect(TokenKind::RParen)?;
                Ok(BindingPattern::Tuple(items))
            }
            _ => Ok(BindingPattern::Name(self.parse_name()?)),
        }
    }

    fn parse_attrs(&mut self) -> Result<PendingAttrs> {
        let mut attrs = PendingAttrs::default();

        loop {
            self.skip_newlines();
            if !self.check(&TokenKind::Pound) {
                break;
            }

            self.advance();
            self.expect(TokenKind::LBracket)?;
            let attr_name = self.parse_name_path()?;
            self.expect(TokenKind::LParen)?;

            match attr_name.as_str() {
                "capability" => {
                    let mut caps = Vec::new();
                    while !self.check(&TokenKind::RParen) && !self.check(&TokenKind::Eof) {
                        let capability = Capability::from_source_name(&self.current().text)
                            .ok_or_else(|| CompileError::new("expected canonical capability name", self.current().span))?;
                        caps.push(capability);
                        self.advance();

                        if self.check(&TokenKind::Comma) {
                            self.advance();
                        } else {
                            break;
                        }
                    }
                    attrs.capabilities = Some(caps);
                }
                "type_id" => {
                    if attrs.type_id.is_some() {
                        return Err(CompileError::new("duplicate type_id attribute", self.current().span));
                    }
                    let span = self.current().span;
                    let value = match &self.current().kind {
                        TokenKind::String(value) => {
                            let value = value.clone();
                            self.advance();
                            value
                        }
                        _ => return Err(CompileError::new("expected string literal type_id", self.current().span)),
                    };
                    if value.is_empty() {
                        return Err(CompileError::new("type_id must not be empty", span));
                    }
                    if value.chars().any(char::is_control) {
                        return Err(CompileError::new("type_id must not contain control characters", span));
                    }
                    attrs.type_id = Some(TypeIdentity { value, span });
                }
                "effect" => {
                    let mut has_mutating = false;
                    let mut has_creating = false;
                    let mut has_destroying = false;
                    let mut has_read_only = false;
                    while !self.check(&TokenKind::RParen) && !self.check(&TokenKind::Eof) {
                        let effect_name = self.parse_name()?;
                        match effect_name.as_str() {
                            "Pure" | "pure" => {}
                            "ReadOnly" | "readonly" | "read_only" => has_read_only = true,
                            "Mutating" | "mutating" => has_mutating = true,
                            "Creating" | "creating" => has_creating = true,
                            "Destroying" | "destroying" => has_destroying = true,
                            _ => return Err(CompileError::new("expected effect class", self.current().span)),
                        }

                        if self.check(&TokenKind::Comma) {
                            self.advance();
                            self.skip_newlines();
                        } else {
                            break;
                        }
                    }

                    attrs.effect = Some(if has_mutating || (has_creating && has_destroying) {
                        EffectClass::Mutating
                    } else if has_creating {
                        EffectClass::Creating
                    } else if has_destroying {
                        EffectClass::Destroying
                    } else if has_read_only {
                        EffectClass::ReadOnly
                    } else {
                        EffectClass::Pure
                    });
                }
                "scheduler_hint" => {
                    let mut parallelizable = true;
                    let mut estimated_cycles = 1000;
                    while !self.check(&TokenKind::RParen) && !self.check(&TokenKind::Eof) {
                        let hint_name = self.parse_name()?;
                        match hint_name.as_str() {
                            "parallel" => parallelizable = true,
                            "sequential" => parallelizable = false,
                            "estimated_cycles" => {
                                self.expect(TokenKind::Eq)?;
                                estimated_cycles = match &self.current().kind {
                                    TokenKind::Integer(n) => {
                                        let value = u64::try_from(*n)
                                            .map_err(|_| CompileError::new("estimated_cycles must fit in u64", self.current().span))?;
                                        self.advance();
                                        value
                                    }
                                    _ => return Err(CompileError::new("expected integer estimated_cycles", self.current().span)),
                                };
                            }
                            _ => {}
                        }

                        if self.check(&TokenKind::Comma) {
                            self.advance();
                            self.skip_newlines();
                        } else {
                            break;
                        }
                    }
                    attrs.scheduler_hint = Some(SchedulerHint { parallelizable, estimated_cycles });
                }
                _ => {
                    return Err(CompileError::new(format!("unknown attribute '{}'", attr_name), self.current().span));
                }
            }

            self.expect(TokenKind::RParen)?;
            self.expect(TokenKind::RBracket)?;
            self.skip_newlines();
        }

        Ok(attrs)
    }

    pub fn parse_module(&mut self) -> Result<Module> {
        let start_span = self.current().span;

        self.expect(TokenKind::Module)?;

        let full_name = self.parse_name_path()?;
        self.consume_optional_semi();

        self.skip_newlines();

        let mut items = Vec::new();
        let mut visibilities = std::collections::BTreeMap::new();
        while !self.check(&TokenKind::Eof) {
            self.skip_newlines();
            if self.check(&TokenKind::Eof) {
                break;
            }
            let start_position = self.position;
            match self.parse_item() {
                Ok((item, visibility)) => {
                    if let Some(name) = item.name() {
                        visibilities.insert(name.to_string(), visibility);
                    }
                    items.push(item);
                }
                Err(error) if self.recover => {
                    self.record_diagnostic(error);
                    self.synchronize_item(start_position);
                }
                Err(error) => return Err(error),
            }
            self.skip_newlines();
        }

        let end_span = self.current().span;
        Ok(Module {
            name: full_name,
            items,
            interface_templates: Vec::new(),
            visibilities,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_item(&mut self) -> Result<(Item, Visibility)> {
        let leading_visibility = self.parse_visibility()?;
        let attrs = self.parse_attrs()?;
        let trailing_visibility = self.parse_visibility()?;
        let visibility = match (leading_visibility, trailing_visibility) {
            (Visibility::LegacyPublic, trailing) => trailing,
            (leading, Visibility::LegacyPublic) => leading,
            _ => {
                return Err(CompileError::new("a top-level declaration may have only one visibility modifier", self.current().span));
            }
        };
        let item = match &self.current().kind {
            TokenKind::Use => {
                self.reject_type_id_attr(&attrs)?;
                Ok(Item::Use(self.parse_use()?))
            }
            TokenKind::Resource => Ok(Item::Resource(self.parse_resource(attrs.type_id, attrs.capabilities)?)),
            TokenKind::Shared => Ok(Item::Shared(self.parse_shared(attrs.type_id, attrs.capabilities)?)),
            TokenKind::Receipt => Ok(Item::Receipt(self.parse_receipt(attrs.type_id, attrs.capabilities)?)),
            TokenKind::Struct => Ok(Item::Struct(self.parse_struct(attrs.type_id)?)),
            TokenKind::Identifier(name) if name == "flow" => {
                self.reject_type_id_attr(&attrs)?;
                Ok(Item::Flow(self.parse_flow()?))
            }
            TokenKind::Invariant => {
                self.reject_all_attrs("invariant", &attrs)?;
                Ok(Item::Invariant(self.parse_invariant()?))
            }
            TokenKind::Const => {
                self.reject_type_id_attr(&attrs)?;
                Ok(Item::Const(self.parse_const()?))
            }
            TokenKind::Enum => {
                self.reject_type_id_attr(&attrs)?;
                Ok(Item::Enum(self.parse_enum()?))
            }
            TokenKind::Action => {
                self.reject_type_id_attr(&attrs)?;
                Ok(Item::Action(self.parse_action(attrs.effect, attrs.scheduler_hint)?))
            }
            TokenKind::Fn => {
                self.reject_type_id_attr(&attrs)?;
                if attrs.capabilities.is_some() || attrs.scheduler_hint.is_some() {
                    return Err(CompileError::new("fn definitions only accept the #[effect(...)] attribute", self.current().span));
                }
                Ok(Item::Function(self.parse_fn(attrs.effect)?))
            }
            TokenKind::Lock => {
                self.reject_type_id_attr(&attrs)?;
                Ok(Item::Lock(self.parse_lock()?))
            }
            _ => Err(CompileError::new(format!("unexpected token: {}", self.current().kind), self.current().span)),
        }?;
        if item.name().is_none() && visibility != Visibility::LegacyPublic {
            return Err(CompileError::new("visibility modifiers are only valid on named top-level declarations", self.current().span));
        }
        Ok((item, visibility))
    }

    fn parse_visibility(&mut self) -> Result<Visibility> {
        if self.check(&TokenKind::Private) {
            self.advance();
            return Ok(Visibility::Private);
        }
        if !self.check(&TokenKind::Public) {
            return Ok(Visibility::LegacyPublic);
        }
        let span = self.current().span;
        self.advance();
        if !self.check(&TokenKind::LParen) {
            return Ok(Visibility::Public);
        }
        self.advance();
        if self.current().text != "package" {
            return Err(CompileError::new("expected 'package' in public(package)", self.current().span));
        }
        self.advance();
        self.expect(TokenKind::RParen).map_err(|_| CompileError::new("expected ')' after public(package)", span))?;
        Ok(Visibility::Package)
    }

    fn reject_type_id_attr(&self, attrs: &PendingAttrs) -> Result<()> {
        if let Some(type_id) = &attrs.type_id {
            Err(CompileError::new("#[type_id] can only be applied to resource, shared, receipt, or struct definitions", type_id.span))
        } else {
            Ok(())
        }
    }

    fn reject_all_attrs(&self, item_kind: &str, attrs: &PendingAttrs) -> Result<()> {
        if attrs.type_id.is_some() || attrs.capabilities.is_some() || attrs.effect.is_some() || attrs.scheduler_hint.is_some() {
            Err(CompileError::new(format!("attributes cannot be applied to {} definitions", item_kind), self.current().span))
        } else {
            Ok(())
        }
    }

    fn parse_type_params(&mut self) -> Result<Vec<TypeParam>> {
        if !self.check(&TokenKind::Lt) {
            return Ok(Vec::new());
        }

        self.advance();
        let mut params = Vec::new();
        while !self.check(&TokenKind::Gt) && !self.check(&TokenKind::Eof) {
            let start = self.current().span;
            let phantom = self.current().text == "phantom";
            if phantom {
                self.advance();
            }
            let name = self.parse_name()?;
            let mut constraints = Vec::new();
            if self.check(&TokenKind::Colon) {
                self.advance();
                loop {
                    let Some(ability) = ValueAbility::from_source_name(&self.current().text) else {
                        return Err(CompileError::new(
                            "expected value constraint: copy, drop, store, fixed, serializable, non_linear, or cell",
                            self.current().span,
                        ));
                    };
                    if constraints.contains(&ability) {
                        return Err(CompileError::new(
                            format!("duplicate '{}' constraint on type parameter '{}'", ability.as_str(), name),
                            self.current().span,
                        ));
                    }
                    constraints.push(ability);
                    self.advance();
                    if self.check(&TokenKind::Plus) {
                        self.advance();
                    } else {
                        break;
                    }
                }
            }
            params.push(TypeParam { name, constraints, phantom, span: start });
            if self.check(&TokenKind::Comma) {
                self.advance();
            } else {
                break;
            }
        }
        self.expect(TokenKind::Gt)?;
        Ok(params)
    }

    fn reject_generic_type_params(&self, type_name: &str) -> Result<()> {
        if self.check(&TokenKind::Lt) {
            Err(CompileError::new(
                format!(
                    "Cell-backed type '{}' cannot declare generic parameters; use concrete resource/shared/receipt schemas and generic non-Cell value types",
                    type_name
                ),
                self.current().span,
            ))
        } else {
            Ok(())
        }
    }

    fn parse_value_abilities(&mut self) -> Result<Vec<ValueAbility>> {
        if !self.check(&TokenKind::Has) {
            return Ok(Vec::new());
        }
        self.advance();
        let mut abilities = Vec::new();
        loop {
            let Some(ability) = ValueAbility::from_source_name(&self.current().text) else {
                return Err(CompileError::new(
                    "expected value ability: copy, drop, store, fixed, serializable, non_linear, or cell",
                    self.current().span,
                ));
            };
            if abilities.contains(&ability) {
                return Err(CompileError::new(format!("duplicate '{}' value ability", ability.as_str()), self.current().span));
            }
            abilities.push(ability);
            self.advance();
            if self.check(&TokenKind::Comma) {
                self.advance();
            } else {
                break;
            }
        }
        Ok(abilities)
    }

    fn parse_use(&mut self) -> Result<UseStmt> {
        let start_span = self.current().span;
        self.expect(TokenKind::Use)?;

        let path = self.parse_name_path()?.split("::").map(ToString::to_string).collect::<Vec<_>>();

        let (module_path, imports) = if self.check(&TokenKind::ColonColon) {
            self.advance();
            if self.check(&TokenKind::LBrace) {
                self.advance();
                let mut imports = Vec::new();
                while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
                    imports.push(UseImport { name: self.parse_name_path()?, alias: None });
                    if self.check(&TokenKind::Comma) {
                        self.advance();
                    } else {
                        break;
                    }
                }
                self.expect(TokenKind::RBrace)?;
                (path, imports)
            } else {
                let import_name = self.parse_name_path()?;
                let alias = match &self.current().kind {
                    TokenKind::Identifier(s) if s == "as" => {
                        self.advance();
                        match &self.current().kind {
                            TokenKind::Identifier(n) => {
                                let a = n.clone();
                                self.advance();
                                Some(a)
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                };
                (path, vec![UseImport { name: import_name, alias }])
            }
        } else {
            let mut module_path = path;
            let import_name = module_path.pop().ok_or_else(|| CompileError::new("expected import path", self.current().span))?;
            let alias = match &self.current().kind {
                TokenKind::Identifier(s) if s == "as" => {
                    self.advance();
                    match &self.current().kind {
                        TokenKind::Identifier(n) => {
                            let a = n.clone();
                            self.advance();
                            Some(a)
                        }
                        _ => None,
                    }
                }
                _ => None,
            };
            (module_path, vec![UseImport { name: import_name, alias }])
        };

        self.consume_optional_semi();

        let end_span = self.current().span;
        Ok(UseStmt { module_path, imports, span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column) })
    }

    fn parse_resource(&mut self, type_id: Option<TypeIdentity>, attr_capabilities: Option<Vec<Capability>>) -> Result<ResourceDef> {
        let start_span = self.current().span;
        self.expect(TokenKind::Resource)?;

        let name = self.parse_name()?;
        self.reject_generic_type_params(&name)?;

        let capabilities = merge_capabilities(attr_capabilities, self.parse_capabilities()?);
        self.skip_newlines();
        let type_policy = self.parse_type_policy_decls()?;
        self.skip_newlines();

        let (fields, validity) = self.parse_fields_and_validity()?;

        let end_span = self.current().span;
        Ok(ResourceDef {
            name,
            type_id,
            identity: type_policy.identity.unwrap_or_default(),
            default_hash_type: type_policy.default_hash_type,
            capacity_floor: type_policy.capacity_floor,
            capabilities,
            fields,
            validity,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_shared(&mut self, type_id: Option<TypeIdentity>, attr_capabilities: Option<Vec<Capability>>) -> Result<SharedDef> {
        let start_span = self.current().span;
        self.expect(TokenKind::Shared)?;

        let name = self.parse_name()?;
        self.reject_generic_type_params(&name)?;

        let capabilities = merge_capabilities(attr_capabilities, self.parse_capabilities()?);
        self.skip_newlines();
        let type_policy = self.parse_type_policy_decls()?;
        self.skip_newlines();
        let (fields, validity) = self.parse_fields_and_validity()?;

        let end_span = self.current().span;
        Ok(SharedDef {
            name,
            type_id,
            identity: type_policy.identity.unwrap_or_default(),
            default_hash_type: type_policy.default_hash_type,
            capacity_floor: type_policy.capacity_floor,
            capabilities,
            fields,
            validity,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_receipt(&mut self, type_id: Option<TypeIdentity>, attr_capabilities: Option<Vec<Capability>>) -> Result<ReceiptDef> {
        let start_span = self.current().span;
        self.expect(TokenKind::Receipt)?;

        let name = self.parse_name()?;
        self.reject_generic_type_params(&name)?;
        let claim_output = if self.check(&TokenKind::Arrow) {
            self.advance();
            Some(self.parse_type()?)
        } else {
            None
        };

        let capabilities = merge_capabilities(attr_capabilities, self.parse_capabilities()?);
        self.skip_newlines();
        let type_policy = self.parse_type_policy_decls()?;
        self.skip_newlines();
        let (fields, validity) = self.parse_fields_and_validity()?;

        let end_span = self.current().span;
        Ok(ReceiptDef {
            name,
            type_id,
            identity: type_policy.identity.unwrap_or_default(),
            default_hash_type: type_policy.default_hash_type,
            capacity_floor: type_policy.capacity_floor,
            claim_output,
            capabilities,
            fields,
            validity,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_struct(&mut self, type_id: Option<TypeIdentity>) -> Result<StructDef> {
        let start_span = self.current().span;
        self.expect(TokenKind::Struct)?;

        let name = self.parse_name()?;
        let type_params = self.parse_type_params()?;
        self.skip_newlines();
        let abilities = self.parse_value_abilities()?;
        if !type_params.is_empty() && type_id.is_some() {
            return Err(CompileError::new(
                "generic value structs cannot declare #[type_id]; Cell identity belongs to concrete Cell-backed types",
                start_span,
            ));
        }

        self.skip_newlines();
        let type_policy = self.parse_type_policy_decls()?;
        self.skip_newlines();
        let (fields, validity) = self.parse_fields_and_validity()?;

        let end_span = self.current().span;
        Ok(StructDef {
            name,
            type_params,
            abilities,
            type_id,
            default_hash_type: type_policy.default_hash_type,
            capacity_floor: type_policy.capacity_floor,
            fields,
            validity,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_flow(&mut self) -> Result<FlowDef> {
        let start_span = self.current().span;
        let keyword = self.parse_name()?;
        debug_assert_eq!(keyword, "flow");

        let first = self.parse_name_path()?;
        let (name, target) =
            if self.check(&TokenKind::For) || matches!(&self.current().kind, TokenKind::Identifier(name) if name == "for") {
                self.advance();
                (Some(first), self.parse_state_field_path()?)
            } else if self.check(&TokenKind::Dot) {
                self.advance();
                let field_start = self.current().span;
                let field = self.parse_name()?;
                let field_end = self.current().span;
                (
                    None,
                    StateFieldPath {
                        base: first,
                        field,
                        span: Span::new(start_span.start, field_end.end, field_start.line, field_start.column),
                    },
                )
            } else {
                return Err(CompileError::new("expected 'for' or '.field' in flow declaration", self.current().span));
            };
        self.expect(TokenKind::LBrace)?;
        self.skip_newlines();

        let mut initial_states = Vec::new();
        let mut terminal_states = Vec::new();
        let mut transitions = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
            if self.current_identifier().as_deref() == Some("initial") {
                self.advance();
                initial_states.extend(self.parse_flow_state_list("initial")?);
                self.expect(TokenKind::Semi)?;
                self.skip_newlines();
                continue;
            }
            if self.current_identifier().as_deref() == Some("terminal") {
                self.advance();
                terminal_states.extend(self.parse_flow_state_list("terminal")?);
                self.expect(TokenKind::Semi)?;
                self.skip_newlines();
                continue;
            }
            let transition_start = self.current().span;
            let from = self.parse_name_path()?;
            self.expect(TokenKind::Arrow)?;
            let to = self.parse_name_path()?;
            let action = if matches!(&self.current().kind, TokenKind::Identifier(name) if name == "by") {
                self.advance();
                Some(self.parse_name_path()?)
            } else {
                None
            };
            let transition_end = self.current().span;
            transitions.push(StateTransition {
                from,
                to,
                action,
                span: Span::new(transition_start.start, transition_end.end, transition_start.line, transition_start.column),
            });

            if self.check(&TokenKind::Comma) || self.check(&TokenKind::Semi) {
                self.advance();
            }
            self.skip_newlines();
        }

        self.expect(TokenKind::RBrace)?;
        self.consume_optional_semi();

        let end_span = self.current().span;
        Ok(FlowDef {
            name,
            target,
            initial_states,
            terminal_states,
            transitions,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_flow_state_list(&mut self, declaration: &str) -> Result<Vec<String>> {
        let mut states = Vec::new();
        while !self.check(&TokenKind::Semi) && !self.check(&TokenKind::Eof) {
            states.push(self.parse_name_path()?);
            if self.check(&TokenKind::Comma) {
                self.advance();
            } else {
                break;
            }
        }
        if states.is_empty() {
            return Err(CompileError::new(format!("{} declaration must name at least one state", declaration), self.current().span));
        }
        Ok(states)
    }

    fn parse_state_field_path(&mut self) -> Result<StateFieldPath> {
        let start_span = self.current().span;
        let base = self.parse_name_path()?;
        self.expect(TokenKind::Dot)?;
        let field = self.parse_name()?;
        let end_span = self.current().span;
        Ok(StateFieldPath { base, field, span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column) })
    }

    fn parse_type_policy_decls(&mut self) -> Result<TypePolicyDecls> {
        let mut policy = TypePolicyDecls::default();
        loop {
            self.skip_newlines();
            let Some(name) = self.current_identifier() else {
                break;
            };
            match name.as_str() {
                "with_default_hash_type" => {
                    if policy.default_hash_type.is_some() {
                        return Err(crate::error::CompileError::new(
                            "duplicate with_default_hash_type declaration",
                            self.current().span,
                        ));
                    }
                    policy.default_hash_type = Some(self.parse_default_hash_type_decl()?);
                }
                "with_capacity_floor" => {
                    if policy.capacity_floor.is_some() {
                        return Err(crate::error::CompileError::new("duplicate with_capacity_floor declaration", self.current().span));
                    }
                    policy.capacity_floor = Some(self.parse_capacity_floor_decl()?);
                }
                "identity" => {
                    if policy.identity.is_some() {
                        return Err(crate::error::CompileError::new("duplicate identity declaration", self.current().span));
                    }
                    policy.identity = Some(self.parse_identity_decl()?);
                }
                _ => break,
            }
        }
        Ok(policy)
    }

    fn parse_default_hash_type_decl(&mut self) -> Result<HashTypeDecl> {
        let start_span = self.current().span;
        self.advance();
        self.expect(TokenKind::LParen)?;
        let value = self.parse_name()?;
        self.expect(TokenKind::RParen)?;
        let normalized = normalize_hash_type_decl(&value).ok_or_else(|| {
            crate::error::CompileError::new(
                format!("unsupported CKB hash_type '{}'; expected Data, Data1, Data2, or Type", value),
                start_span,
            )
        })?;
        Ok(HashTypeDecl { value: normalized, span: start_span })
    }

    fn parse_capacity_floor_decl(&mut self) -> Result<CapacityFloorDecl> {
        let start_span = self.current().span;
        self.advance();
        self.expect(TokenKind::LParen)?;
        let shannons = match &self.current().kind {
            TokenKind::Integer(value) => {
                let value = u64::try_from(*value)
                    .map_err(|_| CompileError::new("capacity floor must fit in u64 shannons", self.current().span))?;
                self.advance();
                value
            }
            _ => {
                return Err(crate::error::CompileError::new(
                    "expected integer shannon value in with_capacity_floor(...)",
                    self.current().span,
                ));
            }
        };
        self.expect(TokenKind::RParen)?;
        if shannons == 0 {
            return Err(crate::error::CompileError::new("capacity floor must be greater than zero shannons", start_span));
        }
        Ok(CapacityFloorDecl { shannons, span: start_span })
    }

    fn parse_identity_decl(&mut self) -> Result<IdentityPolicy> {
        self.advance(); // consume "identity"
        if self.check(&TokenKind::LParen) {
            self.advance();
            let kind = self.parse_name()?;
            let policy = match kind.as_str() {
                "ckb_type_id" => IdentityPolicy::CkbTypeId,
                "field" => {
                    self.expect(TokenKind::LParen)?;
                    let path = self.parse_name()?;
                    self.expect(TokenKind::RParen)?;
                    IdentityPolicy::Field(path)
                }
                "script_args" => IdentityPolicy::ScriptArgs,
                "singleton_type" => IdentityPolicy::SingletonType,
                "none" => IdentityPolicy::None,
                other => {
                    return Err(crate::error::CompileError::new(
                        format!(
                            "unsupported identity policy '{}'; expected none, ckb_type_id, field(...), script_args, or singleton_type",
                            other
                        ),
                        self.current().span,
                    ));
                }
            };
            self.expect(TokenKind::RParen)?;
            Ok(policy)
        } else {
            // `identity ckb_type_id` without parens
            let kind = self.parse_name()?;
            match kind.as_str() {
                "ckb_type_id" => Ok(IdentityPolicy::CkbTypeId),
                "script_args" => Ok(IdentityPolicy::ScriptArgs),
                "singleton_type" => Ok(IdentityPolicy::SingletonType),
                "none" => Ok(IdentityPolicy::None),
                other => Err(crate::error::CompileError::new(
                    format!("unsupported identity policy '{}'; expected none, ckb_type_id, script_args, or singleton_type", other),
                    self.current().span,
                )),
            }
        }
    }

    fn parse_const(&mut self) -> Result<ConstDef> {
        let start_span = self.current().span;
        self.expect(TokenKind::Const)?;
        let name = self.parse_name_path()?;
        self.expect(TokenKind::Colon)?;
        let ty = self.parse_type()?;
        self.expect(TokenKind::Eq)?;
        let value = self.parse_expr()?;
        self.consume_optional_semi();

        let end_span = self.current().span;
        Ok(ConstDef { name, ty, value, span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column) })
    }

    fn parse_enum(&mut self) -> Result<EnumDef> {
        let start_span = self.current().span;
        self.expect(TokenKind::Enum)?;
        let name = self.parse_name_path()?;
        let type_params = self.parse_type_params()?;
        self.skip_newlines();
        let abilities = self.parse_value_abilities()?;
        self.skip_newlines();
        self.expect(TokenKind::LBrace)?;
        self.skip_newlines();

        let mut variants = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
            let variant_start = self.current().span;
            let variant_name = self.parse_name_path()?;
            let fields = if self.check(&TokenKind::LParen) {
                self.advance();
                let items = self.parse_type_list(TokenKind::RParen)?;
                self.expect(TokenKind::RParen)?;
                items
            } else {
                Vec::new()
            };
            let variant_end = self.current().span;
            variants.push(EnumVariant {
                name: variant_name,
                fields,
                span: Span::new(variant_start.start, variant_end.end, variant_start.line, variant_start.column),
            });

            if self.check(&TokenKind::Comma) {
                self.advance();
            }
            self.skip_newlines();
        }

        self.expect(TokenKind::RBrace)?;
        self.consume_optional_semi();

        let end_span = self.current().span;
        Ok(EnumDef {
            name,
            type_params,
            abilities,
            variants,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_capabilities(&mut self) -> Result<Vec<Capability>> {
        let mut caps = Vec::new();

        if self.check(&TokenKind::Has) {
            self.advance();

            while let Some(capability) = Capability::from_source_name(&self.current().text) {
                caps.push(capability);
                self.advance();

                if self.check(&TokenKind::Comma) {
                    self.advance();
                } else {
                    break;
                }
            }
        }

        Ok(caps)
    }

    fn parse_fields_and_validity(&mut self) -> Result<(Vec<Field>, Option<ValidityBlock>)> {
        self.expect(TokenKind::LBrace)?;
        self.skip_newlines();

        let mut fields = Vec::new();
        let mut validity = None;
        while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
            if self.current_identifier().as_deref() == Some("validity") && self.peek(1).kind != TokenKind::Colon {
                if validity.is_some() {
                    return Err(CompileError::new("type declaration contains more than one validity block", self.current().span));
                }
                let start = self.current().span;
                self.advance();
                self.skip_newlines();
                let mut predicates = Vec::new();
                while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
                    if !self.check(&TokenKind::Require) {
                        return Err(CompileError::new(
                            "validity block only accepts pure require predicates and must be the final section of the type body",
                            self.current().span,
                        ));
                    }
                    predicates.push(self.parse_require()?);
                    self.consume_optional_semi();
                    self.skip_newlines();
                }
                if predicates.is_empty() {
                    return Err(CompileError::new("validity block must contain at least one require predicate", start));
                }
                let end = predicates.last().map(Expr::span).unwrap_or(start);
                validity = Some(ValidityBlock { predicates, span: Span::new(start.start, end.end, start.line, start.column) });
                break;
            }
            let field = self.parse_field()?;
            fields.push(field);
            if self.check(&TokenKind::Comma) {
                self.advance();
            }
            self.skip_newlines();
        }

        self.expect(TokenKind::RBrace)?;
        Ok((fields, validity))
    }

    fn parse_field(&mut self) -> Result<Field> {
        let start_span = self.current().span;

        let name = self.parse_name()?;

        self.expect(TokenKind::Colon)?;
        let ty = self.parse_type()?;
        if self.current_identifier().as_deref() == Some("where") {
            return Err(CompileError::new(
                "field-level 'where' refinements are deferred; declare predicates in the type validity block",
                self.current().span,
            ));
        }

        let end_span = self.current().span;
        Ok(Field { name, ty, span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column) })
    }

    fn parse_invariant(&mut self) -> Result<InvariantDef> {
        let start_span = self.current().span;
        self.expect(TokenKind::Invariant)?;
        let name = self.parse_name()?;
        self.expect(TokenKind::LBrace)?;
        self.skip_newlines();

        let mut trigger = None;
        let mut scope = None;
        let mut reads = Vec::new();
        let mut aggregates = Vec::new();
        let mut quantifiers = Vec::new();
        let mut asserts = Vec::new();

        while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
            self.skip_newlines();
            if self.check(&TokenKind::RBrace) {
                break;
            }

            if self.check(&TokenKind::Assert) {
                if self.current().text == "assert_invariant" {
                    asserts.push(self.parse_invariant_call_assert()?);
                } else {
                    asserts.push(self.parse_invariant_assert()?);
                }
                self.consume_optional_semi();
                self.skip_newlines();
                continue;
            }

            if let Some(name) = self.ident_like_name() {
                if name == "forall" {
                    quantifiers.push(self.parse_bounded_forall()?);
                    self.consume_optional_semi();
                    self.skip_newlines();
                    continue;
                }
                if name == "count" {
                    quantifiers.push(self.parse_bounded_count()?);
                    self.consume_optional_semi();
                    self.skip_newlines();
                    continue;
                }
                if Self::is_invariant_aggregate_start(&name) {
                    aggregates.push(self.parse_aggregate_invariant()?);
                    self.consume_optional_semi();
                    self.skip_newlines();
                    continue;
                }
            }

            let key_span = self.current().span;
            let key = self.ident_like_name().ok_or_else(|| {
                CompileError::new("expected invariant field, aggregate assertion, or assert_invariant", self.current().span)
            })?;
            self.advance();
            self.expect(TokenKind::Colon)?;

            match key.as_str() {
                "trigger" => {
                    if trigger.is_some() {
                        return Err(CompileError::new("duplicate invariant trigger declaration", key_span));
                    }
                    trigger = Some(self.parse_name_path()?);
                }
                "scope" => {
                    if scope.is_some() {
                        return Err(CompileError::new("duplicate invariant scope declaration", key_span));
                    }
                    scope = Some(self.parse_name_path()?);
                }
                "reads" => {
                    reads.extend(self.parse_invariant_reads()?);
                }
                _ => {
                    return Err(CompileError::new(
                        format!("unknown invariant field '{}'; expected trigger, scope, reads, or assert_invariant", key),
                        key_span,
                    ));
                }
            }

            self.consume_optional_semi();
            self.skip_newlines();
        }

        let end_span = self.current().span;
        self.expect(TokenKind::RBrace)?;
        Ok(InvariantDef {
            name,
            trigger,
            scope,
            reads,
            aggregates,
            quantifiers,
            asserts,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_bounded_forall(&mut self) -> Result<BoundedQuantifier> {
        let start_span = self.current().span;
        let keyword = self.parse_name()?;
        debug_assert_eq!(keyword, "forall");
        let role = self.parse_name().map_err(|_| {
            CompileError::new(
                "forall requires a role, binding, and finite source view: `forall output token in outputs<Token> { ... }`",
                start_span,
            )
        })?;
        let binding_span = self.current().span;
        let binding = self.parse_name().map_err(|_| {
            CompileError::new(
                "unbounded forall is not supported; name a finite source view with `forall <role> <binding> in <source_view<T>>`",
                binding_span,
            )
        })?;
        if !self.check(&TokenKind::In) {
            return Err(CompileError::new(
                "unbounded forall is not supported; expected `in` followed by a finite source view",
                self.current().span,
            ));
        }
        self.advance();
        let range = self.parse_invariant_target()?;
        if range.field.is_some() {
            return Err(CompileError::new("forall range must name a source view and cell type, not a projected field", start_span));
        }
        self.expect(TokenKind::LBrace)?;
        self.skip_newlines();
        let mut predicates = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
            if !self.check(&TokenKind::Require) {
                return Err(CompileError::new(
                    "forall body only accepts pure `require` predicates; lifecycle and control-flow statements are not allowed",
                    self.current().span,
                ));
            }
            predicates.push(self.parse_require()?);
            self.consume_optional_semi();
            self.skip_newlines();
        }
        if predicates.is_empty() {
            return Err(CompileError::new("forall body must contain at least one require predicate", start_span));
        }
        let end_span = self.current().span;
        self.expect(TokenKind::RBrace)?;
        Ok(BoundedQuantifier {
            kind: BoundedQuantifierKind::ForAll,
            role: Some(role),
            binding: Some(binding),
            range,
            predicates,
            relation: None,
            expected: None,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_bounded_count(&mut self) -> Result<BoundedQuantifier> {
        let start_span = self.current().span;
        let keyword = self.parse_name()?;
        debug_assert_eq!(keyword, "count");
        self.expect(TokenKind::LParen)?;
        let range = self.parse_invariant_target()?;
        if range.field.is_some() {
            return Err(CompileError::new("count range must name a source view and cell type, not a projected field", start_span));
        }
        let where_span = self.current().span;
        let where_name = self
            .ident_like_name()
            .ok_or_else(|| CompileError::new("count requires `where <predicate>` after its finite source view", where_span))?;
        if where_name != "where" {
            return Err(CompileError::new("count requires `where <predicate>` after its finite source view", where_span));
        }
        self.advance();
        let predicate = self.parse_expr()?;
        self.expect(TokenKind::RParen)?;
        let relation = match self.current().kind {
            TokenKind::Lt => AggregateRelation::Lt,
            TokenKind::Le => AggregateRelation::Le,
            TokenKind::EqEq => AggregateRelation::Eq,
            TokenKind::Ge => AggregateRelation::Ge,
            TokenKind::Gt => AggregateRelation::Gt,
            _ => return Err(CompileError::new("count requires a comparison against a u64 expression", self.current().span)),
        };
        self.advance();
        let expected = self.parse_expr()?;
        let end_span = self.current().span;
        Ok(BoundedQuantifier {
            kind: BoundedQuantifierKind::Count,
            role: None,
            binding: None,
            range,
            predicates: vec![predicate],
            relation: Some(relation),
            expected: Some(expected),
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn is_invariant_aggregate_start(name: &str) -> bool {
        matches!(name, "assert_sum" | "assert_conserved" | "assert_delta" | "assert_distinct" | "assert_singleton")
    }

    fn parse_aggregate_invariant(&mut self) -> Result<AggregateInvariant> {
        let start_span = self.current().span;
        let name = self.parse_name()?;
        if name == "assert_sum" {
            return self.parse_aggregate_sum_comparison(start_span);
        }

        self.expect(TokenKind::LParen)?;
        self.skip_newlines();
        let target = self.parse_invariant_target()?;
        self.skip_newlines();
        self.expect(TokenKind::Comma)?;
        self.skip_newlines();

        let (kind, argument, scope) = match name.as_str() {
            "assert_conserved" => (AggregateInvariantKind::Conserved, None, self.parse_aggregate_scope_arg()?),
            "assert_distinct" => (AggregateInvariantKind::Distinct, None, self.parse_aggregate_scope_arg()?),
            "assert_singleton" => (AggregateInvariantKind::Singleton, None, self.parse_aggregate_scope_arg()?),
            "assert_delta" => {
                let delta = self.parse_aggregate_argument()?;
                self.skip_newlines();
                self.expect(TokenKind::Comma)?;
                self.skip_newlines();
                (AggregateInvariantKind::Delta, Some(delta), self.parse_aggregate_scope_arg()?)
            }
            _ => {
                return Err(CompileError::new(format!("unknown aggregate invariant primitive '{}'", name), start_span));
            }
        };

        self.skip_newlines();
        let end_span = self.current().span;
        self.expect(TokenKind::RParen)?;
        Ok(AggregateInvariant {
            kind,
            target,
            scope,
            argument,
            relation: None,
            rhs: None,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_aggregate_sum_comparison(&mut self, start_span: Span) -> Result<AggregateInvariant> {
        let left = self.parse_aggregate_sum_operand()?;
        self.skip_newlines();
        let relation = match self.current().kind {
            TokenKind::Lt => AggregateRelation::Lt,
            TokenKind::Le => AggregateRelation::Le,
            TokenKind::EqEq => AggregateRelation::Eq,
            TokenKind::Ge => AggregateRelation::Ge,
            TokenKind::Gt => AggregateRelation::Gt,
            _ => {
                return Err(CompileError::new("assert_sum aggregate assertion requires a comparison operator", self.current().span));
            }
        };
        self.advance();
        self.skip_newlines();

        let rhs_start = self.current().span;
        let rhs_name = self.parse_name()?;
        if rhs_name != "assert_sum" {
            return Err(CompileError::new("assert_sum comparison right-hand side must be assert_sum(...)", rhs_start));
        }
        let right = self.parse_aggregate_sum_operand()?;
        let scope = aggregate_scope_from_targets(&left, Some(&right)).ok_or_else(|| {
            CompileError::new("assert_sum aggregate assertion requires explicit input/output source views", start_span)
        })?;
        let end_span = self.current().span;

        Ok(AggregateInvariant {
            kind: AggregateInvariantKind::Sum,
            target: left,
            scope,
            argument: None,
            relation: Some(relation),
            rhs: Some(right),
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_aggregate_sum_operand(&mut self) -> Result<AggregateTarget> {
        self.expect(TokenKind::LParen)?;
        self.skip_newlines();
        let target = self.parse_invariant_target()?;
        self.skip_newlines();
        self.expect(TokenKind::RParen)?;
        Ok(target)
    }

    fn parse_aggregate_scope_arg(&mut self) -> Result<String> {
        let key_span = self.current().span;
        let key = self.parse_name()?;
        if key != "scope" {
            return Err(CompileError::new("aggregate invariant primitive requires `scope = ...`", key_span));
        }
        self.skip_newlines();
        self.expect(TokenKind::Eq)?;
        self.skip_newlines();
        self.parse_name_path()
    }

    fn parse_aggregate_argument(&mut self) -> Result<String> {
        match &self.current().kind {
            TokenKind::Integer(value) => {
                let rendered = value.to_string();
                self.advance();
                Ok(rendered)
            }
            TokenKind::String(value) => {
                let rendered = format!("{:?}", value);
                self.advance();
                Ok(rendered)
            }
            _ => self.parse_invariant_target().map(|target| target.to_string()),
        }
    }

    fn parse_invariant_assert(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        self.expect(TokenKind::Assert)?;
        let condition = self.parse_expr()?;
        let end_span = self.current().span;
        Ok(Expr::Assert(AssertExpr {
            condition: Box::new(condition),
            message: Box::new(Expr::String("invariant assertion failed".to_string())),
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }

    fn parse_invariant_call_assert(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        self.expect(TokenKind::Assert)?;
        self.expect(TokenKind::LParen)?;
        self.skip_newlines();
        let condition = self.parse_expr()?;
        self.expect(TokenKind::Comma)?;
        self.skip_newlines();
        let message = self.parse_expr()?;
        self.skip_newlines();
        let end_span = self.current().span;
        self.expect(TokenKind::RParen)?;
        Ok(Expr::Assert(AssertExpr {
            condition: Box::new(condition),
            message: Box::new(message),
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }

    fn parse_invariant_reads(&mut self) -> Result<Vec<AggregateTarget>> {
        let mut reads = Vec::new();
        self.skip_newlines();
        if self.check(&TokenKind::RBrace) || self.check(&TokenKind::Semi) {
            return Ok(reads);
        }

        loop {
            reads.push(self.parse_invariant_target()?);
            if self.check(&TokenKind::Comma) {
                self.advance();
                self.skip_newlines();
                if self.check(&TokenKind::RBrace) || self.check(&TokenKind::Semi) {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(reads)
    }

    fn parse_invariant_target(&mut self) -> Result<AggregateTarget> {
        let start_span = self.current().span;
        let root = self.parse_name_path()?;
        let mut type_name = None;
        if self.check(&TokenKind::Lt) {
            self.advance();
            let ty = self.parse_type()?;
            self.expect(TokenKind::Gt)?;
            type_name = Some(Self::render_type(&ty));
        }

        let mut fields = Vec::new();
        while self.check(&TokenKind::Dot) {
            self.advance();
            fields.push(self.parse_name()?);
        }

        let field = (!fields.is_empty()).then(|| fields.join("."));
        let source = if let Some(source) = SourceView::from_source_name(&root) {
            source
        } else {
            if type_name.is_some() {
                return Err(CompileError::new(
                    format!("unknown invariant source view '{}'; generic source views use the closed CKB view registry", root),
                    start_span,
                ));
            }
            type_name = Some(root);
            SourceView::SelectedCells
        };

        if source == SourceView::TypeIdentity && (type_name.is_some() || field.is_some()) {
            return Err(CompileError::new("type_id aggregate target cannot have a type argument or field projection", start_span));
        }

        Ok(AggregateTarget { source, type_name, field })
    }

    fn parse_type(&mut self) -> Result<Type> {
        if self.type_depth >= MAX_PARSE_RECURSION_DEPTH {
            return Err(CompileError::new(
                format!("type nesting exceeds the parser limit of {}", MAX_PARSE_RECURSION_DEPTH),
                self.current().span,
            ));
        }
        self.type_depth += 1;
        let result = self.parse_type_inner();
        self.type_depth -= 1;
        result
    }

    fn parse_type_inner(&mut self) -> Result<Type> {
        let ty = match &self.current().kind {
            TokenKind::U8 => {
                self.advance();
                Type::U8
            }
            TokenKind::U16 => {
                self.advance();
                Type::U16
            }
            TokenKind::U32 => {
                self.advance();
                Type::U32
            }
            TokenKind::I32 => {
                self.advance();
                Type::I32
            }
            TokenKind::U64 => {
                self.advance();
                Type::U64
            }
            TokenKind::U128 => {
                self.advance();
                Type::U128
            }
            TokenKind::Bool => {
                self.advance();
                Type::Bool
            }
            TokenKind::Address => {
                self.advance();
                Type::Address
            }
            TokenKind::Hash => {
                self.advance();
                Type::Hash
            }
            TokenKind::Identifier(_) | TokenKind::Launch => {
                let mut name = self.parse_name_path()?;
                if self.check(&TokenKind::Lt) {
                    self.advance();
                    let mut args = Vec::new();
                    while !self.check(&TokenKind::Gt) && !self.check(&TokenKind::Eof) {
                        if let TokenKind::Integer(value) = self.current().kind {
                            args.push(Type::Named(value.to_string()));
                            self.advance();
                        } else {
                            args.push(self.parse_type()?);
                        }
                        if self.check(&TokenKind::Comma) {
                            self.advance();
                        } else {
                            break;
                        }
                    }
                    self.expect(TokenKind::Gt)?;
                    let rendered_args = args.iter().map(Self::render_type).collect::<Vec<_>>().join(", ");
                    name.push('<');
                    name.push_str(&rendered_args);
                    name.push('>');
                }
                Type::Named(name)
            }
            TokenKind::LBracket => {
                self.advance();
                let elem_ty = self.parse_type()?;
                self.expect(TokenKind::Semi)?;
                let size = match &self.current().kind {
                    TokenKind::Integer(n) => {
                        let size = usize::try_from(*n)
                            .map_err(|_| CompileError::new("array size exceeds the supported platform range", self.current().span))?;
                        self.advance();
                        size
                    }
                    _ => {
                        return Err(CompileError::new("expected array size", self.current().span));
                    }
                };
                self.expect(TokenKind::RBracket)?;
                Type::Array(Box::new(elem_ty), size)
            }
            TokenKind::LParen => {
                self.advance();
                let mut elems = Vec::new();
                while !self.check(&TokenKind::RParen) && !self.check(&TokenKind::Eof) {
                    elems.push(self.parse_type()?);
                    if self.check(&TokenKind::Comma) {
                        self.advance();
                    } else {
                        break;
                    }
                }
                self.expect(TokenKind::RParen)?;
                Type::Tuple(elems)
            }
            TokenKind::Ampersand => {
                self.advance();
                if self.check(&TokenKind::Mut) {
                    self.advance();
                    Type::MutRef(Box::new(self.parse_type()?))
                } else {
                    Type::Ref(Box::new(self.parse_type()?))
                }
            }
            TokenKind::ReadRef => {
                return Err(CompileError::new(
                    "`read_ref` is not a type qualifier; use `read name: T` for action/lock parameters or `read_ref<T>()` as an expression",
                    self.current().span,
                ));
            }
            _ => {
                return Err(CompileError::new(format!("expected type, found {}", self.current().kind), self.current().span));
            }
        };

        Ok(ty)
    }

    fn render_type(ty: &Type) -> String {
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
            Type::Array(elem, size) => format!("[{}; {}]", Self::render_type(elem), size),
            Type::Tuple(types) => format!("({})", types.iter().map(Self::render_type).collect::<Vec<_>>().join(", ")),
            Type::Named(name) => name.clone(),
            Type::Ref(inner) => format!("&{}", Self::render_type(inner)),
            Type::MutRef(inner) => format!("&mut {}", Self::render_type(inner)),
        }
    }

    fn parse_action(&mut self, effect: Option<EffectClass>, scheduler_hint: Option<SchedulerHint>) -> Result<ActionDef> {
        let start_span = self.current().span;
        self.expect(TokenKind::Action)?;

        let name = self.parse_name()?;

        let params = self.parse_params()?;

        let (return_type, outputs) = if self.check(&TokenKind::Arrow) {
            self.advance();
            self.parse_action_output_signature()?
        } else {
            (None, Vec::new())
        };

        let (state_edges, body) = self.parse_action_body()?;

        let end_span = self.current().span;
        let effect_declared = effect.is_some();

        Ok(ActionDef {
            name,
            params,
            return_type,
            outputs,
            state_edges,
            body,
            effect: effect.unwrap_or(EffectClass::Pure),
            effect_declared,
            scheduler_hint,
            next_surface: None,
            doc_comment: None,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_action_output_signature(&mut self) -> Result<(Option<Type>, Vec<ActionOutput>)> {
        self.skip_newlines();

        if self.check(&TokenKind::LParen) && self.action_output_tuple_looks_named() {
            self.advance();
            self.skip_newlines();
            let mut outputs = Vec::new();
            while !self.check(&TokenKind::RParen) && !self.check(&TokenKind::Eof) {
                outputs.push(self.parse_action_output_binding()?);
                if self.check(&TokenKind::Comma) {
                    self.advance();
                    self.skip_newlines();
                } else {
                    break;
                }
            }
            self.expect(TokenKind::RParen)?;
            return Ok((None, outputs));
        }

        if self.action_output_looks_named() {
            return Ok((None, vec![self.parse_action_output_binding()?]));
        }

        Ok((Some(self.parse_type()?), Vec::new()))
    }

    fn action_output_tuple_looks_named(&self) -> bool {
        matches!((&self.peek(1).kind, &self.peek(2).kind), (TokenKind::Identifier(_), TokenKind::Colon))
    }

    fn action_output_looks_named(&self) -> bool {
        matches!((&self.current().kind, &self.peek(1).kind), (TokenKind::Identifier(_), TokenKind::Colon))
    }

    fn parse_action_output_binding(&mut self) -> Result<ActionOutput> {
        let start_span = self.current().span;
        let name = self.parse_name()?;
        self.expect(TokenKind::Colon)?;
        let ty = self.parse_type()?;
        let end_span = self.current().span;
        Ok(ActionOutput { name, ty, span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column) })
    }

    fn parse_action_clauses(&mut self) -> Result<Vec<ActionStateEdge>> {
        let mut state_edges = Vec::new();

        loop {
            self.skip_newlines();
            match &self.current().kind {
                TokenKind::Transition => {
                    state_edges.extend(self.parse_action_state_edges()?);
                }
                _ => break,
            }
        }

        Ok(state_edges)
    }

    fn parse_action_body(&mut self) -> Result<(Vec<ActionStateEdge>, Vec<Stmt>)> {
        self.skip_newlines();
        self.expect(TokenKind::LBrace)?;
        self.skip_newlines();

        let state_edges = self.parse_action_clauses()?;
        self.skip_newlines();
        if matches!(&self.current().kind, TokenKind::Identifier(name) if name == "where") {
            return Err(CompileError::new("`where` action proof blocks are not supported; use `verification`", self.current().span));
        }
        self.parse_verification_marker()?;

        let mut stmts = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
            if let Some(stmt) = self.parse_stmt_recovering()? {
                stmts.push(stmt);
            }
            self.skip_newlines();
        }
        self.expect(TokenKind::RBrace)?;

        Ok((state_edges, stmts))
    }

    fn parse_action_state_edges(&mut self) -> Result<Vec<ActionStateEdge>> {
        if !self.check(&TokenKind::Transition) {
            return Ok(Vec::new());
        }

        let mut edges = Vec::new();
        while self.check(&TokenKind::Transition) {
            self.advance();
            self.skip_newlines();
            if self.check(&TokenKind::LBrace) {
                return Err(CompileError::new(
                    "transition block syntax is not part of the canonical action surface",
                    self.current().span,
                ));
            }
            loop {
                edges.push(self.parse_action_state_edge()?);

                if self.check(&TokenKind::Comma) {
                    self.advance();
                    continue;
                }
                break;
            }
            self.skip_newlines();
        }

        Ok(edges)
    }

    fn parse_action_state_edge(&mut self) -> Result<ActionStateEdge> {
        let start_span = self.current().span;
        let first = self.parse_name_path()?;
        if !self.check(&TokenKind::Dot) {
            self.expect(TokenKind::Arrow)?;
            let output_start = self.current().span;
            let output = self.parse_name_path()?;
            if self.check(&TokenKind::Dot) {
                return Err(CompileError::new(
                    "lineage transition output must be a binding name: transition input -> output",
                    output_start,
                ));
            }
            let end_span = self.current().span;
            return Ok(ActionStateEdge {
                path: StateFieldPath { base: first, field: String::new(), span: start_span },
                to_path: StateFieldPath { base: output, field: String::new(), span: output_start },
                from: String::new(),
                to: String::new(),
                span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
            });
        }
        self.advance();
        let field = self.parse_name()?;
        let path_span = Span::new(start_span.start, self.current().span.end, start_span.line, start_span.column);
        let path = StateFieldPath { base: first, field, span: path_span };
        if !self.check(&TokenKind::Colon) {
            return Err(CompileError::new(
                "state transition must put ':' before the source state: transition input.state: From -> output.state: To",
                self.current().span,
            ));
        }
        self.advance();
        let from = self.parse_name_path()?;
        self.expect(TokenKind::Arrow)?;
        let to_start_span = self.current().span;
        let to_first = self.parse_name_path()?;
        if !self.check(&TokenKind::Dot) {
            return Err(CompileError::new(
                "state transition must use an explicit output field path: transition input.state: From -> output.state: To",
                to_start_span,
            ));
        }
        self.advance();
        let to_field = self.parse_name()?;
        let to_path_span = Span::new(to_start_span.start, self.current().span.end, to_start_span.line, to_start_span.column);
        let to_path = StateFieldPath { base: to_first, field: to_field, span: to_path_span };
        if !self.check(&TokenKind::Colon) {
            return Err(CompileError::new(
                "state transition must put ':' before the target state: transition input.state: From -> output.state: To",
                self.current().span,
            ));
        }
        self.advance();
        let to = self.parse_name_path()?;
        let end_span = self.current().span;
        Ok(ActionStateEdge {
            path,
            to_path,
            from,
            to,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_fn(&mut self, effect: Option<EffectClass>) -> Result<FnDef> {
        let start_span = self.current().span;
        self.expect(TokenKind::Fn)?;

        let name = self.parse_name()?;
        let type_params = self.parse_type_params()?;
        let params = self.parse_params()?;
        let return_type = if self.check(&TokenKind::Arrow) {
            self.advance();
            Some(self.parse_type()?)
        } else {
            None
        };
        let body = self.parse_block()?;
        let end_span = self.current().span;

        Ok(FnDef {
            name,
            type_params,
            params,
            return_type,
            body,
            effect: effect.unwrap_or(EffectClass::Pure),
            effect_declared: effect.is_some(),
            doc_comment: None,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_lock(&mut self) -> Result<LockDef> {
        let start_span = self.current().span;
        self.expect(TokenKind::Lock)?;

        let name = self.parse_name()?;

        let params = self.parse_params()?;
        let return_type = if self.check(&TokenKind::Arrow) {
            self.advance();
            self.parse_type()?
        } else {
            Type::Bool
        };
        self.skip_newlines();
        self.expect(TokenKind::LBrace)?;
        self.skip_newlines();
        self.parse_verification_marker()?;
        let mut body = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
            if let Some(stmt) = self.parse_stmt_recovering()? {
                body.push(stmt);
            }
            self.skip_newlines();
        }
        self.expect(TokenKind::RBrace)?;

        let end_span = self.current().span;
        Ok(LockDef {
            name,
            params,
            return_type,
            body,
            next_surface: None,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_params(&mut self) -> Result<Vec<Param>> {
        self.expect(TokenKind::LParen)?;

        let mut params = Vec::new();
        loop {
            self.skip_newlines();
            if self.check(&TokenKind::RParen) || self.check(&TokenKind::Eof) {
                break;
            }
            let param = self.parse_param()?;
            params.push(param);

            if self.check(&TokenKind::Comma) {
                self.advance();
            } else {
                break;
            }
        }

        self.skip_newlines();
        self.expect(TokenKind::RParen)?;
        Ok(params)
    }

    fn parse_param(&mut self) -> Result<Param> {
        let start_span = self.current().span;

        if self.check(&TokenKind::Ref) {
            return Err(CompileError::new(
                "parameter modifier 'ref' is reserved but unsupported; use '&T' for read-only helper views, or `action(before: T) -> after: T` plus `transition` and `require` constraints for Cell state updates",
                self.current().span,
            ));
        }
        let is_ref = false;

        let is_mut = if self.check(&TokenKind::Mut) {
            self.advance();
            true
        } else {
            false
        };

        let (prefix_source, prefix_read_ref) = self.parse_param_source_prefix()?;
        let name = self.parse_name()?;

        self.expect(TokenKind::Colon)?;
        let postfix_source = if prefix_source == ParamSource::Default && !prefix_read_ref {
            self.parse_param_source_marker()
        } else {
            ParamSource::Default
        };
        let source = if postfix_source == ParamSource::Default { prefix_source } else { postfix_source };
        let is_read_ref = prefix_read_ref;
        let mut ty = if source == ParamSource::Protected {
            if is_read_ref {
                return Err(CompileError::new(
                    "protected parameters already denote the lock's protected read-only Cell view; remove 'read_ref'",
                    self.current().span,
                ));
            }
            let protected_ty = self.parse_type()?;
            match protected_ty {
                Type::Ref(_) | Type::MutRef(_) => {
                    return Err(CompileError::new(
                        "protected parameters use 'protected name: T', not 'protected name: &T'",
                        self.current().span,
                    ));
                }
                ty => Type::Ref(Box::new(ty)),
            }
        } else {
            self.parse_type()?
        };
        if prefix_read_ref && !matches!(ty, Type::Ref(_)) {
            ty = Type::Ref(Box::new(ty));
        }

        let end_span = self.current().span;
        Ok(Param {
            name,
            ty,
            is_mut,
            is_ref,
            is_read_ref,
            source,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_param_source_prefix(&mut self) -> Result<(ParamSource, bool)> {
        let current_name = Self::token_ident_like_name(&self.current().kind);
        let next_is_name = Self::token_ident_like_name(&self.peek(1).kind).is_some();
        let next_next_is_colon = matches!(&self.peek(2).kind, TokenKind::Colon);
        if !next_is_name || !next_next_is_colon {
            return Ok((ParamSource::Default, false));
        }
        match current_name.as_deref() {
            Some("read") => {
                self.advance();
                Ok((ParamSource::Default, true))
            }
            Some("input") => {
                self.advance();
                Ok((ParamSource::Input, false))
            }
            Some("output") => Err(CompileError::new(
                "`output name: T` is only valid on the action return side; write `action f(input: T) -> output: T`",
                self.current().span,
            )),
            Some("protected") => {
                self.advance();
                Ok((ParamSource::Protected, false))
            }
            Some("witness") => {
                self.advance();
                Ok((ParamSource::Witness, false))
            }
            Some("lock_args") => {
                self.advance();
                Ok((ParamSource::LockArgs, false))
            }
            _ => Ok((ParamSource::Default, false)),
        }
    }

    fn parse_param_source_marker(&mut self) -> ParamSource {
        let source = match &self.current().kind {
            TokenKind::Identifier(name) if name == "protected" => ParamSource::Protected,
            TokenKind::Identifier(name) if name == "witness" => ParamSource::Witness,
            TokenKind::Identifier(name) if name == "lock_args" => ParamSource::LockArgs,
            _ => ParamSource::Default,
        };
        if source != ParamSource::Default {
            self.advance();
        }
        source
    }

    fn parse_block(&mut self) -> Result<Vec<Stmt>> {
        self.expect(TokenKind::LBrace)?;
        self.skip_newlines();

        let mut stmts = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
            if let Some(stmt) = self.parse_stmt_recovering()? {
                stmts.push(stmt);
            }
            self.skip_newlines();
        }

        self.expect(TokenKind::RBrace)?;
        Ok(stmts)
    }

    fn parse_stmt(&mut self) -> Result<Stmt> {
        if self.statement_depth >= MAX_PARSE_RECURSION_DEPTH {
            return Err(CompileError::new(
                format!("statement nesting exceeds the parser limit of {}", MAX_PARSE_RECURSION_DEPTH),
                self.current().span,
            ));
        }
        self.statement_depth += 1;
        let result = self.parse_stmt_inner();
        self.statement_depth -= 1;
        result
    }

    fn parse_stmt_inner(&mut self) -> Result<Stmt> {
        let stmt = match &self.current().kind {
            TokenKind::Let => Stmt::Let(self.parse_let()?),
            TokenKind::Return => Stmt::Return(self.parse_return()?),
            TokenKind::If => Stmt::If(self.parse_if()?),
            TokenKind::For => Stmt::For(self.parse_for()?),
            TokenKind::While => Stmt::While(self.parse_while()?),
            TokenKind::Break => Stmt::Break(self.parse_loop_control(TokenKind::Break)?),
            TokenKind::Continue => Stmt::Continue(self.parse_loop_control(TokenKind::Continue)?),
            TokenKind::Label => self.parse_labeled_loop()?,
            TokenKind::Borrow => Stmt::Borrow(self.parse_borrow()?),
            _ if self.is_replace_relation_ahead() => Stmt::Expr(self.parse_replace_relation()?),
            _ => {
                let expr = self.parse_expr()?;
                Stmt::Expr(expr)
            }
        };
        self.consume_optional_semi();
        Ok(stmt)
    }

    /// The successor relation is authoring-route syntax: `replace x -> y {`.
    /// It is recognised contextually so `replace` stays an ordinary identifier
    /// everywhere else, including capability lists and the frozen Edition 2026
    /// grammar.
    fn is_replace_relation_ahead(&self) -> bool {
        matches!(self.entry_body_grammar, EntryBodyGrammar::ConstraintBlock)
            && matches!(&self.current().kind, TokenKind::Identifier(name) if name == "replace")
            && matches!(&self.peek(1).kind, TokenKind::Identifier(_))
            && matches!(&self.peek(2).kind, TokenKind::Arrow)
    }

    fn expect_identifier(&mut self, what: &str) -> Result<String> {
        if let TokenKind::Identifier(name) = &self.current().kind {
            let name = name.clone();
            self.advance();
            Ok(name)
        } else {
            Err(CompileError::new(format!("expected {what}, found `{}`", self.current().kind), self.current().span))
        }
    }

    fn expect_identifier_keyword(&mut self, keyword: &str, spelling: &str) -> Result<()> {
        if matches!(&self.current().kind, TokenKind::Identifier(name) if name == keyword) {
            self.advance();
            Ok(())
        } else {
            Err(CompileError::new(format!("expected {spelling}"), self.current().span))
        }
    }

    fn parse_replace_relation(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        self.advance(); // `replace`
        let before = self.expect_identifier("relation predecessor")?;
        self.expect(TokenKind::Arrow)?;
        let after = self.expect_identifier("relation successor")?;

        let mut data: Option<ReplaceDataTreatment> = None;
        let mut lock: Option<ReplaceLockTreatment> = None;
        let mut capacity: Option<ReplaceCapacityTreatment> = None;
        let mut identity: Option<ReplaceIdentityTreatment> = None;

        self.skip_newlines();
        self.expect(TokenKind::LBrace)?;
        loop {
            self.skip_newlines();
            if self.check(&TokenKind::RBrace) || self.check(&TokenKind::Eof) {
                break;
            }
            let keyword = match &self.current().kind {
                TokenKind::Identifier(name) => name.clone(),
                // `lock` is a lexer keyword, not an identifier.
                TokenKind::Lock => "lock".to_string(),
                _ => {
                    return Err(CompileError::new(
                        "expected a `data`, `lock`, `capacity` or `identity` treatment",
                        self.current().span,
                    ));
                }
            };
            self.advance();
            match keyword.as_str() {
                "data" => {
                    if data.is_some() {
                        return Err(CompileError::new("duplicate `data` treatment", self.current().span));
                    }
                    data = Some(self.parse_replace_data_treatment()?);
                }
                "lock" => {
                    if lock.is_some() {
                        return Err(CompileError::new("duplicate `lock` treatment", self.current().span));
                    }
                    lock = Some(self.parse_replace_lock_treatment()?);
                }
                "capacity" => {
                    if capacity.is_some() {
                        return Err(CompileError::new("duplicate `capacity` treatment", self.current().span));
                    }
                    self.expect(TokenKind::Eq)?;
                    self.expect_identifier_keyword("same", "`capacity = same`")?;
                    capacity = Some(ReplaceCapacityTreatment::Same);
                }
                "identity" => {
                    if identity.is_some() {
                        return Err(CompileError::new("duplicate `identity` treatment", self.current().span));
                    }
                    self.expect(TokenKind::Eq)?;
                    self.expect_identifier_keyword("same", "`identity = same`")?;
                    identity = Some(ReplaceIdentityTreatment::Same);
                }
                _ => {
                    return Err(CompileError::new(
                        format!("unknown relation treatment `{keyword}`; expected `data`, `lock`, `capacity` or `identity`"),
                        self.current().span,
                    ));
                }
            }
            self.consume_optional_semi();
        }
        self.skip_newlines();
        self.expect(TokenKind::RBrace)?;

        let missing: Vec<&str> =
            [("data", data.is_none()), ("lock", lock.is_none()), ("capacity", capacity.is_none()), ("identity", identity.is_none())]
                .into_iter()
                .filter(|(_, missing)| *missing)
                .map(|(name, _)| name)
                .collect();
        if !missing.is_empty() {
            return Err(CompileError::new(
                format!("replace relation must state every treatment explicitly; missing {}", missing.join(", ")),
                start_span,
            ));
        }

        Ok(Expr::ReplaceRelation(ReplaceRelation {
            before,
            after,
            data: data.unwrap(),
            lock: lock.unwrap(),
            capacity: capacity.unwrap(),
            identity: identity.unwrap(),
            span: start_span,
        }))
    }

    fn parse_replace_data_treatment(&mut self) -> Result<ReplaceDataTreatment> {
        if self.check(&TokenKind::Eq) {
            // `data = same except { f = expr, ... }`
            self.advance();
            self.expect_identifier_keyword("same", "`data = same except { ... }`")?;
            self.expect_identifier_keyword("except", "`data = same except { ... }`")?;
            self.skip_newlines();
            self.expect(TokenKind::LBrace)?;
            let mut assigned = Vec::new();
            loop {
                self.skip_newlines();
                if self.check(&TokenKind::RBrace) || self.check(&TokenKind::Eof) {
                    break;
                }
                let field = self.expect_identifier("`same except` field")?;
                if assigned.iter().any(|(name, _)| *name == field) {
                    return Err(CompileError::new(format!("duplicate `same except` field `{field}`"), self.current().span));
                }
                self.expect(TokenKind::Eq)?;
                let value = self.parse_expr()?;
                assigned.push((field, value));
                self.consume_optional_semi();
            }
            self.skip_newlines();
            self.expect(TokenKind::RBrace)?;
            return Ok(ReplaceDataTreatment::SameExcept(assigned));
        }

        // `data { same { f, ... } f = expr ... }`
        self.skip_newlines();
        self.expect(TokenKind::LBrace)?;
        let mut treatments = Vec::new();
        loop {
            self.skip_newlines();
            if self.check(&TokenKind::RBrace) || self.check(&TokenKind::Eof) {
                break;
            }
            if matches!(&self.current().kind, TokenKind::Identifier(name) if name == "same")
                && matches!(&self.peek(1).kind, TokenKind::LBrace)
            {
                self.advance();
                self.expect(TokenKind::LBrace)?;
                let mut fields = Vec::new();
                let mut seen = std::collections::BTreeSet::new();
                loop {
                    self.skip_newlines();
                    if self.check(&TokenKind::RBrace) || self.check(&TokenKind::Eof) {
                        break;
                    }
                    let field = self.expect_identifier("`same` field")?;
                    if !seen.insert(field.clone()) {
                        return Err(CompileError::new(format!("duplicate `same` field `{field}`"), self.current().span));
                    }
                    fields.push(ReplaceFieldTreatment::Same(field));
                    self.consume_optional_semi();
                }
                self.skip_newlines();
                self.expect(TokenKind::RBrace)?;
                treatments.extend(fields);
            } else {
                let field = self.expect_identifier("relation data field")?;
                self.expect(TokenKind::Eq)?;
                if matches!(&self.current().kind, TokenKind::Identifier(name) if name == "same") {
                    self.advance();
                    treatments.push(ReplaceFieldTreatment::Same(field));
                } else {
                    let value = self.parse_expr()?;
                    treatments.push(ReplaceFieldTreatment::Assign(field, value));
                }
                self.consume_optional_semi();
            }
        }
        self.skip_newlines();
        self.expect(TokenKind::RBrace)?;
        Ok(ReplaceDataTreatment::Fields(treatments))
    }

    fn parse_replace_lock_treatment(&mut self) -> Result<ReplaceLockTreatment> {
        self.expect(TokenKind::Eq)?;
        if matches!(&self.current().kind, TokenKind::Identifier(name) if name == "same") {
            self.advance();
            return Ok(ReplaceLockTreatment::Same);
        }
        if matches!(&self.current().kind, TokenKind::Identifier(name) if name == "exact")
            && matches!(&self.peek(1).kind, TokenKind::LParen)
        {
            self.advance();
            self.expect(TokenKind::LParen)?;
            let lock = self.parse_expr()?;
            self.expect(TokenKind::RParen)?;
            return Ok(ReplaceLockTreatment::Exact(Box::new(lock)));
        }
        if matches!(&self.current().kind, TokenKind::Identifier(name) if name == "exact_hash")
            && matches!(&self.peek(1).kind, TokenKind::LParen)
        {
            self.advance();
            self.expect(TokenKind::LParen)?;
            let lock = self.parse_expr()?;
            self.expect(TokenKind::RParen)?;
            return Ok(ReplaceLockTreatment::ExactHash(Box::new(lock)));
        }
        Err(CompileError::new(
            "expected `lock = same`, `lock = exact(address)` or `lock = exact_hash(script_hash)`",
            self.current().span,
        ))
    }

    fn parse_let(&mut self) -> Result<LetStmt> {
        let start_span = self.current().span;
        self.expect(TokenKind::Let)?;

        let is_mut = if self.check(&TokenKind::Mut) {
            self.advance();
            true
        } else {
            false
        };

        let pattern = self.parse_binding_pattern()?;

        let ty = if self.check(&TokenKind::Colon) {
            self.advance();
            Some(self.parse_type()?)
        } else {
            None
        };

        self.expect(TokenKind::Eq)?;
        let value = self.parse_expr()?;

        let end_span = self.current().span;
        Ok(LetStmt { pattern, ty, value, is_mut, span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column) })
    }

    fn parse_return(&mut self) -> Result<ReturnStmt> {
        let start_span = self.current().span;
        self.expect(TokenKind::Return)?;

        let value = if self.check(&TokenKind::Newline) || self.check(&TokenKind::RBrace) || self.check(&TokenKind::Eof) {
            None
        } else {
            Some(self.parse_expr()?)
        };
        let end_span = self.previous_non_newline().span;
        Ok(ReturnStmt { value, span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column) })
    }

    fn parse_if(&mut self) -> Result<IfStmt> {
        if self.if_depth >= MAX_PARSE_RECURSION_DEPTH {
            return Err(CompileError::new(
                format!("if nesting exceeds the parser limit of {}", MAX_PARSE_RECURSION_DEPTH),
                self.current().span,
            ));
        }
        self.if_depth += 1;
        let result = self.parse_if_inner();
        self.if_depth -= 1;
        result
    }

    fn parse_if_inner(&mut self) -> Result<IfStmt> {
        let start_span = self.current().span;
        self.expect(TokenKind::If)?;

        let condition = self.parse_expr()?;
        let then_branch = self.parse_block()?;

        let else_branch = if self.check(&TokenKind::Else) {
            self.advance();
            if self.check(&TokenKind::If) {
                // else if
                let inner_if = self.parse_if()?;
                Some(vec![Stmt::If(inner_if)])
            } else {
                Some(self.parse_block()?)
            }
        } else {
            None
        };

        let end_span = self.current().span;
        Ok(IfStmt {
            condition,
            then_branch,
            else_branch,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_for(&mut self) -> Result<ForStmt> {
        let start_span = self.current().span;
        self.expect(TokenKind::For)?;

        let pattern = self.parse_binding_pattern()?;

        self.expect(TokenKind::In)?;
        let iterable = self.parse_expr()?;
        let body = self.parse_block()?;

        let end_span = self.current().span;
        Ok(ForStmt {
            label: None,
            pattern,
            iterable,
            body,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_while(&mut self) -> Result<WhileStmt> {
        let start_span = self.current().span;
        self.expect(TokenKind::While)?;

        let condition = self.parse_expr()?;
        let body = self.parse_block()?;

        let end_span = self.current().span;
        Ok(WhileStmt {
            label: None,
            condition,
            body,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_loop_control(&mut self, keyword: TokenKind) -> Result<LoopControlStmt> {
        let start = self.current().span;
        self.expect(keyword)?;
        let label = self.ident_like_name().map(|_| self.parse_name()).transpose()?;
        let end = self.current().span;
        Ok(LoopControlStmt { label, span: Span::new(start.start, end.start, start.line, start.column) })
    }

    fn parse_labeled_loop(&mut self) -> Result<Stmt> {
        self.expect(TokenKind::Label)?;
        let label = self.parse_name()?;
        self.expect(TokenKind::Colon)?;
        match self.current().kind {
            TokenKind::For => {
                let mut statement = self.parse_for()?;
                statement.label = Some(label);
                Ok(Stmt::For(statement))
            }
            TokenKind::While => {
                let mut statement = self.parse_while()?;
                statement.label = Some(label);
                Ok(Stmt::While(statement))
            }
            _ => Err(CompileError::new("label must precede a for or while loop", self.current().span)),
        }
    }

    fn parse_borrow(&mut self) -> Result<BorrowStmt> {
        let start_span = self.current().span;
        self.expect(TokenKind::Borrow)?;
        let root = self.parse_name()?;
        let mut path = Vec::new();
        while self.check(&TokenKind::Dot) {
            self.advance();
            path.push(self.parse_name()?);
        }
        let as_span = self.current().span;
        let keyword = self.parse_name()?;
        if keyword != "as" {
            return Err(CompileError::new("expected 'as' in borrow block", as_span));
        }
        let binding = self.parse_name()?;
        let body = self.parse_block()?;
        let end_span = self.previous_non_newline().span;
        Ok(BorrowStmt {
            root,
            path,
            binding,
            body,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_expr(&mut self) -> Result<Expr> {
        if self.expression_depth >= MAX_PARSE_RECURSION_DEPTH {
            return Err(CompileError::new(
                format!("expression nesting exceeds the parser limit of {}", MAX_PARSE_RECURSION_DEPTH),
                self.current().span,
            ));
        }
        self.expression_depth += 1;
        let result = self.parse_expr_inner();
        self.expression_depth -= 1;
        result
    }

    fn parse_expr_inner(&mut self) -> Result<Expr> {
        self.skip_newlines();
        self.parse_assignment()
    }

    fn parse_assignment(&mut self) -> Result<Expr> {
        let left = self.parse_range()?;
        let start_span = self.current().span;

        if self.check(&TokenKind::Eq) {
            self.advance();
            let right = self.parse_expr()?;
            return Ok(Expr::Assign(AssignExpr {
                target: Box::new(left),
                op: AssignOp::Assign,
                value: Box::new(right),
                span: start_span,
            }));
        }

        if self.check(&TokenKind::Plus) && self.peek(1).kind == TokenKind::Eq {
            self.advance();
            self.advance();
            let right = self.parse_expr()?;
            return Ok(Expr::Assign(AssignExpr {
                target: Box::new(left),
                op: AssignOp::AddAssign,
                value: Box::new(right),
                span: start_span,
            }));
        }

        Ok(left)
    }

    fn parse_range(&mut self) -> Result<Expr> {
        let left = self.parse_or()?;
        if self.check(&TokenKind::Dot) && self.peek(1).kind == TokenKind::Dot {
            let start_span = self.current().span;
            self.advance();
            self.advance();
            let right = self.parse_or()?;
            Ok(Expr::Range(RangeExpr { start: Box::new(left), end: Box::new(right), span: start_span }))
        } else {
            Ok(left)
        }
    }

    fn parse_or(&mut self) -> Result<Expr> {
        let mut left = self.parse_and()?;

        loop {
            self.skip_newlines();
            if !self.check(&TokenKind::Or) {
                break;
            }
            let op = BinaryOp::Or;
            let start_span = self.current().span;
            self.advance();
            self.skip_newlines();
            let right = self.parse_and()?;
            left = Expr::Binary(BinaryExpr { op, left: Box::new(left), right: Box::new(right), span: start_span });
        }

        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr> {
        let mut left = self.parse_bitwise_or()?;

        loop {
            self.skip_newlines();
            if !self.check(&TokenKind::And) {
                break;
            }
            let op = BinaryOp::And;
            let start_span = self.current().span;
            self.advance();
            self.skip_newlines();
            let right = self.parse_bitwise_or()?;
            left = Expr::Binary(BinaryExpr { op, left: Box::new(left), right: Box::new(right), span: start_span });
        }

        Ok(left)
    }

    fn parse_bitwise_or(&mut self) -> Result<Expr> {
        let mut left = self.parse_bitwise_xor()?;
        loop {
            self.skip_newlines();
            if !self.check(&TokenKind::Pipe) {
                break;
            }
            let start_span = self.current().span;
            self.advance();
            self.skip_newlines();
            let right = self.parse_bitwise_xor()?;
            left = Expr::Binary(BinaryExpr { op: BinaryOp::BitOr, left: Box::new(left), right: Box::new(right), span: start_span });
        }
        Ok(left)
    }

    fn parse_bitwise_xor(&mut self) -> Result<Expr> {
        let mut left = self.parse_bitwise_and()?;
        loop {
            self.skip_newlines();
            if !self.check(&TokenKind::Caret) {
                break;
            }
            let start_span = self.current().span;
            self.advance();
            self.skip_newlines();
            let right = self.parse_bitwise_and()?;
            left = Expr::Binary(BinaryExpr { op: BinaryOp::BitXor, left: Box::new(left), right: Box::new(right), span: start_span });
        }
        Ok(left)
    }

    fn parse_bitwise_and(&mut self) -> Result<Expr> {
        let mut left = self.parse_equality()?;
        loop {
            self.skip_newlines();
            if !self.check(&TokenKind::Ampersand) {
                break;
            }
            let start_span = self.current().span;
            self.advance();
            self.skip_newlines();
            let right = self.parse_equality()?;
            left = Expr::Binary(BinaryExpr { op: BinaryOp::BitAnd, left: Box::new(left), right: Box::new(right), span: start_span });
        }
        Ok(left)
    }

    fn parse_equality(&mut self) -> Result<Expr> {
        let mut left = self.parse_comparison()?;

        loop {
            self.skip_newlines();
            let op = if self.check(&TokenKind::EqEq) {
                self.advance();
                Some(BinaryOp::Eq)
            } else if self.check(&TokenKind::NotEq) {
                self.advance();
                Some(BinaryOp::Ne)
            } else {
                None
            };

            if let Some(op) = op {
                let start_span = self.current().span;
                self.skip_newlines();
                let right = self.parse_comparison()?;
                left = Expr::Binary(BinaryExpr { op, left: Box::new(left), right: Box::new(right), span: start_span });
            } else {
                break;
            }
        }

        Ok(left)
    }

    fn parse_comparison(&mut self) -> Result<Expr> {
        let mut left = self.parse_shift()?;

        loop {
            self.skip_newlines();
            let op = if self.check(&TokenKind::Lt) {
                self.advance();
                Some(BinaryOp::Lt)
            } else if self.check(&TokenKind::Le) {
                self.advance();
                Some(BinaryOp::Le)
            } else if self.check(&TokenKind::Gt) {
                self.advance();
                Some(BinaryOp::Gt)
            } else if self.check(&TokenKind::Ge) {
                self.advance();
                Some(BinaryOp::Ge)
            } else {
                None
            };

            if let Some(op) = op {
                let start_span = self.current().span;
                self.skip_newlines();
                let right = self.parse_shift()?;
                left = Expr::Binary(BinaryExpr { op, left: Box::new(left), right: Box::new(right), span: start_span });
            } else {
                break;
            }
        }

        Ok(left)
    }

    fn parse_shift(&mut self) -> Result<Expr> {
        let mut left = self.parse_term()?;
        loop {
            self.skip_newlines();
            let op = if self.check(&TokenKind::Lt) && self.peek(1).kind == TokenKind::Lt {
                let span = self.current().span;
                self.advance();
                self.advance();
                Some((BinaryOp::Shl, span))
            } else if self.check(&TokenKind::Gt) && self.peek(1).kind == TokenKind::Gt {
                let span = self.current().span;
                self.advance();
                self.advance();
                Some((BinaryOp::Shr, span))
            } else {
                None
            };
            let Some((op, start_span)) = op else {
                break;
            };
            self.skip_newlines();
            let right = self.parse_term()?;
            left = Expr::Binary(BinaryExpr { op, left: Box::new(left), right: Box::new(right), span: start_span });
        }
        Ok(left)
    }

    fn parse_term(&mut self) -> Result<Expr> {
        let mut left = self.parse_factor()?;

        loop {
            self.skip_newlines();
            let op = if self.check(&TokenKind::Plus) && !matches!(&self.peek(1).kind, TokenKind::Eq) {
                self.advance();
                Some(BinaryOp::Add)
            } else if self.check(&TokenKind::Minus) {
                self.advance();
                Some(BinaryOp::Sub)
            } else {
                None
            };

            if let Some(op) = op {
                let start_span = self.current().span;
                self.skip_newlines();
                let right = self.parse_factor()?;
                left = Expr::Binary(BinaryExpr { op, left: Box::new(left), right: Box::new(right), span: start_span });
            } else {
                break;
            }
        }

        Ok(left)
    }

    fn parse_factor(&mut self) -> Result<Expr> {
        let mut left = self.parse_cast()?;

        loop {
            self.skip_newlines();
            let op = if self.check(&TokenKind::Star) {
                self.advance();
                Some(BinaryOp::Mul)
            } else if self.check(&TokenKind::Slash) {
                self.advance();
                Some(BinaryOp::Div)
            } else if self.check(&TokenKind::Percent) {
                self.advance();
                Some(BinaryOp::Mod)
            } else {
                None
            };

            if let Some(op) = op {
                let start_span = self.current().span;
                self.skip_newlines();
                let right = self.parse_cast()?;
                left = Expr::Binary(BinaryExpr { op, left: Box::new(left), right: Box::new(right), span: start_span });
            } else {
                break;
            }
        }

        Ok(left)
    }

    fn parse_cast(&mut self) -> Result<Expr> {
        let mut expr = self.parse_unary()?;
        loop {
            self.skip_newlines();
            let is_as = matches!(&self.current().kind, TokenKind::Identifier(name) if name == "as");
            if !is_as {
                break;
            }
            let start_span = self.current().span;
            self.advance();
            self.skip_newlines();
            let ty = self.parse_type()?;
            expr = Expr::Cast(CastExpr { expr: Box::new(expr), ty, span: start_span });
        }
        Ok(expr)
    }

    fn parse_unary(&mut self) -> Result<Expr> {
        if self.unary_depth >= MAX_PARSE_RECURSION_DEPTH {
            return Err(CompileError::new(
                format!("unary expression nesting exceeds the parser limit of {}", MAX_PARSE_RECURSION_DEPTH),
                self.current().span,
            ));
        }
        self.unary_depth += 1;
        let result = self.parse_unary_inner();
        self.unary_depth -= 1;
        result
    }

    fn parse_unary_inner(&mut self) -> Result<Expr> {
        if self.check(&TokenKind::Minus) {
            let start_span = self.current().span;
            self.advance();
            let expr = self.parse_unary()?;
            return Ok(Expr::Unary(UnaryExpr { op: UnaryOp::Neg, expr: Box::new(expr), span: start_span }));
        }

        if self.check(&TokenKind::Not) {
            let start_span = self.current().span;
            self.advance();
            let expr = self.parse_unary()?;
            return Ok(Expr::Unary(UnaryExpr { op: UnaryOp::Not, expr: Box::new(expr), span: start_span }));
        }

        if self.check(&TokenKind::Ampersand) {
            let start_span = self.current().span;
            self.advance();
            let expr = self.parse_unary()?;
            return Ok(Expr::Unary(UnaryExpr { op: UnaryOp::Ref, expr: Box::new(expr), span: start_span }));
        }

        if self.check(&TokenKind::Star) {
            let start_span = self.current().span;
            self.advance();
            let expr = self.parse_unary()?;
            return Ok(Expr::Unary(UnaryExpr { op: UnaryOp::Deref, expr: Box::new(expr), span: start_span }));
        }

        self.parse_postfix()
    }

    fn parse_postfix(&mut self) -> Result<Expr> {
        let mut expr = self.parse_primary()?;

        loop {
            if self.check(&TokenKind::Newline) {
                break;
            }
            if self.check(&TokenKind::Dot) && !matches!(&self.peek(1).kind, TokenKind::Dot) {
                self.advance();
                let field = match &self.current().kind {
                    _ if self.ident_like_name().is_some() => self.parse_name()?,
                    TokenKind::Integer(n) => {
                        let index = n.to_string();
                        self.advance();
                        index
                    }
                    _ => {
                        return Err(CompileError::new("expected field name", self.current().span));
                    }
                };
                expr = Expr::FieldAccess(FieldAccessExpr { expr: Box::new(expr), field, span: self.current().span });
            } else if self.check(&TokenKind::Lt) && self.supports_generic_call(&expr) {
                self.advance();
                let mut type_args = Vec::new();
                while !self.check(&TokenKind::Gt) && !self.check(&TokenKind::Eof) {
                    type_args.push(self.parse_type()?);
                    if self.check(&TokenKind::Comma) {
                        self.advance();
                    } else {
                        break;
                    }
                }
                self.expect(TokenKind::Gt)?;
                if !self.check(&TokenKind::LParen) {
                    return Err(CompileError::new("generic callable type arguments must be followed by '(...)'", self.current().span));
                }
                let args = self.parse_args()?;
                expr = Expr::Call(CallExpr { func: Box::new(expr), type_args, args, span: self.current().span });
            } else if self.check(&TokenKind::LParen) {
                let args = self.parse_args()?;
                expr = Expr::Call(CallExpr { func: Box::new(expr), type_args: Vec::new(), args, span: self.current().span });
            } else if self.check(&TokenKind::LBracket) {
                self.advance();
                let index = self.parse_expr()?;
                self.expect(TokenKind::RBracket)?;
                expr = Expr::Index(IndexExpr { expr: Box::new(expr), index: Box::new(index), span: self.current().span });
            } else {
                break;
            }
        }

        Ok(expr)
    }

    fn supports_generic_call(&self, expr: &Expr) -> bool {
        matches!(expr, Expr::Identifier(_)) && self.generic_arguments_followed_by(&TokenKind::LParen)
    }

    fn generic_arguments_followed_by(&self, follower: &TokenKind) -> bool {
        if !self.check(&TokenKind::Lt) {
            return false;
        }
        // Probe the type grammar, not angle-bracket balance across later statements.
        // A comparison may otherwise consume an unrelated function's `-> (...)`.
        // The probe owns its cursor/diagnostics and retains the type nesting budget.
        let mut probe = Self::new(self.tokens);
        probe.position = self.position + 1;
        probe.type_depth = self.type_depth;
        while !probe.check(&TokenKind::Gt) && !probe.check(&TokenKind::Eof) {
            if probe.parse_type().is_err() {
                return false;
            }
            if probe.check(&TokenKind::Comma) {
                probe.advance();
            } else {
                break;
            }
        }
        if !probe.check(&TokenKind::Gt) {
            return false;
        }
        probe.advance();
        probe.skip_newlines();
        probe.check(follower)
    }

    fn parse_primary(&mut self) -> Result<Expr> {
        match &self.current().kind {
            TokenKind::Integer(n) => {
                let val = *n;
                self.advance();
                Ok(Expr::Integer(val))
            }
            TokenKind::True => {
                self.advance();
                Ok(Expr::Bool(true))
            }
            TokenKind::False => {
                self.advance();
                Ok(Expr::Bool(false))
            }
            TokenKind::String(s) => {
                let val = s.clone();
                self.advance();
                Ok(Expr::String(val))
            }
            TokenKind::ByteString(b) => {
                let val = b.clone();
                self.advance();
                Ok(Expr::ByteString(val))
            }
            TokenKind::Create => self.parse_create(),
            TokenKind::Consume => self.parse_consume(),
            TokenKind::Preserve => self.parse_preserve(),
            TokenKind::DestroyKw => self.parse_destroy(),
            TokenKind::Launch => Err(CompileError::new(
                "launch is reserved for a post-v1 transaction builder and is not part of the executable language core; use explicit create/consume/destroy operations",
                self.current().span,
            )),
            TokenKind::ReadRef => self.parse_read_ref_expr(),
            TokenKind::If => self.parse_if_expr(),
            TokenKind::Match => self.parse_match_expr(),
            TokenKind::Require => self.parse_require(),
            TokenKind::Std => self.parse_stdlib_call(),
            _ if self.ident_like_name().is_some() => {
                if matches!(self.ident_like_name().as_deref(), Some("consume_each" | "create_each")) {
                    return self.parse_bounded_collection_each();
                }
                if matches!(self.ident_like_name().as_deref(), Some("claim")) && !self.check_next_lparen() {
                    return self.parse_claim_expr();
                }
                if matches!(self.ident_like_name().as_deref(), Some("settle")) && !self.check_next_lparen() {
                    return self.parse_settle_expr();
                }
                let name = self.parse_name_path()?;
                // v0.15 destruction policy forms (context-sensitive identifiers)
                match name.as_str() {
                    "destroy_singleton_type" => return self.parse_destroy_singleton_type(),
                    "destroy_unique" => return self.parse_destroy_unique(),
                    "destroy_instance" => return self.parse_destroy_instance(),
                    "burn_amount" => return self.parse_burn_amount(),
                    "create_unique" => return self.parse_create_unique_expr(),
                    "replace_unique" => return self.parse_replace_unique_expr(),
                    _ => {}
                }
                if self.check(&TokenKind::Lt)
                    && Self::looks_like_type_name(&name)
                    && self.generic_arguments_followed_by(&TokenKind::LBrace)
                {
                    self.advance();
                    let mut type_args = Vec::new();
                    while !self.check(&TokenKind::Gt) && !self.check(&TokenKind::Eof) {
                        type_args.push(self.parse_type()?);
                        if self.check(&TokenKind::Comma) {
                            self.advance();
                        } else {
                            break;
                        }
                    }
                    self.expect(TokenKind::Gt)?;
                    let rendered = type_args.iter().map(Self::render_type).collect::<Vec<_>>().join(", ");
                    return self.parse_struct_init(format!("{}<{}>", name, rendered));
                }
                if self.check(&TokenKind::LBrace) && Self::looks_like_type_name(&name) {
                    self.parse_struct_init(name)
                } else {
                    Ok(Expr::Identifier(name))
                }
            }
            TokenKind::LParen => {
                self.advance();
                if self.check(&TokenKind::RParen) {
                    self.advance();
                    return Ok(Expr::Tuple(vec![]));
                }
                let expr = self.parse_expr()?;
                if self.check(&TokenKind::Comma) {
                    let mut elems = vec![expr];
                    while self.check(&TokenKind::Comma) {
                        self.advance();
                        if self.check(&TokenKind::RParen) {
                            break;
                        }
                        elems.push(self.parse_expr()?);
                    }
                    self.expect(TokenKind::RParen)?;
                    Ok(Expr::Tuple(elems))
                } else {
                    self.expect(TokenKind::RParen)?;
                    Ok(expr)
                }
            }
            TokenKind::LBracket => self.parse_array_expr(),
            TokenKind::LBrace => {
                let stmts = self.parse_block()?;
                Ok(Expr::Block(stmts))
            }
            _ => Err(CompileError::new(format!("unexpected token in expression: {}", self.current().kind), self.current().span)),
        }
    }

    fn parse_bounded_collection_each(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        let operation = self.parse_name()?;
        let binding = self.parse_name()?;
        self.expect(TokenKind::In)?;
        let collection = self.parse_expr()?;
        if !self.check(&TokenKind::LBrace) {
            return Err(CompileError::new(format!("{} requires a braced per-element contract body", operation), self.current().span));
        }
        let body = self.parse_block()?;
        let end_span = self.current().span;
        Ok(Expr::Call(CallExpr {
            func: Box::new(Expr::Identifier(format!("__cellscript_{}", operation))),
            type_args: Vec::new(),
            args: vec![Expr::Identifier(binding), collection, Expr::Block(body)],
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }

    fn check_next_lparen(&self) -> bool {
        self.peek(1).kind == TokenKind::LParen
    }

    fn parse_array_expr(&mut self) -> Result<Expr> {
        self.expect(TokenKind::LBracket)?;
        let mut elems = Vec::new();
        loop {
            self.skip_newlines();
            if self.check(&TokenKind::RBracket) || self.check(&TokenKind::Eof) {
                break;
            }
            elems.push(self.parse_expr()?);
            self.skip_newlines();
            if self.check(&TokenKind::Comma) {
                self.advance();
                continue;
            }
            break;
        }
        self.expect(TokenKind::RBracket)?;
        Ok(Expr::Array(elems))
    }

    fn parse_args(&mut self) -> Result<Vec<Expr>> {
        self.expect(TokenKind::LParen)?;

        let mut args = Vec::new();
        loop {
            self.skip_newlines();
            if self.check(&TokenKind::RParen) || self.check(&TokenKind::Eof) {
                break;
            }
            args.push(self.parse_expr()?);
            if self.check(&TokenKind::Comma) {
                self.advance();
            } else {
                break;
            }
        }

        self.skip_newlines();
        self.expect(TokenKind::RParen)?;
        Ok(args)
    }

    fn parse_create(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        self.expect(TokenKind::Create)?;
        let first = self.parse_name_path()?;
        let (target, ty) = if self.check(&TokenKind::Eq) {
            self.advance();
            (Some(first), self.parse_name_path()?)
        } else {
            (None, first)
        };

        self.expect(TokenKind::LBrace)?;
        self.skip_newlines();

        let mut fields = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
            let field_name = self.parse_name()?;
            let value = if self.check(&TokenKind::Colon) {
                self.advance();
                self.parse_expr()?
            } else {
                Expr::Identifier(field_name.clone())
            };
            fields.push((field_name, value));

            if self.check(&TokenKind::Comma) {
                self.advance();
                self.skip_newlines();
            } else {
                self.skip_newlines();
            }
        }

        self.expect(TokenKind::RBrace)?;

        let lock = match &self.current().kind {
            TokenKind::Identifier(s) if s == "with_lock" => {
                self.advance();
                self.expect(TokenKind::LParen)?;
                let lock_expr = self.parse_expr()?;
                self.expect(TokenKind::RParen)?;
                Some(Box::new(lock_expr))
            }
            _ => None,
        };

        let end_span = self.current().span;
        Ok(Expr::Create(CreateExpr {
            target,
            ty,
            fields,
            lock,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }

    fn parse_consume(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        self.expect(TokenKind::Consume)?;

        let expr = self.parse_expr()?;

        let end_span = self.current().span;
        Ok(Expr::Consume(ConsumeExpr {
            expr: Box::new(expr),
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }

    fn parse_claim_expr(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        let keyword = self.parse_name()?;
        if keyword != "claim" {
            return Err(CompileError::new("expected 'claim'", start_span));
        }
        let receipt = self.parse_expr()?;

        let end_span = self.current().span;
        Ok(Expr::Claim(ClaimExpr {
            receipt: Box::new(receipt),
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }

    fn parse_settle_expr(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        let keyword = self.parse_name()?;
        if keyword != "settle" {
            return Err(CompileError::new("expected 'settle'", start_span));
        }
        let expr = self.parse_expr()?;

        let end_span = self.current().span;
        Ok(Expr::Settle(SettleExpr {
            expr: Box::new(expr),
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }

    fn parse_destroy(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        self.expect(TokenKind::DestroyKw)?;

        // Check for v0.15 destruction policy forms:
        //   destroy_singleton_type(cell)
        //   destroy_unique(cell, identity = type_id)
        //   destroy_instance(cell, identity_field = id)
        //   burn_amount(cell, field = amount)
        //   bare: destroy cell  (legacy compat → Default policy)
        let policy = if self.check(&TokenKind::LParen) {
            return Err(CompileError::new(
                "expected cell expression after destroy; for policy-specific forms use destroy_singleton_type, destroy_unique, destroy_instance, or burn_amount",
                self.current().span,
            ));
        } else {
            DestructionPolicy::Default
        };

        let expr = self.parse_expr()?;

        let end_span = self.current().span;
        Ok(Expr::Destroy(DestroyExpr {
            expr: Box::new(expr),
            policy,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }

    fn parse_destroy_singleton_type(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        // Already consumed the identifier "destroy_singleton_type"
        self.expect(TokenKind::LParen)?;
        let expr = self.parse_expr()?;
        self.expect(TokenKind::RParen)?;

        let end_span = self.current().span;
        Ok(Expr::Destroy(DestroyExpr {
            expr: Box::new(expr),
            policy: DestructionPolicy::SingletonType,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }

    fn parse_destroy_unique(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        // Already consumed the identifier "destroy_unique"
        self.expect(TokenKind::LParen)?;
        let expr = self.parse_expr()?;
        self.expect(TokenKind::Comma)?;
        let identity = self.parse_named_arg("identity")?;
        self.expect(TokenKind::RParen)?;

        let end_span = self.current().span;
        Ok(Expr::Destroy(DestroyExpr {
            expr: Box::new(expr),
            policy: DestructionPolicy::Unique { identity },
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }

    fn parse_destroy_instance(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        // Already consumed the identifier "destroy_instance"
        self.expect(TokenKind::LParen)?;
        let expr = self.parse_expr()?;
        self.expect(TokenKind::Comma)?;
        let identity_field = self.parse_named_arg("identity_field")?;
        self.expect(TokenKind::RParen)?;

        let end_span = self.current().span;
        Ok(Expr::Destroy(DestroyExpr {
            expr: Box::new(expr),
            policy: DestructionPolicy::Instance { identity_field },
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }

    fn parse_burn_amount(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        // Already consumed the identifier "burn_amount"
        self.expect(TokenKind::LParen)?;
        let expr = self.parse_expr()?;
        self.expect(TokenKind::Comma)?;
        let field = self.parse_named_arg("field")?;
        self.expect(TokenKind::RParen)?;

        let end_span = self.current().span;
        Ok(Expr::Destroy(DestroyExpr {
            expr: Box::new(expr),
            policy: DestructionPolicy::BurnAmount { field },
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }

    /// Parse a named argument like `identity = type_id` or `field = amount`.
    fn parse_named_arg(&mut self, expected_name: &str) -> Result<String> {
        let name = self.parse_name()?;
        if name != expected_name {
            return Err(CompileError::new(
                format!("expected named argument '{}', got '{}'", expected_name, name),
                self.current().span,
            ));
        }
        self.expect(TokenKind::Eq)?;
        let value = self.parse_name()?;
        Ok(value)
    }

    fn parse_create_unique_expr(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        // Already consumed the identifier "create_unique"
        self.expect(TokenKind::Lt)?;
        let ty = Self::render_type(&self.parse_type()?);
        self.expect(TokenKind::Gt)?;
        self.expect(TokenKind::LParen)?;
        let identity = self.parse_identity_policy_from_args()?;
        self.expect(TokenKind::RParen)?;

        let fields = self.parse_field_init_list()?;

        let lock = if self.ident_like_name().as_deref() == Some("with_lock") {
            self.advance();
            self.expect(TokenKind::LParen)?;
            let lock_expr = self.parse_expr()?;
            self.expect(TokenKind::RParen)?;
            Some(Box::new(lock_expr))
        } else {
            None
        };

        let end_span = self.current().span;
        Ok(Expr::CreateUnique(CreateUniqueExpr {
            target: None,
            ty,
            fields,
            lock,
            identity,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }

    fn parse_replace_unique_expr(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        // Already consumed the identifier "replace_unique"
        self.expect(TokenKind::Lt)?;
        let ty = Self::render_type(&self.parse_type()?);
        self.expect(TokenKind::Gt)?;
        self.expect(TokenKind::LParen)?;
        let identity = self.parse_identity_policy_from_args()?;
        self.expect(TokenKind::RParen)?;

        let expr = self.parse_expr()?;

        let fields = self.parse_field_init_list()?;

        let end_span = self.current().span;
        Ok(Expr::ReplaceUnique(ReplaceUniqueExpr {
            expr: Box::new(expr),
            ty,
            fields,
            identity,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }

    fn parse_identity_policy_from_args(&mut self) -> Result<IdentityPolicy> {
        let name = self.parse_name()?;
        if name != "identity" {
            return Err(CompileError::new(format!("expected 'identity' named argument, got '{}'", name), self.current().span));
        }
        self.expect(TokenKind::Eq)?;
        let kind = self.parse_name()?;
        match kind.as_str() {
            "ckb_type_id" => Ok(IdentityPolicy::CkbTypeId),
            "field" => {
                self.expect(TokenKind::LParen)?;
                let path = self.parse_name()?;
                self.expect(TokenKind::RParen)?;
                Ok(IdentityPolicy::Field(path))
            }
            "script_args" => Ok(IdentityPolicy::ScriptArgs),
            "singleton_type" => Ok(IdentityPolicy::SingletonType),
            "none" => Ok(IdentityPolicy::None),
            other => Err(CompileError::new(
                format!(
                    "unsupported identity policy '{}'; expected none, ckb_type_id, field(...), script_args, or singleton_type",
                    other
                ),
                self.current().span,
            )),
        }
    }

    fn parse_field_init_list(&mut self) -> Result<Vec<(String, Expr)>> {
        self.expect(TokenKind::LBrace)?;
        self.skip_newlines();
        let mut fields = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
            let name = self.parse_name_path()?;
            if self.check(&TokenKind::Colon) {
                self.advance();
                let value = self.parse_expr()?;
                fields.push((name, value));
            } else {
                // Field shorthand: `amount` means `amount: amount`
                fields.push((name.clone(), Expr::Identifier(name)));
            }
            if self.check(&TokenKind::Comma) {
                self.advance();
            }
            self.skip_newlines();
        }
        self.expect(TokenKind::RBrace)?;
        Ok(fields)
    }

    fn parse_read_ref_expr(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        self.expect(TokenKind::ReadRef)?;

        let ty = if self.check(&TokenKind::Lt) {
            self.advance();
            let ty = self.parse_type()?;
            self.expect(TokenKind::Gt)?;
            Self::render_type(&ty)
        } else {
            Self::render_type(&self.parse_type()?)
        };

        if self.check(&TokenKind::LParen) {
            self.advance();
            self.expect(TokenKind::RParen)?;
        }

        let end_span = self.current().span;
        Ok(Expr::ReadRef(ReadRefExpr { ty, span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column) }))
    }

    fn parse_require(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        self.expect(TokenKind::Require)?;

        // Anonymous require block: require { expr\n expr\n }
        if self.check(&TokenKind::LBrace) {
            self.advance();
            self.skip_newlines();
            let mut expressions = Vec::new();
            while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
                let expr = self.parse_expr()?;
                // Validate: only pure boolean expressions allowed
                match &expr {
                    Expr::Consume(_) | Expr::Create(_) | Expr::Destroy(_) => {
                        return Err(CompileError::new(
                            "require block contains statement — only pure boolean expressions are allowed",
                            expr.span(),
                        )
                        .with_code("E1005"));
                    }
                    Expr::If(_) | Expr::Match(_) => {
                        return Err(CompileError::new(
                            "require block contains control flow — only pure boolean expressions are allowed",
                            expr.span(),
                        )
                        .with_code("E1006"));
                    }
                    _ => {}
                }
                expressions.push(expr);
                self.consume_optional_semi();
                self.skip_newlines();
            }
            if expressions.is_empty() {
                return Err(CompileError::new("require block is empty — at least one boolean expression is required", start_span)
                    .with_code("E1001"));
            }
            let end_span = self.current().span;
            self.expect(TokenKind::RBrace)?;
            return Ok(Expr::RequireBlock(RequireBlockExpr {
                expressions,
                span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
            }));
        }

        // Standard require: require condition[, message]
        let condition = self.parse_expr()?;
        let message = if self.check(&TokenKind::Comma) {
            self.advance();
            self.skip_newlines();
            Some(Box::new(self.parse_expr()?))
        } else if self.check(&TokenKind::Else) {
            self.advance();
            self.skip_newlines();
            let message_span = self.current().span;
            if let Some(name) = self.ident_like_name() {
                self.advance();
                Some(Box::new(Expr::String(name)))
            } else {
                return Err(CompileError::new("require else must name an error identifier", message_span));
            }
        } else {
            None
        };
        let end_span = self.current().span;
        Ok(Expr::Require(RequireExpr {
            condition: Box::new(condition),
            message,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }

    /// Parse `preserve output_name from input_name { field1, field2, ... }`
    fn parse_preserve(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        self.expect(TokenKind::Preserve)?;

        let output_name = self.parse_name()?;

        // Expect "from"
        let from_marker = self.ident_like_name().unwrap_or_default();
        if from_marker != "from" {
            return Err(CompileError::new("expected 'from' in preserve expression", self.current().span));
        }
        self.advance(); // consume "from"

        let input_name = self.parse_name()?;

        // Require a field block — bare `preserve output from input` is not allowed
        if !self.check(&TokenKind::LBrace) {
            return Err(CompileError::new(
                "bare 'preserve' requires a field block — use 'preserve output from input { field1, field2 }'",
                self.current().span,
            )
            .with_code("E1009"));
        }
        self.advance(); // consume {
        self.skip_newlines();

        let mut fields = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
            // Reject wildcard
            if self.check(&TokenKind::Star) {
                return Err(CompileError::new("preserve wildcard '*' is not allowed — use explicit whitelist", self.current().span)
                    .with_code("E1007"));
            }
            // Reject 'except' keyword used as blacklist
            if self.ident_like_name().as_deref() == Some("except") {
                return Err(CompileError::new("preserve except is not allowed — use explicit whitelist", self.current().span)
                    .with_code("E1008"));
            }
            let field_name = self.parse_name()?;
            fields.push(field_name);
            self.consume_optional_semi();
            self.skip_newlines();
        }

        if fields.is_empty() {
            return Err(
                CompileError::new("preserve block is empty — at least one field name is required", start_span).with_code("E1001")
            );
        }

        let end_span = self.current().span;
        self.expect(TokenKind::RBrace)?;

        Ok(Expr::Preserve(PreserveExpr {
            output_name,
            input_name,
            fields,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }

    /// Parse `std::namespace::name(args)` or `std::namespace::name(args) { field1, field2 }`
    fn parse_stdlib_call(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        self.expect(TokenKind::Std)?;

        // Expect ::
        self.expect(TokenKind::ColonColon)?;

        // Parse namespace name
        let namespace = self.parse_name()?;

        // Expect ::
        self.expect(TokenKind::ColonColon)?;

        // Parse function name
        let name = self.parse_name()?;

        // Parse argument list
        let args = self.parse_args()?;

        // Optional preserve-style field block for lifecycle patterns
        let preserve_fields = if self.check(&TokenKind::LBrace) {
            self.advance();
            self.skip_newlines();
            let mut fields = Vec::new();
            while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
                fields.push(self.parse_name()?);
                self.consume_optional_semi();
                self.skip_newlines();
            }
            self.expect(TokenKind::RBrace)?;
            fields
        } else {
            vec![]
        };

        let end_span = self.current().span;
        Ok(Expr::StdlibCall(StdlibCallExpr {
            namespace,
            name,
            args,
            preserve_fields,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }

    fn parse_if_expr(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        self.expect(TokenKind::If)?;
        let condition = self.parse_expr()?;
        let then_branch = Box::new(self.parse_branch_expr()?);
        self.skip_newlines();
        self.expect(TokenKind::Else)?;
        let else_branch = Box::new(self.parse_branch_expr()?);
        Ok(Expr::If(IfExpr { condition: Box::new(condition), then_branch, else_branch, span: start_span }))
    }

    fn parse_branch_expr(&mut self) -> Result<Expr> {
        self.skip_newlines();
        if self.check(&TokenKind::LBrace) {
            Ok(Expr::Block(self.parse_block()?))
        } else if self.check(&TokenKind::If) {
            self.parse_if_expr()
        } else {
            self.parse_expr()
        }
    }

    fn parse_struct_init(&mut self, ty: String) -> Result<Expr> {
        let start_span = self.current().span;
        self.expect(TokenKind::LBrace)?;
        self.skip_newlines();

        let mut fields = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
            let field_name = self.parse_name()?;
            let value = if self.check(&TokenKind::Colon) {
                self.advance();
                self.parse_expr()?
            } else {
                Expr::Identifier(field_name.clone())
            };
            fields.push((field_name, value));

            if self.check(&TokenKind::Comma) {
                self.advance();
            }
            self.skip_newlines();
        }

        self.expect(TokenKind::RBrace)?;
        Ok(Expr::StructInit(StructInitExpr { ty, fields, span: start_span }))
    }

    fn parse_match_expr(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        self.expect(TokenKind::Match)?;
        let expr = self.parse_expr()?;
        self.skip_newlines();
        self.expect(TokenKind::LBrace)?;
        self.skip_newlines();

        let mut arms = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
            let arm_start = self.current().span;
            let pattern = self.parse_match_pattern()?;
            self.skip_newlines();
            self.expect(TokenKind::FatArrow)?;
            self.skip_newlines();
            let value = if self.check(&TokenKind::LBrace) {
                Expr::Block(self.parse_block()?)
            } else if self.check(&TokenKind::Require) {
                self.parse_match_arm_require()?
            } else {
                self.parse_expr()?
            };
            let arm_end = self.current().span;
            let arm_span = Span::new(arm_start.start, arm_end.end, arm_start.line, arm_start.column);
            arms.push(MatchArm { pattern, value, span: arm_span });
            self.skip_newlines();
            if self.check(&TokenKind::Comma) {
                self.advance();
                self.skip_newlines();
            } else if self.check(&TokenKind::RBrace) {
                break;
            }
        }

        self.expect(TokenKind::RBrace)?;
        Ok(Expr::Match(MatchExpr { expr: Box::new(expr), arms, span: start_span }))
    }

    fn parse_match_pattern(&mut self) -> Result<MatchPattern> {
        let mut patterns = vec![self.parse_match_pattern_primary()?];
        while self.check(&TokenKind::Pipe) {
            self.advance();
            self.skip_newlines();
            patterns.push(self.parse_match_pattern_primary()?);
        }
        if patterns.len() == 1 {
            Ok(patterns.pop().expect("one match pattern"))
        } else {
            Ok(MatchPattern::Or(patterns))
        }
    }

    fn parse_match_pattern_primary(&mut self) -> Result<MatchPattern> {
        if self.check(&TokenKind::Underscore) || matches!(&self.current().kind, TokenKind::Identifier(name) if name == "_") {
            self.advance();
            return Ok(MatchPattern::Wildcard);
        }
        if self.check(&TokenKind::LParen) {
            self.advance();
            self.skip_newlines();
            let mut items = Vec::new();
            let mut saw_comma = false;
            while !self.check(&TokenKind::RParen) && !self.check(&TokenKind::Eof) {
                items.push(self.parse_match_pattern()?);
                self.skip_newlines();
                if self.check(&TokenKind::Comma) {
                    saw_comma = true;
                    self.advance();
                    self.skip_newlines();
                } else {
                    break;
                }
            }
            self.expect(TokenKind::RParen)?;
            if items.len() == 1 && !saw_comma {
                return Ok(items.pop().expect("one grouped match pattern"));
            }
            return Ok(MatchPattern::Tuple(items));
        }
        let path = self.parse_name_path()?;
        if self.check(&TokenKind::LBrace) {
            self.advance();
            self.skip_newlines();
            let mut fields = Vec::new();
            while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
                let name = self.parse_name()?;
                let pattern = if self.check(&TokenKind::Colon) {
                    self.advance();
                    self.skip_newlines();
                    self.parse_match_pattern()?
                } else {
                    MatchPattern::Binding(name.clone())
                };
                fields.push((name, pattern));
                self.skip_newlines();
                if self.check(&TokenKind::Comma) {
                    self.advance();
                    self.skip_newlines();
                } else {
                    break;
                }
            }
            self.expect(TokenKind::RBrace)?;
            return Ok(MatchPattern::Struct { path, fields });
        }
        let mut fields = Vec::new();
        if self.check(&TokenKind::LParen) {
            self.advance();
            self.skip_newlines();
            while !self.check(&TokenKind::RParen) && !self.check(&TokenKind::Eof) {
                fields.push(self.parse_match_pattern()?);
                self.skip_newlines();
                if self.check(&TokenKind::Comma) {
                    self.advance();
                    self.skip_newlines();
                } else {
                    break;
                }
            }
            self.expect(TokenKind::RParen)?;
            return Ok(MatchPattern::Variant { path, fields });
        }
        if path.rsplit_once("::").is_some() || path.chars().next().is_some_and(char::is_uppercase) {
            Ok(MatchPattern::Variant { path, fields })
        } else {
            Ok(MatchPattern::Binding(path))
        }
    }

    fn parse_match_arm_require(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        self.expect(TokenKind::Require)?;
        let condition = self.parse_expr()?;
        let message = if self.check(&TokenKind::Comma) && matches!(self.peek(1).kind, TokenKind::String(_)) {
            self.advance();
            self.skip_newlines();
            Some(Box::new(self.parse_expr()?))
        } else if self.check(&TokenKind::Else) {
            self.advance();
            self.skip_newlines();
            let message_span = self.current().span;
            if let Some(name) = self.ident_like_name() {
                self.advance();
                Some(Box::new(Expr::String(name)))
            } else {
                return Err(CompileError::new("require else must name an error identifier", message_span));
            }
        } else {
            None
        };
        let end_span = self.current().span;
        Ok(Expr::Require(RequireExpr {
            condition: Box::new(condition),
            message,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }
}

pub fn parse(tokens: &[Token]) -> Result<Module> {
    parse_with_entry_grammar(tokens, EntryBodyGrammar::VerificationSection)
}

pub(crate) fn parse_with_entry_grammar(tokens: &[Token], grammar: EntryBodyGrammar) -> Result<Module> {
    let mut parser = Parser::new(tokens);
    parser.entry_body_grammar = grammar;
    parser.skip_newlines();
    parser.parse_module()
}

pub fn parse_diagnostics(tokens: &[Token]) -> std::result::Result<Module, Vec<CompileError>> {
    parse_diagnostics_with_entry_grammar(tokens, EntryBodyGrammar::VerificationSection)
}

pub(crate) fn parse_diagnostics_with_entry_grammar(
    tokens: &[Token],
    grammar: EntryBodyGrammar,
) -> std::result::Result<Module, Vec<CompileError>> {
    let mut parser = Parser::new_recovering(tokens);
    parser.entry_body_grammar = grammar;
    parser.skip_newlines();
    let parsed = parser.parse_module();
    match (parsed, parser.diagnostics.is_empty()) {
        (Ok(module), true) => Ok(module),
        (Ok(_), false) => Err(parser.diagnostics),
        (Err(error), true) => Err(vec![error]),
        (Err(error), false) => {
            parser.diagnostics.push(error);
            Err(parser.diagnostics)
        }
    }
}

pub(crate) fn parse_type_fragment(tokens: &[Token]) -> Result<Type> {
    let mut fragment = tokens.to_vec();
    let end = fragment.last().map_or(Span::default(), |token| token.span);
    fragment.push(Token::new(TokenKind::Eof, Span::new(end.end, end.end, end.line, end.column), ""));
    let mut parser = Parser::new(&fragment);
    parser.skip_newlines();
    let ty = parser.parse_type()?;
    parser.skip_newlines();
    parser.expect(TokenKind::Eof)?;
    Ok(ty)
}

pub(crate) fn parse_expression_fragment(tokens: &[Token]) -> Result<Expr> {
    let mut fragment = tokens.to_vec();
    let end = fragment.last().map_or(Span::default(), |token| token.span);
    fragment.push(Token::new(TokenKind::Eof, Span::new(end.end, end.end, end.line, end.column), ""));
    let mut parser = Parser::new(&fragment);
    parser.skip_newlines();
    let expression = parser.parse_expr()?;
    parser.skip_newlines();
    parser.expect(TokenKind::Eof)?;
    Ok(expression)
}

fn merge_capabilities(attr_capabilities: Option<Vec<Capability>>, inline_capabilities: Vec<Capability>) -> Vec<Capability> {
    let mut merged = attr_capabilities.unwrap_or_default();
    for capability in inline_capabilities {
        if !merged.contains(&capability) {
            merged.push(capability);
        }
    }
    merged
}

fn normalize_hash_type_decl(value: &str) -> Option<String> {
    match value {
        "Data" | "data" => Some("data".to_string()),
        "Data1" | "data1" => Some("data1".to_string()),
        "Data2" | "data2" => Some("data2".to_string()),
        "Type" | "type" => Some("type".to_string()),
        _ => None,
    }
}

fn aggregate_scope_from_targets(left: &AggregateTarget, right: Option<&AggregateTarget>) -> Option<String> {
    let left_scope = aggregate_scope_from_target(left)?;
    if let Some(right) = right {
        let right_scope = aggregate_scope_from_target(right)?;
        if left_scope != right_scope {
            return None;
        }
    }
    Some(left_scope.to_string())
}

fn aggregate_scope_from_target(target: &AggregateTarget) -> Option<&'static str> {
    target.source.aggregate_scope()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::lex;

    #[test]
    fn generic_lookahead_does_not_cross_comparisons_or_function_boundaries() {
        let source = r#"
module comparison_boundary
fn before(index: u64, end: u64, start: u64) -> bool {
    while index < 3 { break }
    if end < start || end - start < 4 { return false }
    return true
}
fn after() -> (u64, u64) { return (0, 0) }
"#;
        assert_eq!(parse(&lex(source).unwrap()).unwrap().items.len(), 2);
        for source in [
            "module generic_call\nfn f() -> u64 { return choose<u64>(1) }",
            "module generic_struct\nfn f() -> u64 { let x = Box<[u8; 32]> { value: 0 } return 0 }",
            "module generic_nested\nfn f() -> u64 { return choose<Box<u64>>(1) }",
        ] {
            parse(&lex(source).unwrap()).unwrap();
        }
    }

    #[test]
    fn parses_labeled_loop_control() {
        let source = r#"
module loop_control

fn count() -> u64 {
    label outer: for i in 0..4 {
        while i < 3 {
            continue
        }
        break outer
    }
    return 0
}
"#;
        let module = parse(&lex(source).unwrap()).unwrap();
        let Item::Function(function) = &module.items[0] else {
            panic!("expected function");
        };
        let Stmt::For(outer) = &function.body[0] else {
            panic!("expected for loop");
        };
        assert_eq!(outer.label.as_deref(), Some("outer"));
        assert!(matches!(outer.body[0], Stmt::While(_)));
        assert!(matches!(&outer.body[1], Stmt::Break(control) if control.label.as_deref() == Some("outer")));
    }

    #[test]
    fn test_parse_resource() {
        let input = r#"
module test

resource Token has store, replace, relock, consume, burn {
    amount: u64
    symbol: [u8; 8]
}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        assert_eq!(module.name, "test");
        assert_eq!(module.items.len(), 1);
    }

    #[test]
    fn parse_diagnostics_collects_multiple_statement_errors() {
        let input = r#"
module test

action bad() -> bool {
    verification
        let first: u64 true
        let second: bool 1
        return true
}
"#;
        let tokens = lex(input).unwrap();
        let diagnostics = parse_diagnostics(&tokens).expect_err("recovery should report parse diagnostics");
        assert_eq!(diagnostics.len(), 2);
        assert!(diagnostics.iter().any(|error| error.message.contains("expected '=', found 'true'")));
        assert!(diagnostics.iter().any(|error| error.message.contains("expected '=', found integer 1")));
    }

    #[test]
    fn parse_diagnostics_collects_multiple_top_level_errors() {
        let input = r#"
module test

resource BrokenOne {
    amount:
}

resource BrokenTwo {
    amount:
}
"#;
        let tokens = lex(input).unwrap();
        let diagnostics = parse_diagnostics(&tokens).expect_err("recovery should report parse diagnostics");
        assert_eq!(diagnostics.len(), 2);
        assert!(diagnostics.iter().all(|error| error.message.contains("expected type")));
        assert_eq!(diagnostics[0].span.line, 5);
        assert_eq!(diagnostics[1].span.line, 9);
    }

    #[test]
    fn test_parse_merges_attribute_and_inline_capabilities() {
        let input = r#"
module test

#[capability(store)]
resource Token has replace, relock, destroy {
    amount: u64
}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        let resource = match &module.items[0] {
            Item::Resource(resource) => resource,
            other => panic!("expected resource item, found {:?}", other),
        };

        assert!(resource.capabilities.contains(&Capability::Store));
        assert!(resource.capabilities.contains(&Capability::Replace));
        assert!(resource.capabilities.contains(&Capability::Relock));
        assert!(resource.capabilities.contains(&Capability::Destroy));
    }

    #[test]
    fn test_parse_invariant() {
        let input = r#"
module test

invariant token_conservation {
    trigger: type_group
    scope: group
    reads: group_inputs<Token>.amount, group_outputs<Token>.amount
    assert_invariant(true, "token amount is conserved")
}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        let invariant = match &module.items[0] {
            Item::Invariant(invariant) => invariant,
            other => panic!("expected invariant item, found {:?}", other),
        };

        assert_eq!(invariant.name, "token_conservation");
        assert_eq!(invariant.trigger.as_deref(), Some("type_group"));
        assert_eq!(invariant.scope.as_deref(), Some("group"));
        assert_eq!(
            invariant.reads.iter().map(ToString::to_string).collect::<Vec<_>>(),
            vec!["group_inputs<Token>.amount", "group_outputs<Token>.amount"]
        );
        assert_eq!(invariant.reads[0].source, SourceView::GroupInput);
        assert_eq!(invariant.reads[0].type_and_field(), Some(("Token", "amount")));
        assert_eq!(invariant.asserts.len(), 1);
    }

    #[test]
    fn test_parse_aggregate_invariant_primitives() {
        let input = r#"
module test

invariant token_conservation {
    trigger: type_group
    scope: group
    reads: group_inputs<Token>.amount, group_outputs<Token>.amount
    assert_conserved(Token.amount, scope = group)
    assert_sum(group_outputs<Token>.amount) <= assert_sum(group_inputs<Token>.amount)
}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        let invariant = match &module.items[0] {
            Item::Invariant(invariant) => invariant,
            other => panic!("expected invariant item, found {:?}", other),
        };

        assert_eq!(invariant.aggregates.len(), 2);
        assert_eq!(invariant.aggregates[0].kind, AggregateInvariantKind::Conserved);
        assert_eq!(invariant.aggregates[0].target.to_string(), "Token.amount");
        assert_eq!(invariant.aggregates[0].target.source, SourceView::SelectedCells);
        assert_eq!(invariant.aggregates[0].target.type_and_field(), Some(("Token", "amount")));
        assert_eq!(invariant.aggregates[0].scope, "group");
        assert_eq!(invariant.aggregates[1].kind, AggregateInvariantKind::Sum);
        assert_eq!(invariant.aggregates[1].relation, Some(AggregateRelation::Le));
        assert_eq!(invariant.aggregates[1].target.to_string(), "group_outputs<Token>.amount");
        assert_eq!(invariant.aggregates[1].target.source, SourceView::GroupOutput);
        assert_eq!(invariant.aggregates[1].rhs.as_ref().map(ToString::to_string).as_deref(), Some("group_inputs<Token>.amount"));
    }

    #[test]
    fn test_parse_rejects_unknown_generic_invariant_source_view() {
        let input = r#"
module test

invariant invalid_source {
    trigger: type_group
    scope: group
    reads: mystery<Token>.amount
    assert_conserved(Token.amount, scope = group)
}

resource Token {
    amount: u64
}
"#;
        let tokens = lex(input).unwrap();
        let error = parse(&tokens).unwrap_err();
        assert!(error.message.contains("unknown invariant source view 'mystery'"), "{}", error.message);
    }

    #[test]
    fn test_parse_invariant_assert_statement() {
        let input = r#"
module test

invariant token_conservation {
    trigger: type_group
    scope: group
    reads: group_inputs<Token>.amount, group_outputs<Token>.amount
    assert_invariant(true, "token conserved")
}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        let invariant = match &module.items[0] {
            Item::Invariant(invariant) => invariant,
            other => panic!("expected invariant item, found {:?}", other),
        };

        assert_eq!(invariant.asserts.len(), 1);
        assert!(matches!(invariant.asserts[0], Expr::Assert(_)));
    }

    #[test]
    fn test_parse_type_id_attribute() {
        let input = r#"
module test

#[type_id("cellscript::token::Token:v1")]
resource Token has store {
    amount: u64
}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        let resource = match &module.items[0] {
            Item::Resource(resource) => resource,
            other => panic!("expected resource item, found {:?}", other),
        };

        assert_eq!(resource.type_id.as_ref().map(|type_id| type_id.value.as_str()), Some("cellscript::token::Token:v1"));
    }

    #[test]
    fn test_rejects_type_id_on_action() {
        let input = r#"
module test

#[type_id("cellscript::action:v1")]
action run() -> u64 {
    verification
    return 0
}
"#;
        let tokens = lex(input).unwrap();
        let err = parse(&tokens).unwrap_err();

        assert!(err.message.contains("#[type_id] can only be applied"), "unexpected error: {}", err.message);
    }

    #[test]
    fn test_rejects_generic_resource_definition() {
        let input = r#"
module test

resource Vault<T> has store {
    content: T
}
"#;
        let tokens = lex(input).unwrap();
        let err = parse(&tokens).unwrap_err();

        assert!(
            err.message.contains("Cell-backed type 'Vault' cannot declare generic parameters"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn test_parse_action() {
        let input = r#"
module test

action mint(amount: u64) -> token: Token {
    verification
    create token = Token { amount: amount, symbol: b"TEST" }
}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        assert_eq!(module.items.len(), 1);
    }

    #[test]
    fn parses_function_effect_attribute() {
        let input = r#"
module test

#[effect(ReadOnly)]
fn inspect(value: &u64) -> u64 {
    return *value
}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        let Item::Function(function) = &module.items[0] else {
            panic!("expected function");
        };
        assert!(function.effect_declared);
        assert_eq!(function.effect, EffectClass::ReadOnly);
    }

    #[test]
    fn test_parse_flow_and_action_transition_clause() {
        let input = r#"
module test

flow OfferFlow for Offer.state {
    initial Created;
    terminal Filled;

    Created -> Live by publish;
    Live -> Filled by accept;
}

	action accept(input: Offer) -> output: Offer {
	    transition input.state: Live -> output.state: Filled
        verification
            require output.state == OfferState::Filled
    }
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        assert!(matches!(&module.items[0], Item::Flow(machine) if machine.name.as_deref() == Some("OfferFlow")));
        let Item::Flow(machine) = &module.items[0] else {
            panic!("expected flow");
        };
        assert_eq!(machine.initial_states, vec!["Created"]);
        assert_eq!(machine.terminal_states, vec!["Filled"]);
        let Item::Action(action) = &module.items[1] else {
            panic!("expected action");
        };
        assert_eq!(action.params[0].source, ParamSource::Default);
        assert_eq!(action.outputs.len(), 1);
        assert_eq!(action.outputs[0].name, "output");
        assert_eq!(action.state_edges.len(), 1);
        assert_eq!(action.state_edges[0].path.base, "input");
        assert_eq!(action.state_edges[0].to_path.base, "output");
        assert_eq!(action.state_edges[0].from, "Live");
        assert_eq!(action.state_edges[0].to, "Filled");
    }

    #[test]
    fn test_parse_action_continuation_transitions() {
        let input = r#"
module test

action settle(input: Offer, receipt: Receipt) -> (output: Offer, next_receipt: Receipt) {
    transition input -> output
    transition receipt -> next_receipt
    verification
        require output.state == OfferState::Filled
}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        let Item::Action(action) = &module.items[0] else {
            panic!("expected action");
        };
        assert_eq!(action.state_edges.len(), 2);
        assert_eq!(action.state_edges[0].path.base, "input");
        assert_eq!(action.state_edges[1].path.base, "receipt");
        assert_eq!(action.state_edges[1].to_path.base, "next_receipt");
        assert!(action.state_edges[0].path.field.is_empty());
    }

    #[test]
    fn test_rejects_transition_block() {
        let input = r#"
module test

action accept(input: Offer) -> output: Offer {
    transition {
    }
    verification
        require output.state == OfferState::Filled
}
"#;
        let tokens = lex(input).unwrap();
        let err = parse(&tokens).unwrap_err();
        assert!(err.message.contains("transition block syntax is not part"), "unexpected error: {}", err.message);
    }

    #[test]
    fn test_rejects_legacy_move_as_ordinary_unexpected_token() {
        let input = r#"
module test

action accept(input: Offer) -> output: Offer {
    move input.state: Live -> output.state: Filled
    verification
        require output.state == OfferState::Filled
}
"#;
        let tokens = lex(input).unwrap();
        let err = parse(&tokens).unwrap_err();
        assert!(err.message.contains("expected 'verification'"), "unexpected error: {}", err.message);
    }

    #[test]
    fn test_rejects_transition_clause_without_state_colons() {
        let input = r#"
module test

action accept(input: Offer) -> output: Offer {
    transition input.state Live -> output.state Filled
    verification
        require output.state == OfferState::Filled
}
"#;
        let tokens = lex(input).unwrap();
        let err = parse(&tokens).unwrap_err();
        assert!(err.message.contains("state transition must put ':' before the source state"), "unexpected error: {}", err.message);
    }

    #[test]
    fn test_rejects_action_brace_body_without_verification() {
        let input = r#"
module test

action accept(input: Offer) -> output: Offer {
    require input.state == output.state
}
"#;
        let tokens = lex(input).unwrap();
        let err = parse(&tokens).unwrap_err();
        assert!(err.message.contains("expected 'verification'"), "unexpected error: {}", err.message);
    }

    #[test]
    fn test_rejects_where_action_proof_block_without_compatibility() {
        let input = r#"
module test

action accept(input: Offer) -> output: Offer {
    where
        require input.state == output.state
}
"#;
        let tokens = lex(input).unwrap();
        let err = parse(&tokens).unwrap_err();
        assert!(err.message.contains("not supported"), "unexpected error: {}", err.message);
        assert!(err.message.contains("verification"), "unexpected error: {}", err.message);
    }

    #[test]
    fn test_rejects_read_ref_as_type_qualifier() {
        let input = r#"
module test

action grant(config: read_ref Config) -> grant: Grant {
    verification
    create grant = Grant { admin: config.admin }
}
"#;
        let tokens = lex(input).unwrap();
        let err = parse(&tokens).unwrap_err();
        assert!(err.message.contains("`read_ref` is not a type qualifier"), "unexpected error: {}", err.message);
    }

    #[test]
    fn test_rejects_output_parameter_source_prefix() {
        let input = r#"
module test

action accept(input: Offer, output output: Offer) {
    verification
    require output.state == 1
}
"#;
        let tokens = lex(input).unwrap();
        let err = parse(&tokens).unwrap_err();
        assert!(err.message.contains("only valid on the action return side"), "unexpected error: {}", err.message);
    }

    #[test]
    fn test_parse_prefix_source_and_create_target() {
        let input = r#"
module test

action grant(read config: Config, token: Token) -> grant: Grant {
    verification
    consume token
    create grant = Grant { admin: config.admin }
}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        let Item::Action(action) = &module.items[0] else {
            panic!("expected action");
        };
        assert!(action.params[0].is_read_ref);
        assert_eq!(action.params[0].name, "config");
        assert_eq!(action.outputs[0].name, "grant");
        let Stmt::Expr(Expr::Create(create)) = &action.body[1] else {
            panic!("expected targeted create");
        };
        assert_eq!(create.target.as_deref(), Some("grant"));
    }

    #[test]
    fn test_parse_prefix_source_before_keyword_like_name() {
        let input = r#"
module test

lock receipt_owner(protected receipt: ReceiptCell, witness claimed_owner: Address) -> bool {
    verification
            require receipt.owner == claimed_owner
}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        let Item::Lock(lock) = &module.items[0] else {
            panic!("expected lock");
        };
        assert_eq!(lock.params[0].name, "receipt");
        assert_eq!(lock.params[0].source, ParamSource::Protected);
        assert_eq!(lock.params[1].source, ParamSource::Witness);
    }

    #[test]
    fn test_parse_create_field_shorthand() {
        let input = r#"
module test

action mint(amount: u64, symbol: [u8; 8]) -> Token {
    verification
    create Token { amount, symbol }
}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        assert_eq!(module.items.len(), 1);
    }

    #[test]
    fn test_parse_expression() {
        let input = r#"
module test

action test(x: u64, y: u64) -> u64 {
    verification
    let z = x + y * 2
    return z
}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        assert_eq!(module.items.len(), 1);
    }

    #[test]
    fn test_if_expr_with_all_caps_constant_before_block() {
        let input = r#"
module test

const SOFT_CAP_PER_DEPOSIT: u128 = 10000000000000

action discount(raw: u128) -> u128 {
    verification
    let oversize = if raw > SOFT_CAP_PER_DEPOSIT { raw - SOFT_CAP_PER_DEPOSIT } else { 0 }
    return raw - oversize
}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        assert_eq!(module.items.len(), 2);
    }

    #[test]
    fn test_parse_grouped_use_imports() {
        let input = r#"
module test

use cellscript::fungible_token::{Token, MintAuthority}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();

        let use_stmt = match &module.items[0] {
            Item::Use(use_stmt) => use_stmt,
            other => panic!("expected use item, found {:?}", other),
        };

        assert_eq!(use_stmt.module_path, vec!["cellscript".to_string(), "fungible_token".to_string()]);
        assert_eq!(use_stmt.imports.len(), 2);
        assert_eq!(use_stmt.imports[0].name, "Token");
        assert_eq!(use_stmt.imports[1].name, "MintAuthority");
    }

    #[test]
    fn test_launch_expression_is_reserved_until_lowering_exists() {
        let input = r#"
module test

action bad() -> u64 {
    verification
    return launch(Token)
}
"#;
        let tokens = lex(input).unwrap();
        let err = parse(&tokens).unwrap_err();
        assert!(err.message.contains("launch is reserved for a post-v1 transaction builder"), "unexpected error: {}", err.message);
    }

    #[test]
    fn test_postfix_does_not_cross_statement_newline() {
        let input = r#"
module test

action test() -> (u64, u64) {
    verification
    let value = foo(
        1,
        2
    )

    (value, 3)
}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        let action = match &module.items[0] {
            Item::Action(action) => action,
            other => panic!("expected action, found {:?}", other),
        };

        match &action.body[0] {
            Stmt::Let(let_stmt) => {
                assert!(matches!(let_stmt.value, Expr::Call(_)));
            }
            other => panic!("expected let statement, found {:?}", other),
        }

        match &action.body[1] {
            Stmt::Expr(Expr::Tuple(items)) => {
                assert_eq!(items.len(), 2);
            }
            other => panic!("expected tuple return expr, found {:?}", other),
        }
    }

    #[test]
    fn test_parses_expression_match_arms() {
        let input = r#"
module test

enum Flag {
    On,
    Off,
}

action test(flag: Flag) -> u64 {
    verification
    match flag {
        On => 1,
        Off => 0,
    }
}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        let Item::Action(action) = &module.items[1] else { panic!("expected action") };
        let Stmt::Expr(Expr::Match(match_expr)) = &action.body[0] else { panic!("expected match expression") };
        assert_eq!(match_expr.arms.len(), 2);
        assert!(matches!(match_expr.arms[0].pattern, MatchPattern::Variant { ref path, .. } if path == "On"));
    }

    // === 0.13.1 preserve sugar and anonymous require block tests ===

    #[test]
    fn test_parse_preserve_block() {
        let input = r#"
module test

resource Offer has store {
    seller: [u8; 20]
    price: u64
    payment_symbol: [u8; 8]
}

action fill(input: Offer) -> (output: Offer) {
    transition input -> output
    verification
    preserve output from input {
        seller
        price
        payment_symbol
    }
}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        let action = match &module.items[1] {
            Item::Action(action) => action,
            other => panic!("expected action, found {:?}", other),
        };
        // Find the preserve statement in the action body
        let found_preserve = action.body.iter().any(|stmt| matches!(stmt, Stmt::Expr(Expr::Preserve(_))));
        assert!(found_preserve, "expected preserve expression in action body");
    }

    #[test]
    fn test_parse_require_block() {
        let input = r#"
module test

action test(x: u64, y: u64) -> u64 {
    verification
    require {
        x > 0
        y > 0
    }
    return x + y
}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        let action = match &module.items[0] {
            Item::Action(action) => action,
            other => panic!("expected action, found {:?}", other),
        };
        let found_require_block = action.body.iter().any(|stmt| matches!(stmt, Stmt::Expr(Expr::RequireBlock(_))));
        assert!(found_require_block, "expected require block expression in action body");
    }

    #[test]
    fn test_parse_preserve_single_field() {
        let input = r#"
module test

resource Token has store {
    amount: u64
}

action test(input: Token) -> (output: Token) {
    verification
    preserve output from input {
        amount
    }
}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        let action = match &module.items[1] {
            Item::Action(action) => action,
            other => panic!("expected action, found {:?}", other),
        };
        let preserve = action
            .body
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Expr(Expr::Preserve(p)) => Some(p.clone()),
                _ => None,
            })
            .expect("expected preserve expression");
        assert_eq!(preserve.output_name, "output");
        assert_eq!(preserve.input_name, "input");
        assert_eq!(preserve.fields, vec!["amount".to_string()]);
    }

    #[test]
    fn test_reject_empty_preserve_block() {
        let input = r#"
module test

action test(input: u64) -> (output: u64) {
    verification
    preserve output from input {
    }
}
"#;
        let tokens = lex(input).unwrap();
        let err = parse(&tokens).unwrap_err();
        assert!(err.message.contains("preserve block is empty"), "unexpected error: {}", err.message);
        assert_eq!(err.code.as_deref(), Some("E1001"));
    }

    #[test]
    fn test_reject_empty_require_block() {
        let input = r#"
module test

action test() -> u64 {
    verification
    require {
    }
}
"#;
        let tokens = lex(input).unwrap();
        let err = parse(&tokens).unwrap_err();
        assert!(err.message.contains("require block is empty"), "unexpected error: {}", err.message);
        assert_eq!(err.code.as_deref(), Some("E1001"));
    }

    #[test]
    fn test_reject_preserve_wildcard() {
        let input = r#"
module test

action test(input: u64) -> (output: u64) {
    verification
    preserve output from input {
        *
    }
}
"#;
        let tokens = lex(input).unwrap();
        let err = parse(&tokens).unwrap_err();
        assert!(err.message.contains("wildcard"), "unexpected error: {}", err.message);
        assert_eq!(err.code.as_deref(), Some("E1007"));
    }

    #[test]
    fn test_reject_preserve_except() {
        let input = r#"
module test

action test(input: u64) -> (output: u64) {
    verification
    preserve output from input {
        except
    }
}
"#;
        let tokens = lex(input).unwrap();
        let err = parse(&tokens).unwrap_err();
        assert!(err.message.contains("except"), "unexpected error: {}", err.message);
        assert_eq!(err.code.as_deref(), Some("E1008"));
    }

    #[test]
    fn test_reject_bare_preserve() {
        let input = r#"
module test

action test(input: u64) -> (output: u64) {
    verification
    preserve output from input
    return 0
}
"#;
        let tokens = lex(input).unwrap();
        let err = parse(&tokens).unwrap_err();
        assert!(err.message.contains("bare"), "unexpected error: {}", err.message);
        assert_eq!(err.code.as_deref(), Some("E1009"));
    }

    #[test]
    fn test_reject_require_block_with_consume() {
        let input = r#"
module test

resource Token has store {
    amount: u64
}

action test(input: Token) -> u64 {
    verification
    require {
        consume input
    }
}
"#;
        let tokens = lex(input).unwrap();
        let err = parse(&tokens).unwrap_err();
        assert!(err.message.contains("statement"), "unexpected error: {}", err.message);
        assert_eq!(err.code.as_deref(), Some("E1005"));
    }

    #[test]
    fn test_reject_require_block_with_control_flow() {
        let input = r#"
module test

action test(x: u64) -> u64 {
    verification
    require {
        if x > 0 {
            true
        } else {
            false
        }
    }
}
"#;
        let tokens = lex(input).unwrap();
        let err = parse(&tokens).unwrap_err();
        assert!(err.message.contains("control flow"), "unexpected error: {}", err.message);
        assert_eq!(err.code.as_deref(), Some("E1006"));
    }

    #[test]
    fn bounded_quantifier_rejects_unbounded_forall_syntax() {
        let input = r#"
module test

resource Token {
    amount: u64
}

invariant bad {
    trigger: type_group
    scope: group
    reads: group_outputs<Token>.amount
    forall token: Token {
        require token.amount > 0
    }
}
"#;
        let tokens = lex(input).unwrap();
        let err = parse(&tokens).unwrap_err();
        assert!(err.message.contains("unbounded forall"), "unexpected error: {}", err.message);
    }

    #[test]
    fn rejects_deeply_nested_expressions_without_stack_overflow() {
        let expression = format!("{}1{}", "(".repeat(MAX_PARSE_RECURSION_DEPTH + 1), ")".repeat(MAX_PARSE_RECURSION_DEPTH + 1));
        let input = format!("module test\naction deep() -> u64 {{\nverification\nreturn {expression}\n}}");
        let tokens = lex(&input).unwrap();
        let error = parse(&tokens).expect_err("deep expression must hit the parser recursion budget");
        assert!(error.message.contains("expression nesting exceeds"), "unexpected error: {}", error.message);
    }

    #[test]
    fn rejects_deeply_nested_unary_expressions_without_stack_overflow() {
        let expression = format!("{}1", "-".repeat(MAX_PARSE_RECURSION_DEPTH + 1));
        let input = format!("module test\naction deep() -> i32 {{\nverification\nreturn {expression}\n}}");
        let tokens = lex(&input).unwrap();
        let error = parse(&tokens).expect_err("deep unary expression must hit the parser recursion budget");
        assert!(error.message.contains("unary expression nesting exceeds"), "unexpected error: {}", error.message);
    }

    #[test]
    fn rejects_deeply_nested_types_without_stack_overflow() {
        let ty = format!("{}u8{}", "[".repeat(MAX_PARSE_RECURSION_DEPTH + 1), "; 1]".repeat(MAX_PARSE_RECURSION_DEPTH + 1));
        let input = format!("module test\nstruct Deep {{\nvalue: {ty}\n}}");
        let tokens = lex(&input).unwrap();
        let error = parse(&tokens).expect_err("deep type must hit the parser recursion budget");
        assert!(error.message.contains("type nesting exceeds"), "unexpected error: {}", error.message);
    }

    #[test]
    fn rejects_deeply_nested_statements_without_stack_overflow() {
        let nested = format!(
            "{}return 1\n{}",
            "if true {\n".repeat(MAX_PARSE_RECURSION_DEPTH + 1),
            "}\n".repeat(MAX_PARSE_RECURSION_DEPTH + 1)
        );
        let input = format!("module test\naction deep() -> u64 {{\nverification\n{nested}}}");
        let tokens = lex(&input).unwrap();
        let error = parse(&tokens).expect_err("deep statements must hit the parser recursion budget");
        assert!(error.message.contains("statement nesting exceeds"), "unexpected error: {}", error.message);
    }

    #[test]
    fn rejects_deep_else_if_chains_without_stack_overflow() {
        let chain = format!("{}{{ return 1 }}", "if true { return 1 } else ".repeat(MAX_PARSE_RECURSION_DEPTH + 1));
        let input = format!("module test\naction deep() -> u64 {{\nverification\n{chain}\n}}");
        let tokens = lex(&input).unwrap();
        let error = parse(&tokens).expect_err("deep else-if chain must hit the parser recursion budget");
        assert!(error.message.contains("if nesting exceeds"), "unexpected error: {}", error.message);
    }
}
