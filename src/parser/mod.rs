use crate::ast::*;
use crate::error::{CompileError, Result, Span};
use crate::lexer::token::{Token, TokenKind};

pub struct Parser<'a> {
    tokens: &'a [Token],
    position: usize,
}

#[derive(Debug, Default, Clone)]
struct PendingAttrs {
    type_id: Option<TypeIdentity>,
    capabilities: Option<Vec<Capability>>,
    lifecycle: Option<Lifecycle>,
    effect: Option<EffectClass>,
    scheduler_hint: Option<SchedulerHint>,
}

impl<'a> Parser<'a> {
    pub fn new(tokens: &'a [Token]) -> Self {
        Self { tokens, position: 0 }
    }

    fn current(&self) -> &Token {
        &self.tokens[self.position.min(self.tokens.len() - 1)]
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
            TokenKind::Action => Some("action".to_string()),
            TokenKind::Lock => Some("lock".to_string()),
            TokenKind::Has => Some("has".to_string()),
            TokenKind::Store => Some("store".to_string()),
            TokenKind::Transfer | TokenKind::TransferKw => Some("transfer".to_string()),
            TokenKind::Destroy | TokenKind::DestroyKw => Some("destroy".to_string()),
            TokenKind::Claim => Some("claim".to_string()),
            TokenKind::Settle => Some("settle".to_string()),
            TokenKind::Launch => Some("launch".to_string()),
            TokenKind::Assert => Some("assert".to_string()),
            TokenKind::Address => Some("Address".to_string()),
            TokenKind::Hash => Some("Hash".to_string()),
            TokenKind::Env => Some("env".to_string()),
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
        name.split("::").last().and_then(|segment| segment.chars().next()).is_some_and(|ch| ch.is_ascii_uppercase())
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
                        match &self.current().kind {
                            TokenKind::Store => {
                                caps.push(Capability::Store);
                                self.advance();
                            }
                            TokenKind::Transfer | TokenKind::TransferKw => {
                                caps.push(Capability::Transfer);
                                self.advance();
                            }
                            TokenKind::Destroy | TokenKind::DestroyKw => {
                                caps.push(Capability::Destroy);
                                self.advance();
                            }
                            _ => {
                                return Err(CompileError::new("expected capability name", self.current().span));
                            }
                        }

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
                "lifecycle" => {
                    let start_span = self.current().span;
                    let mut states = Vec::new();
                    while !self.check(&TokenKind::RParen) && !self.check(&TokenKind::Eof) {
                        states.push(self.parse_name_path()?);
                        if self.check(&TokenKind::Arrow) || self.check(&TokenKind::Comma) {
                            self.advance();
                        } else {
                            break;
                        }
                    }
                    attrs.lifecycle = Some(Lifecycle {
                        states,
                        span: Span::new(start_span.start, self.current().span.end, start_span.line, start_span.column),
                    });
                }
                "effect" => {
                    let mut has_mutating = false;
                    let mut has_creating = false;
                    let mut has_destroying = false;
                    let mut has_read_only = false;
                    while !self.check(&TokenKind::RParen) && !self.check(&TokenKind::Eof) {
                        let effect_name = self.parse_name()?;
                        match effect_name.as_str() {
                            "Pure" => {}
                            "ReadOnly" => has_read_only = true,
                            "Mutating" => has_mutating = true,
                            "Creating" => has_creating = true,
                            "Destroying" => has_destroying = true,
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
                                        let value = *n;
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
                    while !self.check(&TokenKind::RParen) && !self.check(&TokenKind::Eof) {
                        self.advance();
                    }
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
        while !self.check(&TokenKind::Eof) {
            self.skip_newlines();
            if self.check(&TokenKind::Eof) {
                break;
            }
            items.push(self.parse_item()?);
            self.skip_newlines();
        }

        let end_span = self.current().span;
        Ok(Module { name: full_name, items, span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column) })
    }

    fn parse_item(&mut self) -> Result<Item> {
        let attrs = self.parse_attrs()?;
        match &self.current().kind {
            TokenKind::Use => {
                self.reject_type_id_attr(&attrs)?;
                Ok(Item::Use(self.parse_use()?))
            }
            TokenKind::Resource => Ok(Item::Resource(self.parse_resource(attrs.type_id, attrs.capabilities)?)),
            TokenKind::Shared => Ok(Item::Shared(self.parse_shared(attrs.type_id, attrs.capabilities)?)),
            TokenKind::Receipt => Ok(Item::Receipt(self.parse_receipt(attrs.type_id, attrs.lifecycle, attrs.capabilities)?)),
            TokenKind::Struct => Ok(Item::Struct(self.parse_struct(attrs.type_id)?)),
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
                Ok(Item::Function(self.parse_fn()?))
            }
            TokenKind::Lock => {
                self.reject_type_id_attr(&attrs)?;
                Ok(Item::Lock(self.parse_lock()?))
            }
            _ => Err(CompileError::new(format!("unexpected token: {}", self.current().kind), self.current().span)),
        }
    }

    fn reject_type_id_attr(&self, attrs: &PendingAttrs) -> Result<()> {
        if let Some(type_id) = &attrs.type_id {
            Err(CompileError::new("#[type_id] can only be applied to resource, shared, receipt, or struct definitions", type_id.span))
        } else {
            Ok(())
        }
    }

    fn reject_generic_type_params(&self, type_name: &str) -> Result<()> {
        if self.check(&TokenKind::Lt) {
            Err(CompileError::new(
                format!(
                    "generic type parameters on '{}' are post-v1 template/codegen syntax, not CellScript v1 executable core; define a concrete type or generate a specialized .cell module",
                    type_name
                ),
                self.current().span,
            ))
        } else {
            Ok(())
        }
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

        let fields = self.parse_fields()?;

        let end_span = self.current().span;
        Ok(ResourceDef {
            name,
            type_id,
            capabilities,
            fields,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_shared(&mut self, type_id: Option<TypeIdentity>, attr_capabilities: Option<Vec<Capability>>) -> Result<SharedDef> {
        let start_span = self.current().span;
        self.expect(TokenKind::Shared)?;

        let name = self.parse_name()?;
        self.reject_generic_type_params(&name)?;

        let capabilities = merge_capabilities(attr_capabilities, self.parse_capabilities()?);
        let fields = self.parse_fields()?;

        let end_span = self.current().span;
        Ok(SharedDef {
            name,
            type_id,
            capabilities,
            fields,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_receipt(
        &mut self,
        type_id: Option<TypeIdentity>,
        attr_lifecycle: Option<Lifecycle>,
        attr_capabilities: Option<Vec<Capability>>,
    ) -> Result<ReceiptDef> {
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

        let lifecycle = if let Some(lifecycle) = attr_lifecycle {
            Some(lifecycle)
        } else if self.check(&TokenKind::LBracket) {
            Some(self.parse_lifecycle_attr()?)
        } else {
            None
        };

        let capabilities = merge_capabilities(attr_capabilities, self.parse_capabilities()?);
        let fields = self.parse_fields()?;

        let end_span = self.current().span;
        Ok(ReceiptDef {
            name,
            type_id,
            claim_output,
            lifecycle,
            capabilities,
            fields,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_lifecycle_attr(&mut self) -> Result<Lifecycle> {
        let start_span = self.current().span;
        self.expect(TokenKind::LBracket)?;
        self.expect(TokenKind::Identifier("lifecycle".to_string()))?;
        self.expect(TokenKind::LParen)?;

        let mut states = Vec::new();
        while let TokenKind::Identifier(n) = &self.current().kind {
            states.push(n.clone());
            self.advance();
            if self.check(&TokenKind::Arrow) {
                self.advance();
            } else {
                break;
            }
        }

        self.expect(TokenKind::RParen)?;
        self.expect(TokenKind::RBracket)?;

        let end_span = self.current().span;
        Ok(Lifecycle { states, span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column) })
    }

    fn parse_struct(&mut self, type_id: Option<TypeIdentity>) -> Result<StructDef> {
        let start_span = self.current().span;
        self.expect(TokenKind::Struct)?;

        let name = self.parse_name()?;
        self.reject_generic_type_params(&name)?;

        let fields = self.parse_fields()?;

        let end_span = self.current().span;
        Ok(StructDef { name, type_id, fields, span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column) })
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
        Ok(EnumDef { name, variants, span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column) })
    }

    fn parse_capabilities(&mut self) -> Result<Vec<Capability>> {
        let mut caps = Vec::new();

        if self.check(&TokenKind::Has) {
            self.advance();

            loop {
                match &self.current().kind {
                    TokenKind::Store => {
                        caps.push(Capability::Store);
                        self.advance();
                    }
                    TokenKind::Transfer | TokenKind::TransferKw => {
                        caps.push(Capability::Transfer);
                        self.advance();
                    }
                    TokenKind::Destroy | TokenKind::DestroyKw => {
                        caps.push(Capability::Destroy);
                        self.advance();
                    }
                    _ => break,
                }

                if self.check(&TokenKind::Comma) {
                    self.advance();
                } else {
                    break;
                }
            }
        }

        Ok(caps)
    }

    fn parse_fields(&mut self) -> Result<Vec<Field>> {
        self.expect(TokenKind::LBrace)?;
        self.skip_newlines();

        let mut fields = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
            let field = self.parse_field()?;
            fields.push(field);
            if self.check(&TokenKind::Comma) {
                self.advance();
            }
            self.skip_newlines();
        }

        self.expect(TokenKind::RBrace)?;
        Ok(fields)
    }

    fn parse_field(&mut self) -> Result<Field> {
        let start_span = self.current().span;

        let name = self.parse_name()?;

        self.expect(TokenKind::Colon)?;
        let ty = self.parse_type()?;

        let end_span = self.current().span;
        Ok(Field { name, ty, span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column) })
    }

    fn parse_type(&mut self) -> Result<Type> {
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
                        args.push(self.parse_type()?);
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
                        let size = *n as usize;
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
                self.advance();
                Type::Ref(Box::new(self.parse_type()?))
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
            Type::U64 => "u64".to_string(),
            Type::U128 => "u128".to_string(),
            Type::Bool => "bool".to_string(),
            Type::Unit => "()".to_string(),
            Type::Address => "Address".to_string(),
            Type::Hash => "Hash".to_string(),
            Type::Array(elem, size) => format!("[{}; {}]", Self::render_type(elem), size),
            Type::Tuple(types) => format!("({})", types.iter().map(Self::render_type).collect::<Vec<_>>().join(", ")),
            Type::Named(name) => name.clone(),
            Type::Ref(inner) => format!("read_ref {}", Self::render_type(inner)),
            Type::MutRef(inner) => format!("&mut {}", Self::render_type(inner)),
        }
    }

    fn parse_action(&mut self, effect: Option<EffectClass>, scheduler_hint: Option<SchedulerHint>) -> Result<ActionDef> {
        let start_span = self.current().span;
        self.expect(TokenKind::Action)?;

        let name = self.parse_name()?;

        let params = self.parse_params()?;

        let return_type = if self.check(&TokenKind::Arrow) {
            self.advance();
            Some(self.parse_type()?)
        } else {
            None
        };

        let body = self.parse_block()?;

        let end_span = self.current().span;
        let effect_declared = effect.is_some();

        Ok(ActionDef {
            name,
            params,
            return_type,
            body,
            effect: effect.unwrap_or(EffectClass::Pure),
            effect_declared,
            scheduler_hint,
            doc_comment: None,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_fn(&mut self) -> Result<FnDef> {
        let start_span = self.current().span;
        self.expect(TokenKind::Fn)?;

        let name = self.parse_name()?;
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
            params,
            return_type,
            body,
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
        let body = self.parse_block()?;

        let end_span = self.current().span;
        Ok(LockDef {
            name,
            params,
            return_type,
            body,
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
                "parameter modifier 'ref' is reserved but unsupported; use '&T' or '&mut T' in the parameter type",
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

        let name = self.parse_name()?;

        self.expect(TokenKind::Colon)?;
        let is_read_ref = self.check(&TokenKind::ReadRef);
        let ty = self.parse_type()?;

        let end_span = self.current().span;
        Ok(Param {
            name,
            ty,
            is_mut,
            is_ref,
            is_read_ref,
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        })
    }

    fn parse_block(&mut self) -> Result<Vec<Stmt>> {
        self.expect(TokenKind::LBrace)?;
        self.skip_newlines();

        let mut stmts = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
            stmts.push(self.parse_stmt()?);
            self.skip_newlines();
        }

        self.expect(TokenKind::RBrace)?;
        Ok(stmts)
    }

    fn parse_stmt(&mut self) -> Result<Stmt> {
        let stmt = match &self.current().kind {
            TokenKind::Let => Stmt::Let(self.parse_let()?),
            TokenKind::Return => Stmt::Return(self.parse_return()?),
            TokenKind::If => Stmt::If(self.parse_if()?),
            TokenKind::For => Stmt::For(self.parse_for()?),
            TokenKind::While => Stmt::While(self.parse_while()?),
            _ => {
                let expr = self.parse_expr()?;
                Stmt::Expr(expr)
            }
        };
        self.consume_optional_semi();
        Ok(stmt)
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

    fn parse_return(&mut self) -> Result<Option<Expr>> {
        self.expect(TokenKind::Return)?;

        if self.check(&TokenKind::Newline) || self.check(&TokenKind::RBrace) || self.check(&TokenKind::Eof) {
            Ok(None)
        } else {
            Ok(Some(self.parse_expr()?))
        }
    }

    fn parse_if(&mut self) -> Result<IfStmt> {
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
        Ok(ForStmt { pattern, iterable, body, span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column) })
    }

    fn parse_while(&mut self) -> Result<WhileStmt> {
        let start_span = self.current().span;
        self.expect(TokenKind::While)?;

        let condition = self.parse_expr()?;
        let body = self.parse_block()?;

        let end_span = self.current().span;
        Ok(WhileStmt { condition, body, span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column) })
    }

    fn parse_expr(&mut self) -> Result<Expr> {
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
        let mut left = self.parse_equality()?;

        loop {
            self.skip_newlines();
            if !self.check(&TokenKind::And) {
                break;
            }
            let op = BinaryOp::And;
            let start_span = self.current().span;
            self.advance();
            self.skip_newlines();
            let right = self.parse_equality()?;
            left = Expr::Binary(BinaryExpr { op, left: Box::new(left), right: Box::new(right), span: start_span });
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
        let mut left = self.parse_term()?;

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
                let right = self.parse_term()?;
                left = Expr::Binary(BinaryExpr { op, left: Box::new(left), right: Box::new(right), span: start_span });
            } else {
                break;
            }
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
            } else if self.check(&TokenKind::LParen) {
                let args = self.parse_args()?;
                expr = Expr::Call(CallExpr { func: Box::new(expr), args, span: self.current().span });
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
            TokenKind::TransferKw => self.parse_transfer(),
            TokenKind::DestroyKw => self.parse_destroy(),
            TokenKind::Claim => self.parse_claim(),
            TokenKind::Settle => self.parse_settle(),
            TokenKind::Launch => Err(CompileError::new(
                "launch is reserved for a post-v1 transaction builder and is not part of the executable language core; use explicit create/transfer/claim/settle operations",
                self.current().span,
            )),
            TokenKind::ReadRef => self.parse_read_ref_expr(),
            TokenKind::If => self.parse_if_expr(),
            TokenKind::Match => self.parse_match_expr(),
            TokenKind::Assert => self.parse_assert(),
            _ if self.ident_like_name().is_some() => {
                let name = self.parse_name_path()?;
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
        let ty = self.parse_name_path()?;

        self.expect(TokenKind::LBrace)?;
        self.skip_newlines();

        let mut fields = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.check(&TokenKind::Eof) {
            let field_name = self.parse_name()?;

            self.expect(TokenKind::Colon)?;
            let value = self.parse_expr()?;
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

    fn parse_destroy(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        self.expect(TokenKind::DestroyKw)?;

        let expr = self.parse_expr()?;

        let end_span = self.current().span;
        Ok(Expr::Destroy(DestroyExpr {
            expr: Box::new(expr),
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
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

    fn parse_transfer(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        self.expect(TokenKind::TransferKw)?;

        let expr = self.parse_expr()?;
        let marker = self.parse_name_path()?;
        if marker != "to" {
            return Err(CompileError::new("expected 'to' in transfer expression", self.current().span));
        }
        let to = self.parse_expr()?;

        let end_span = self.current().span;
        Ok(Expr::Transfer(TransferExpr {
            expr: Box::new(expr),
            to: Box::new(to),
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }

    fn parse_claim(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        self.expect(TokenKind::Claim)?;

        let receipt = self.parse_expr()?;

        let end_span = self.current().span;
        Ok(Expr::Claim(ClaimExpr {
            receipt: Box::new(receipt),
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }

    fn parse_settle(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        self.expect(TokenKind::Settle)?;

        let expr = self.parse_expr()?;

        let end_span = self.current().span;
        Ok(Expr::Settle(SettleExpr {
            expr: Box::new(expr),
            span: Span::new(start_span.start, end_span.end, start_span.line, start_span.column),
        }))
    }

    fn parse_assert(&mut self) -> Result<Expr> {
        let start_span = self.current().span;
        self.expect(TokenKind::Assert)?;
        if self.check(&TokenKind::Not) {
            self.advance();
        }
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
            self.expect(TokenKind::Colon)?;
            let value = self.parse_expr()?;
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
            let pattern =
                if self.check(&TokenKind::Underscore) || matches!(&self.current().kind, TokenKind::Identifier(name) if name == "_") {
                    self.advance();
                    "_".to_string()
                } else {
                    self.parse_name_path()?
                };
            self.skip_newlines();
            self.expect(TokenKind::FatArrow)?;
            self.skip_newlines();
            let value = self.parse_branch_expr()?;
            let arm_span = self.current().span;
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
}

pub fn parse(tokens: &[Token]) -> Result<Module> {
    let mut parser = Parser::new(tokens);
    parser.skip_newlines();
    parser.parse_module()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::lex;

    #[test]
    fn test_parse_resource() {
        let input = r#"
module test

resource Token has store, transfer, destroy {
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
    fn test_parse_merges_attribute_and_inline_capabilities() {
        let input = r#"
module test

#[capability(store)]
resource Token has transfer, destroy {
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
        assert!(resource.capabilities.contains(&Capability::Transfer));
        assert!(resource.capabilities.contains(&Capability::Destroy));
    }

    #[test]
    fn test_parse_type_id_attribute() {
        let input = r#"
module test

#[type_id("spora::token::Token:v1")]
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

        assert_eq!(resource.type_id.as_ref().map(|type_id| type_id.value.as_str()), Some("spora::token::Token:v1"));
    }

    #[test]
    fn test_rejects_type_id_on_action() {
        let input = r#"
module test

#[type_id("spora::action:v1")]
action run() -> u64 {
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

        assert!(err.message.contains("post-v1 template/codegen syntax"), "unexpected error: {}", err.message);
    }

    #[test]
    fn test_parse_action() {
        let input = r#"
module test

action mint(amount: u64) -> Token {
    create Token { amount: amount, symbol: b"TEST" }
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
    let z = x + y * 2
    return z
}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();
        assert_eq!(module.items.len(), 1);
    }

    #[test]
    fn test_parse_grouped_use_imports() {
        let input = r#"
module test

use spora::fungible_token::{Token, MintAuthority}
"#;
        let tokens = lex(input).unwrap();
        let module = parse(&tokens).unwrap();

        let use_stmt = match &module.items[0] {
            Item::Use(use_stmt) => use_stmt,
            other => panic!("expected use item, found {:?}", other),
        };

        assert_eq!(use_stmt.module_path, vec!["spora".to_string(), "fungible_token".to_string()]);
        assert_eq!(use_stmt.imports.len(), 2);
        assert_eq!(use_stmt.imports[0].name, "Token");
        assert_eq!(use_stmt.imports[1].name, "MintAuthority");
    }

    #[test]
    fn test_launch_expression_is_reserved_until_lowering_exists() {
        let input = r#"
module test

action bad() -> u64 {
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
}
