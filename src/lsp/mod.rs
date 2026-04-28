use crate::ast::*;
use crate::error::{CompileError, Span};
use crate::lexer::token::{keyword_or_identifier, TokenKind};
use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod server;

pub struct LspServer {
    documents: HashMap<String, String>,
    ast_cache: HashMap<String, Module>,
    diagnostics: HashMap<String, Vec<Diagnostic>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub range: Range,
    pub severity: DiagnosticSeverity,
    pub message: String,
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DiagnosticSeverity {
    Error = 1,
    Warning = 2,
    Information = 3,
    Hint = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range {
    pub start: Position,
    pub end: Position,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Position {
    pub line: u32,
    pub character: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionItem {
    pub label: String,
    pub kind: CompletionItemKind,
    pub detail: Option<String>,
    pub documentation: Option<String>,
    pub insert_text: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CompletionItemKind {
    Text = 1,
    Method = 2,
    Function = 3,
    Constructor = 4,
    Field = 5,
    Variable = 6,
    Class = 7,
    Interface = 8,
    Module = 9,
    Property = 10,
    Unit = 11,
    Value = 12,
    Enum = 13,
    Keyword = 14,
    Snippet = 15,
    Color = 16,
    File = 17,
    Reference = 18,
    Folder = 19,
    EnumMember = 20,
    Constant = 21,
    Struct = 22,
    Event = 23,
    Operator = 24,
    TypeParameter = 25,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInformation {
    pub name: String,
    pub kind: SymbolKind,
    pub location: Location,
    pub container_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SymbolKind {
    File = 1,
    Module = 2,
    Namespace = 3,
    Package = 4,
    Class = 5,
    Method = 6,
    Property = 7,
    Field = 8,
    Constructor = 9,
    Enum = 10,
    Interface = 11,
    Function = 12,
    Variable = 13,
    Constant = 14,
    String = 15,
    Number = 16,
    Boolean = 17,
    Array = 18,
    Object = 19,
    Key = 20,
    Null = 21,
    EnumMember = 22,
    Struct = 23,
    Event = 24,
    Operator = 25,
    TypeParameter = 26,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub uri: String,
    pub range: Range,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hover {
    pub contents: String,
    pub range: Option<Range>,
}

impl Default for LspServer {
    fn default() -> Self {
        Self::new()
    }
}

impl LspServer {
    pub fn new() -> Self {
        Self { documents: HashMap::new(), ast_cache: HashMap::new(), diagnostics: HashMap::new() }
    }

    pub fn open_document(&mut self, uri: String, content: String) {
        self.documents.insert(uri.clone(), content.clone());
        self.parse_document(&uri, &content);
    }

    pub fn update_document(&mut self, uri: String, content: String) {
        self.documents.insert(uri.clone(), content.clone());
        self.parse_document(&uri, &content);
    }

    /// Apply incremental text changes to a document and re-parse.
    ///
    /// If any change has `range == None`, the entire document is replaced with that change's text.
    /// Otherwise, each change's text is spliced into the current document at the given range.
    pub fn update_document_incremental(&mut self, uri: &str, changes: Vec<TextDocumentContentChangeEvent>) {
        let Some(mut content) = self.documents.get(uri).cloned() else {
            return;
        };

        for change in changes {
            match change.range {
                None => {
                    // Full document replacement.
                    content = change.text;
                }
                Some(range) => {
                    content = apply_incremental_change(&content, range, &change.text);
                }
            }
        }

        self.documents.insert(uri.to_string(), content.clone());
        self.parse_document(uri, &content);
    }

    pub fn close_document(&mut self, uri: &str) {
        self.documents.remove(uri);
        self.ast_cache.remove(uri);
        self.diagnostics.remove(uri);
    }

    fn parse_document(&mut self, uri: &str, content: &str) {
        self.ast_cache.remove(uri);

        let tokens = match crate::lexer::lex(content) {
            Ok(tokens) => tokens,
            Err(error) => {
                self.diagnostics.insert(uri.to_string(), vec![diagnostic_from_error(content, &error)]);
                return;
            }
        };

        let ast = match crate::parser::parse(&tokens) {
            Ok(ast) => ast,
            Err(error) => {
                self.diagnostics.insert(uri.to_string(), vec![diagnostic_from_error(content, &error)]);
                return;
            }
        };

        self.ast_cache.insert(uri.to_string(), ast.clone());
        let diagnostics = match crate::types::check(&ast).and_then(|_| crate::lifecycle::check(&ast)) {
            Ok(()) => {
                let mut diagnostics = Vec::new();
                if let Ok(metadata) = crate::compile_metadata(content, None) {
                    diagnostics.extend(lowering_diagnostics(content, &ast, &metadata));
                }
                diagnostics
            }
            Err(error) => vec![diagnostic_from_error(content, &error)],
        };
        self.diagnostics.insert(uri.to_string(), diagnostics);
    }

    pub fn get_diagnostics(&self, uri: &str) -> Vec<Diagnostic> {
        self.diagnostics.get(uri).cloned().unwrap_or_default()
    }

    pub fn completion(&self, uri: &str, position: Position) -> Vec<CompletionItem> {
        let mut items = Vec::new();

        let ctx = self.completion_context(uri, position);

        match ctx {
            CompletionContext::Type => {
                items.extend(self.type_completions());
                // Type-position also allows user-defined types.
                if let Some(ast) = self.ast_cache.get(uri) {
                    items.extend(self.type_symbol_completions(ast));
                }
            }
            CompletionContext::Member { type_name } => {
                items.extend(self.member_completions(uri, &type_name));
            }
            CompletionContext::Declaration => {
                items.extend(self.declaration_keyword_completions());
            }
            CompletionContext::Expression => {
                items.extend(self.keyword_completions());
                items.extend(self.type_completions());
                if let (Some(ast), Some(content)) = (self.ast_cache.get(uri), self.documents.get(uri)) {
                    items.extend(self.symbol_completions(ast));
                    items.extend(self.local_completions(content, ast, position));
                }
            }
        }

        items
    }

    /// Determine the completion context at the given position.
    fn completion_context(&self, uri: &str, position: Position) -> CompletionContext {
        let Some(content) = self.documents.get(uri) else {
            return CompletionContext::Expression;
        };

        let line_start = self.line_start_offset(content, position.line);
        let offset = position_to_offset(content, position).unwrap_or(line_start);
        let prefix = &content[line_start..offset];

        // Check for member access: `expr.field`
        if let Some(dot_pos) = prefix.rfind('.') {
            // We want the identifier before the dot.
            let before_dot = &prefix[..dot_pos];
            let type_name = word_before_offset(before_dot, before_dot.len()).unwrap_or_default();
            return CompletionContext::Member { type_name };
        }

        // Check for type context: after `:`, `->`, or `<`
        let trimmed = prefix.trim_end();
        if trimmed.ends_with(':') || trimmed.ends_with("->") || trimmed.ends_with('<') {
            return CompletionContext::Type;
        }

        // Check for top-level / declaration context
        let line_text = prefix.trim();
        if line_text.is_empty() || line_text == "module" {
            return CompletionContext::Declaration;
        }

        CompletionContext::Expression
    }

    /// Get the byte offset where a given line starts.
    fn line_start_offset(&self, content: &str, line: u32) -> usize {
        let mut current_line = 0u32;
        for (idx, ch) in content.char_indices() {
            if current_line == line {
                return idx;
            }
            if ch == '\n' {
                current_line += 1;
            }
        }
        content.len()
    }

    /// Declaration-position keywords only.
    fn declaration_keyword_completions(&self) -> Vec<CompletionItem> {
        vec![
            ("resource", "resource ${1:Name} {\n    $0\n}"),
            ("shared", "shared ${1:Name} {\n    $0\n}"),
            ("receipt", "receipt ${1:Name} {\n    $0\n}"),
            ("struct", "struct ${1:Name} {\n    $0\n}"),
            (
                "invariant",
                "invariant ${1:name} {\n    trigger: ${2:type_group}\n    scope: ${3:group}\n    reads: ${4:group_inputs<Token>.amount}, ${5:group_outputs<Token>.amount}\n    assert_conserved(${6:Token.amount}, scope = ${7:group})\n}",
            ),
            ("action", "action ${1:name}($2) {\n    $0\n}"),
            (
                "lock",
                "lock ${1:name}(${2:cell}: protected ${3:CellType}, ${4:owner}: lock_args ${5:Address}, ${6:claimed_owner}: witness ${7:Address}) -> bool {\n    require ${4} == ${2}.owner\n    require ${6} == ${4}\n    $0\n}",
            ),
            ("const", "const ${1:NAME}: ${2:u64} = $0;"),
            ("enum", "enum ${1:Name} {\n    $0\n}"),
            ("use", "use ${1:path};"),
        ]
        .into_iter()
        .map(|(label, insert)| CompletionItem {
            label: label.to_string(),
            kind: CompletionItemKind::Keyword,
            detail: Some(format!("{} keyword", label)),
            documentation: None,
            insert_text: Some(insert.to_string()),
        })
        .collect()
    }

    /// Completions for user-defined types (at type positions).
    fn type_symbol_completions(&self, module: &Module) -> Vec<CompletionItem> {
        let mut items = Vec::new();
        for item in &module.items {
            let (name, kind_label) = match item {
                Item::Resource(r) => (&r.name, "resource"),
                Item::Shared(s) => (&s.name, "shared"),
                Item::Receipt(r) => (&r.name, "receipt"),
                Item::Struct(s) => (&s.name, "struct"),
                Item::Enum(e) => (&e.name, "enum"),
                _ => continue,
            };
            items.push(CompletionItem {
                label: name.clone(),
                kind: CompletionItemKind::Class,
                detail: Some(format!("{} {}", kind_label, name)),
                documentation: None,
                insert_text: Some(name.clone()),
            });
        }
        items
    }

    /// Member completions for a given type name (after `.`).
    fn member_completions(&self, uri: &str, type_name: &str) -> Vec<CompletionItem> {
        let mut items = Vec::new();

        // Built-in namespace methods.
        match type_name {
            "Vec" => {
                for (name, insert) in [("new", "Vec::new()"), ("push", "push($0)"), ("len", "len()"), ("get", "get($0)")] {
                    items.push(CompletionItem {
                        label: name.to_string(),
                        kind: CompletionItemKind::Method,
                        detail: Some(format!("Vec::{}", name)),
                        documentation: None,
                        insert_text: Some(insert.to_string()),
                    });
                }
                return items;
            }
            "env" => {
                for (name, insert) in [
                    ("current_timepoint", "env::current_timepoint()"),
                    ("sighash_all", "env::sighash_all(${1:source::group_input(0)})"),
                ] {
                    items.push(CompletionItem {
                        label: name.to_string(),
                        kind: CompletionItemKind::Method,
                        detail: Some(format!("env::{}", name)),
                        documentation: None,
                        insert_text: Some(insert.to_string()),
                    });
                }
                return items;
            }
            "source" => {
                for name in ["input", "output", "cell_dep", "header_dep", "group_input", "group_output"] {
                    items.push(CompletionItem {
                        label: name.to_string(),
                        kind: CompletionItemKind::Function,
                        detail: Some(format!("source::{}", name)),
                        documentation: None,
                        insert_text: Some(format!("source::{}(${{1:0}})", name)),
                    });
                }
                return items;
            }
            "witness" => {
                for name in ["raw", "lock", "input_type", "output_type"] {
                    items.push(CompletionItem {
                        label: name.to_string(),
                        kind: CompletionItemKind::Function,
                        detail: Some(format!("witness::{}", name)),
                        documentation: None,
                        insert_text: Some(format!("witness::{}(${{1:source::group_input(0)}})", name)),
                    });
                }
                return items;
            }
            "ckb" => {
                for (name, insert) in [
                    ("header_epoch_number", "ckb::header_epoch_number()"),
                    ("header_epoch_start_block_number", "ckb::header_epoch_start_block_number()"),
                    ("header_epoch_length", "ckb::header_epoch_length()"),
                    ("input_since", "ckb::input_since()"),
                ] {
                    items.push(CompletionItem {
                        label: name.to_string(),
                        kind: CompletionItemKind::Function,
                        detail: Some(format!("ckb::{}", name)),
                        documentation: None,
                        insert_text: Some(insert.to_string()),
                    });
                }
                return items;
            }
            "Address" | "Hash" => {
                // Namespace-style methods.
                return items;
            }
            _ => {}
        }

        // User-defined type fields.
        let mut search_modules: Vec<&Module> = Vec::new();
        if let Some(ast) = self.ast_cache.get(uri) {
            search_modules.push(ast);
        }
        for module in &search_modules {
            for item in &module.items {
                let fields: &[Field] = match item {
                    Item::Resource(r) if r.name == type_name => &r.fields,
                    Item::Shared(s) if s.name == type_name => &s.fields,
                    Item::Receipt(r) if r.name == type_name => &r.fields,
                    Item::Struct(s) if s.name == type_name => &s.fields,
                    _ => continue,
                };
                for field in fields {
                    items.push(CompletionItem {
                        label: field.name.clone(),
                        kind: CompletionItemKind::Field,
                        detail: Some(format!("{}: {}", field.name, type_to_string(&field.ty))),
                        documentation: None,
                        insert_text: Some(field.name.clone()),
                    });
                }
                break;
            }
        }

        items
    }

    /// Completions for local variables visible at `position`.
    fn local_completions(&self, source: &str, module: &Module, position: Position) -> Vec<CompletionItem> {
        let mut items = Vec::new();

        for item in &module.items {
            let (params, body) = match item {
                Item::Action(a) => (&a.params, &a.body),
                Item::Function(f) => (&f.params, &f.body),
                Item::Lock(l) => (&l.params, &l.body),
                _ => continue,
            };

            // Check if position is inside this function's span.
            let func_range = span_to_range(source, item_span(item));
            if !position_in_range(position, func_range) {
                continue;
            }

            // Add parameters.
            for param in params {
                items.push(CompletionItem {
                    label: param.name.clone(),
                    kind: CompletionItemKind::Variable,
                    detail: Some(format!("param: {}", type_to_string(&param.ty))),
                    documentation: None,
                    insert_text: Some(param.name.clone()),
                });
            }

            // Add local `let` bindings that are in scope (before position).
            for stmt in body {
                let stmt_range = span_to_range(source, stmt_span(stmt));
                if position_in_range(position, stmt_range) || position_le(stmt_range.start, position) {
                    // We are past the position, stop.
                    if position_le(position, stmt_range.start) && !position_in_range(position, stmt_range) {
                        break;
                    }
                }
                if let Stmt::Let(let_stmt) = stmt {
                    if let BindingPattern::Name(name) = &let_stmt.pattern {
                        items.push(CompletionItem {
                            label: name.clone(),
                            kind: CompletionItemKind::Variable,
                            detail: Some(format!(
                                "let{}: {}",
                                if let_stmt.is_mut { " mut" } else { "" },
                                let_stmt.ty.as_ref().map(type_to_string).unwrap_or_else(|| "_".to_string())
                            )),
                            documentation: None,
                            insert_text: Some(name.clone()),
                        });
                    }
                }
            }
        }

        items
    }

    fn keyword_completions(&self) -> Vec<CompletionItem> {
        let keywords = vec![
            ("module", "module ${1:name};"),
            ("use", "use ${1:path};"),
            ("resource", "resource ${1:Name} {\n    $0\n}"),
            ("shared", "shared ${1:Name} {\n    $0\n}"),
            ("receipt", "receipt ${1:Name} {\n    $0\n}"),
            ("struct", "struct ${1:Name} {\n    $0\n}"),
            ("action", "action ${1:name}($2) {\n    $0\n}"),
            (
                "lock",
                "lock ${1:name}(${2:cell}: protected ${3:CellType}, ${4:owner}: lock_args ${5:Address}, ${6:claimed_owner}: witness ${7:Address}) -> bool {\n    require ${4} == ${2}.owner\n    require ${6} == ${4}\n    $0\n}",
            ),
            ("let", "let ${1:name} = $0;"),
            ("if", "if ${1:condition} {\n    $0\n}"),
            ("for", "for ${1:item} in ${2:iterable} {\n    $0\n}"),
            ("while", "while ${1:condition} {\n    $0\n}"),
            ("return", "return $0;"),
            ("create", "create ${1:Type} { $0 }"),
            ("destroy", "destroy ${1:expr};"),
            ("transfer", "transfer ${1:expr} to ${2:addr};"),
            ("assert_invariant", "assert_invariant(${1:condition}, \"${2:message}\");"),
            ("require", "require ${1:condition};"),
            ("protected", "protected ${1:CellType}"),
            ("witness", "witness ${1:Address}"),
            ("lock_args", "lock_args ${1:Address}"),
        ];

        keywords
            .into_iter()
            .map(|(label, insert)| CompletionItem {
                label: label.to_string(),
                kind: CompletionItemKind::Keyword,
                detail: Some(format!("{} keyword", label)),
                documentation: None,
                insert_text: Some(insert.to_string()),
            })
            .collect()
    }

    fn type_completions(&self) -> Vec<CompletionItem> {
        let types = vec![
            "u8", "u16", "u32", "u64", "u128", "i8", "i16", "i32", "i64", "i128", "bool", "String", "Address", "Hash", "Bytes", "Vec",
            "Option", "Result", "Map",
        ];

        types
            .into_iter()
            .map(|ty| CompletionItem {
                label: ty.to_string(),
                kind: CompletionItemKind::TypeParameter,
                detail: Some(format!("{} type", ty)),
                documentation: None,
                insert_text: None,
            })
            .collect()
    }

    fn symbol_completions(&self, module: &Module) -> Vec<CompletionItem> {
        let mut items = Vec::new();

        for item in &module.items {
            match item {
                Item::Resource(r) => {
                    items.push(CompletionItem {
                        label: r.name.clone(),
                        kind: CompletionItemKind::Struct,
                        detail: Some(format!("resource {}", r.name)),
                        documentation: None,
                        insert_text: Some(r.name.clone()),
                    });
                }
                Item::Shared(s) => {
                    items.push(CompletionItem {
                        label: s.name.clone(),
                        kind: CompletionItemKind::Struct,
                        detail: Some(format!("shared {}", s.name)),
                        documentation: None,
                        insert_text: Some(s.name.clone()),
                    });
                }
                Item::Receipt(r) => {
                    items.push(CompletionItem {
                        label: r.name.clone(),
                        kind: CompletionItemKind::Struct,
                        detail: Some(format!("receipt {}", r.name)),
                        documentation: None,
                        insert_text: Some(r.name.clone()),
                    });
                }
                Item::Struct(s) => {
                    items.push(CompletionItem {
                        label: s.name.clone(),
                        kind: CompletionItemKind::Struct,
                        detail: Some(format!("struct {}", s.name)),
                        documentation: None,
                        insert_text: Some(s.name.clone()),
                    });
                }
                Item::Invariant(i) => {
                    items.push(CompletionItem {
                        label: i.name.clone(),
                        kind: CompletionItemKind::Keyword,
                        detail: Some(format!("invariant {}", i.name)),
                        documentation: None,
                        insert_text: Some(i.name.clone()),
                    });
                }
                Item::Action(a) => {
                    items.push(CompletionItem {
                        label: a.name.clone(),
                        kind: CompletionItemKind::Function,
                        detail: Some(format!("action {}", a.name)),
                        documentation: a.doc_comment.clone(),
                        insert_text: Some(format!("{}($0)", a.name)),
                    });
                }
                Item::Lock(l) => {
                    items.push(CompletionItem {
                        label: l.name.clone(),
                        kind: CompletionItemKind::Function,
                        detail: Some(format!("lock {}", l.name)),
                        documentation: None,
                        insert_text: Some(format!("{}($0)", l.name)),
                    });
                }
                _ => {}
            }
        }

        items
    }

    pub fn goto_definition(&self, uri: &str, position: Position) -> Option<Location> {
        let symbol = self.symbol_at_position(uri, position)?;

        // 1. Try top-level symbol in the current file.
        if let Some(loc) = self.find_top_level_symbol(uri, &symbol) {
            return Some(loc);
        }

        // 2. Try field definition if inside a type reference (e.g. `token.amount`).
        if let Some(loc) = self.find_field_definition(uri, position, &symbol) {
            return Some(loc);
        }

        // 3. Try local variable / parameter definition.
        if let Some(loc) = self.find_local_definition(uri, position, &symbol) {
            return Some(loc);
        }

        // 4. Try workspace modules (cross-file).
        for module in self.workspace_modules(uri) {
            let module_uri = utf8_path_to_file_uri(&module.path);
            if let Some(loc) = module.ast.items.iter().find_map(|item| {
                let name = item_name(item)?;
                if name == symbol {
                    Some(Location { uri: module_uri.clone(), range: span_to_range(&module.source, item_span(item)) })
                } else {
                    None
                }
            }) {
                return Some(loc);
            }
        }

        None
    }

    /// Find a field definition for `symbol` when accessed via `expr.field`.
    fn find_field_definition(&self, uri: &str, position: Position, symbol: &str) -> Option<Location> {
        let content = self.documents.get(uri)?;
        let offset = position_to_offset(content, position)?;

        // Look for a `.` before the symbol.
        let line_start = self.line_start_offset(content, position.line);
        let prefix = &content[line_start..offset];
        let dot_pos = prefix.rfind('.')?;
        let type_name = word_before_offset(prefix, dot_pos)?;

        let ast = self.ast_cache.get(uri)?;
        for item in &ast.items {
            let (name, fields, span) = match item {
                Item::Resource(r) if r.name == type_name => (&r.name, &r.fields, r.span),
                Item::Shared(s) if s.name == type_name => (&s.name, &s.fields, s.span),
                Item::Receipt(r) if r.name == type_name => (&r.name, &r.fields, r.span),
                Item::Struct(s) if s.name == type_name => (&s.name, &s.fields, s.span),
                _ => continue,
            };
            let _ = name; // used in pattern guard
            for field in fields {
                if field.name == symbol {
                    return Some(Location { uri: uri.to_string(), range: span_to_range(content, field.span) });
                }
            }
            let _ = span;
        }
        None
    }

    /// Find a local variable or parameter definition for `symbol`.
    fn find_local_definition(&self, uri: &str, position: Position, symbol: &str) -> Option<Location> {
        let content = self.documents.get(uri)?;
        let ast = self.ast_cache.get(uri)?;

        for item in &ast.items {
            let (params, body, item_span_val) = match item {
                Item::Action(a) => (&a.params, &a.body, a.span),
                Item::Function(f) => (&f.params, &f.body, f.span),
                Item::Lock(l) => (&l.params, &l.body, l.span),
                _ => continue,
            };

            let func_range = span_to_range(content, item_span_val);
            if !position_in_range(position, func_range) {
                continue;
            }

            // Check parameters.
            for param in params {
                if param.name == symbol {
                    return Some(Location { uri: uri.to_string(), range: span_to_range(content, param.span) });
                }
            }

            // Check local let bindings.
            for stmt in body {
                if let Stmt::Let(let_stmt) = stmt {
                    if let BindingPattern::Name(name) = &let_stmt.pattern {
                        if name == symbol {
                            return Some(Location { uri: uri.to_string(), range: span_to_range(content, let_stmt.span) });
                        }
                    }
                }
            }
        }
        None
    }

    pub fn find_references(&self, uri: &str, position: Position) -> Vec<Location> {
        let Some(symbol) = self.symbol_at_position(uri, position) else {
            return Vec::new();
        };
        let mut refs = Vec::new();

        let workspace_modules = self.workspace_modules(uri);
        if !workspace_modules.is_empty() {
            for module in workspace_modules {
                let module_uri = utf8_path_to_file_uri(&module.path);
                for (start, end) in word_occurrences(&module.source, &symbol) {
                    refs.push(Location {
                        uri: module_uri.clone(),
                        range: Range {
                            start: offset_to_position(&module.source, start),
                            end: offset_to_position(&module.source, end),
                        },
                    });
                }
            }
            return refs;
        }

        if let Some(content) = self.documents.get(uri) {
            for (start, end) in word_occurrences(content, &symbol) {
                refs.push(Location {
                    uri: uri.to_string(),
                    range: Range { start: offset_to_position(content, start), end: offset_to_position(content, end) },
                });
            }
        }
        refs
    }

    pub fn hover(&self, uri: &str, position: Position) -> Option<Hover> {
        let symbol = self.symbol_at_position(uri, position)?;

        // 1. Try top-level item hover (existing logic).
        if let (Some(ast), Some(source)) = (self.ast_cache.get(uri), self.documents.get(uri)) {
            let metadata = crate::compile_metadata(source, None).ok();
            if let Some(hover) = ast.items.iter().find_map(|item| {
                if item_name(item) == Some(symbol.as_str()) {
                    self.item_hover(source, item, metadata.as_ref())
                } else {
                    None
                }
            }) {
                return Some(hover);
            }
        }

        // 2. Try field hover.
        if let Some(hover) = self.field_hover(uri, position, &symbol) {
            return Some(hover);
        }

        // 3. Try local variable / parameter hover.
        if let Some(hover) = self.local_hover(uri, position, &symbol) {
            return Some(hover);
        }

        // 4. Try workspace modules.
        for module in self.workspace_modules(uri) {
            let metadata = crate::compile_metadata(&module.source, None).ok();
            if let Some(hover) = module.ast.items.iter().find_map(|item| {
                if item_name(item) == Some(symbol.as_str()) {
                    self.item_hover(&module.source, item, metadata.as_ref())
                } else {
                    None
                }
            }) {
                return Some(hover);
            }
        }

        None
    }

    /// Hover information for a field access (e.g. `token.amount`).
    fn field_hover(&self, uri: &str, position: Position, symbol: &str) -> Option<Hover> {
        let content = self.documents.get(uri)?;
        let offset = position_to_offset(content, position)?;
        let line_start = self.line_start_offset(content, position.line);
        let prefix = &content[line_start..offset];
        let dot_pos = prefix.rfind('.')?;
        let type_name = word_before_offset(prefix, dot_pos)?;

        let ast = self.ast_cache.get(uri)?;
        for item in &ast.items {
            let fields: &[Field] = match item {
                Item::Resource(r) if r.name == type_name => &r.fields,
                Item::Shared(s) if s.name == type_name => &s.fields,
                Item::Receipt(r) if r.name == type_name => &r.fields,
                Item::Struct(s) if s.name == type_name => &s.fields,
                _ => continue,
            };
            for field in fields {
                if field.name == symbol {
                    return Some(Hover {
                        contents: format!(
                            "```cellscript\n{}: {}\n```\n\nField of `{}`",
                            field.name,
                            type_to_string(&field.ty),
                            type_name
                        ),
                        range: Some(span_to_range(content, field.span)),
                    });
                }
            }
        }
        None
    }

    /// Hover information for a local variable or parameter.
    fn local_hover(&self, uri: &str, position: Position, symbol: &str) -> Option<Hover> {
        let content = self.documents.get(uri)?;
        let ast = self.ast_cache.get(uri)?;

        for item in &ast.items {
            let (params, body, item_span_val) = match item {
                Item::Action(a) => (&a.params, &a.body, a.span),
                Item::Function(f) => (&f.params, &f.body, f.span),
                Item::Lock(l) => (&l.params, &l.body, l.span),
                _ => continue,
            };

            let func_range = span_to_range(content, item_span_val);
            if !position_in_range(position, func_range) {
                continue;
            }

            // Check parameters.
            for param in params {
                if param.name == symbol {
                    return Some(Hover {
                        contents: format!("```cellscript\n{}: {}\n```\n\nParameter", param.name, type_to_string(&param.ty)),
                        range: Some(span_to_range(content, param.span)),
                    });
                }
            }

            // Check local let bindings.
            for stmt in body {
                if let Stmt::Let(let_stmt) = stmt {
                    if let BindingPattern::Name(name) = &let_stmt.pattern {
                        if name == symbol {
                            let ty_str = let_stmt.ty.as_ref().map(type_to_string).unwrap_or_else(|| "_".to_string());
                            return Some(Hover {
                                contents: format!(
                                    "```cellscript\n{}{}: {}\n```\n\nLocal variable",
                                    if let_stmt.is_mut { "mut " } else { "" },
                                    name,
                                    ty_str
                                ),
                                range: Some(span_to_range(content, let_stmt.span)),
                            });
                        }
                    }
                }
            }
        }
        None
    }

    fn item_hover(&self, source: &str, item: &Item, metadata: Option<&crate::CompileMetadata>) -> Option<Hover> {
        let range = span_to_range(source, item_span(item));
        match item {
            Item::Resource(r) => Some(Hover {
                contents: format!("```cellscript\nresource {}\n```\n\nCapabilities: {:?}", r.name, r.capabilities),
                range: Some(range),
            }),
            Item::Shared(s) => Some(Hover { contents: format!("```cellscript\nshared {}\n```", s.name), range: Some(range) }),
            Item::Receipt(r) => Some(Hover {
                contents: format!("```cellscript\nreceipt {}\n```{}", r.name, receipt_lifecycle_hover(r, metadata)),
                range: Some(range),
            }),
            Item::Struct(s) => Some(Hover { contents: format!("```cellscript\nstruct {}\n```", s.name), range: Some(range) }),
            Item::Action(a) => Some(Hover {
                contents: format!(
                    "```cellscript\naction {}\n```\n\n{}{}",
                    a.name,
                    a.doc_comment.as_deref().unwrap_or("No documentation"),
                    action_metadata_hover(&a.name, metadata)
                ),
                range: Some(range),
            }),
            Item::Function(f) => Some(Hover {
                contents: format!("```cellscript\nfn {}\n```\n\n{}", f.name, f.doc_comment.as_deref().unwrap_or("No documentation")),
                range: Some(range),
            }),
            Item::Lock(l) => Some(Hover { contents: format!("```cellscript\nlock {}\n```", l.name), range: Some(range) }),
            Item::Invariant(i) => Some(Hover { contents: format!("```cellscript\ninvariant {}\n```", i.name), range: Some(range) }),
            _ => None,
        }
    }

    pub fn document_symbols(&self, uri: &str) -> Vec<SymbolInformation> {
        let mut symbols = Vec::new();

        if let (Some(ast), Some(source)) = (self.ast_cache.get(uri), self.documents.get(uri)) {
            for item in &ast.items {
                if let Some(symbol) = self.item_symbol(source, item, uri) {
                    symbols.push(symbol);
                }
            }
        }

        symbols
    }

    fn item_symbol(&self, source: &str, item: &Item, uri: &str) -> Option<SymbolInformation> {
        match item {
            Item::Resource(r) => Some(SymbolInformation {
                name: r.name.clone(),
                kind: SymbolKind::Struct,
                location: Location { uri: uri.to_string(), range: span_to_range(source, r.span) },
                container_name: None,
            }),
            Item::Shared(s) => Some(SymbolInformation {
                name: s.name.clone(),
                kind: SymbolKind::Struct,
                location: Location { uri: uri.to_string(), range: span_to_range(source, s.span) },
                container_name: None,
            }),
            Item::Receipt(r) => Some(SymbolInformation {
                name: r.name.clone(),
                kind: SymbolKind::Struct,
                location: Location { uri: uri.to_string(), range: span_to_range(source, r.span) },
                container_name: None,
            }),
            Item::Struct(s) => Some(SymbolInformation {
                name: s.name.clone(),
                kind: SymbolKind::Struct,
                location: Location { uri: uri.to_string(), range: span_to_range(source, s.span) },
                container_name: None,
            }),
            Item::Const(c) => Some(SymbolInformation {
                name: c.name.clone(),
                kind: SymbolKind::Constant,
                location: Location { uri: uri.to_string(), range: span_to_range(source, c.span) },
                container_name: None,
            }),
            Item::Enum(e) => Some(SymbolInformation {
                name: e.name.clone(),
                kind: SymbolKind::Enum,
                location: Location { uri: uri.to_string(), range: span_to_range(source, e.span) },
                container_name: None,
            }),
            Item::Action(a) => Some(SymbolInformation {
                name: a.name.clone(),
                kind: SymbolKind::Function,
                location: Location { uri: uri.to_string(), range: span_to_range(source, a.span) },
                container_name: None,
            }),
            Item::Function(f) => Some(SymbolInformation {
                name: f.name.clone(),
                kind: SymbolKind::Function,
                location: Location { uri: uri.to_string(), range: span_to_range(source, f.span) },
                container_name: None,
            }),
            Item::Lock(l) => Some(SymbolInformation {
                name: l.name.clone(),
                kind: SymbolKind::Function,
                location: Location { uri: uri.to_string(), range: span_to_range(source, l.span) },
                container_name: None,
            }),
            Item::Invariant(i) => Some(SymbolInformation {
                name: i.name.clone(),
                kind: SymbolKind::Event,
                location: Location { uri: uri.to_string(), range: span_to_range(source, i.span) },
                container_name: None,
            }),
            _ => None,
        }
    }

    pub fn rename(&self, uri: &str, position: Position, new_name: String) -> HashMap<String, Vec<TextEdit>> {
        let mut changes = HashMap::new();
        if !is_valid_rename_identifier(&new_name) {
            return changes;
        }
        let refs = self.find_references(uri, position);
        if refs.is_empty() {
            return changes;
        }
        for location in refs {
            changes.entry(location.uri).or_insert_with(Vec::new).push(TextEdit { range: location.range, new_text: new_name.clone() });
        }
        changes
    }

    pub fn code_action(&self, uri: &str, range: Range) -> Vec<CodeAction> {
        let mut actions = Vec::new();
        let has_lowering_diagnostic = self
            .diagnostics
            .get(uri)
            .into_iter()
            .flatten()
            .any(|diagnostic| diagnostic.source == "cellscript-lowering" && ranges_overlap(diagnostic.range, range));

        if has_lowering_diagnostic {
            actions.push(CodeAction {
                title: "Inspect lowering/runtime metadata with `cellc metadata`".to_string(),
                kind: "quickfix".to_string(),
                edit: None,
            });
            actions.push(CodeAction {
                title: "Use `--target riscv64-asm` until executable stateful lowering is implemented".to_string(),
                kind: "quickfix".to_string(),
                edit: None,
            });
        }

        actions
    }

    pub fn format_document(&self, uri: &str) -> Vec<TextEdit> {
        let Some(content) = self.documents.get(uri) else {
            return Vec::new();
        };
        let Some(ast) = self.ast_cache.get(uri) else {
            return Vec::new();
        };
        let Ok(formatted) = crate::fmt::format_default(ast) else {
            return Vec::new();
        };
        if &formatted == content {
            return Vec::new();
        }
        vec![TextEdit { range: Range { start: Position { line: 0, character: 0 }, end: end_position(content) }, new_text: formatted }]
    }

    pub fn format_range(&self, uri: &str, _range: Range) -> Vec<TextEdit> {
        self.format_document(uri)
    }

    pub fn signature_help(&self, uri: &str, position: Position) -> Option<SignatureHelp> {
        let content = self.documents.get(uri)?;
        let offset = position_to_offset(content, position)?;

        let (call_name, active_param) = self.find_call_at_offset(content, offset)?;

        let signature_info = self.find_signature(uri, &call_name)?;

        Some(SignatureHelp { signatures: vec![signature_info], active_signature: Some(0), active_parameter: Some(active_param) })
    }

    pub fn document_highlight(&self, uri: &str, position: Position) -> Vec<DocumentHighlight> {
        let Some(symbol) = self.symbol_at_position(uri, position) else {
            return Vec::new();
        };

        let mut highlights = Vec::new();

        if let Some(content) = self.documents.get(uri) {
            for (start, end) in word_occurrences(content, &symbol) {
                highlights.push(DocumentHighlight {
                    range: Range { start: offset_to_position(content, start), end: offset_to_position(content, end) },
                    kind: DocumentHighlightKind::Read,
                });
            }
        }

        highlights
    }

    pub fn folding_range(&self, uri: &str) -> Vec<FoldingRange> {
        let Some(ast) = self.ast_cache.get(uri) else {
            return Vec::new();
        };
        let Some(content) = self.documents.get(uri) else {
            return Vec::new();
        };

        let mut ranges = Vec::new();

        for item in &ast.items {
            match item {
                Item::Action(action) => {
                    let body_range = self.block_folding_range(content, &action.body, &action.name);
                    if let Some(range) = body_range {
                        ranges.push(range);
                    }
                }
                Item::Function(func) => {
                    let body_range = self.block_folding_range(content, &func.body, &func.name);
                    if let Some(range) = body_range {
                        ranges.push(range);
                    }
                }
                Item::Lock(lock) => {
                    let body_range = self.block_folding_range(content, &lock.body, &lock.name);
                    if let Some(range) = body_range {
                        ranges.push(range);
                    }
                }
                Item::Resource(r) => {
                    if !r.fields.is_empty() {
                        let range = span_to_range(content, r.span);
                        ranges.push(FoldingRange {
                            start_line: range.start.line,
                            start_character: Some(range.start.character),
                            end_line: range.end.line,
                            end_character: Some(range.end.character),
                            kind: Some(FoldingRangeKind::Region),
                        });
                    }
                }
                Item::Shared(s) => {
                    if !s.fields.is_empty() {
                        let range = span_to_range(content, s.span);
                        ranges.push(FoldingRange {
                            start_line: range.start.line,
                            start_character: Some(range.start.character),
                            end_line: range.end.line,
                            end_character: Some(range.end.character),
                            kind: Some(FoldingRangeKind::Region),
                        });
                    }
                }
                _ => {}
            }
        }

        ranges
    }

    pub fn selection_range(&self, uri: &str, position: Position) -> Option<SelectionRange> {
        let content = self.documents.get(uri)?;
        let ast = self.ast_cache.get(uri)?;
        let _offset = position_to_offset(content, position)?;

        let mut ranges: Vec<Range> = Vec::new();

        for item in &ast.items {
            let item_range = span_to_range(content, item_span(item));
            if position_in_range(position, item_range) {
                ranges.push(item_range);

                match item {
                    Item::Action(a) => {
                        for stmt in &a.body {
                            let stmt_range = span_to_range(content, stmt_span(stmt));
                            if position_in_range(position, stmt_range) {
                                ranges.push(stmt_range);
                            }
                        }
                    }
                    Item::Function(f) => {
                        for stmt in &f.body {
                            let stmt_range = span_to_range(content, stmt_span(stmt));
                            if position_in_range(position, stmt_range) {
                                ranges.push(stmt_range);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        if ranges.is_empty() {
            let line_range = Range {
                start: Position { line: position.line, character: 0 },
                end: Position { line: position.line, character: u32::MAX },
            };
            ranges.push(line_range);
        }

        ranges.sort_by(|a, b| {
            let a_size = (b.start.line - a.start.line) * 10000 + b.start.character.saturating_sub(a.start.character);
            let b_size = (b.start.line - a.start.line) * 10000 + b.start.character.saturating_sub(a.start.character);
            a_size.cmp(&b_size)
        });

        let mut result = SelectionRange { range: ranges[0], parent: None };
        for range in ranges.iter().skip(1) {
            result = SelectionRange { range: *range, parent: Some(Box::new(result)) };
        }

        Some(result)
    }

    fn find_call_at_offset(&self, content: &str, offset: usize) -> Option<(String, u32)> {
        let before = &content[..offset];
        let paren_pos = before.rfind('(')?;

        let _before_paren = &content[..paren_pos];
        let func_name = word_at_offset(content, paren_pos)?.to_string();

        let args_part = &content[paren_pos + 1..offset];
        let active_param = args_part.chars().filter(|c| *c == ',').count() as u32;

        Some((func_name, active_param))
    }

    fn find_signature(&self, uri: &str, name: &str) -> Option<SignatureInformation> {
        if let Some(ast) = self.ast_cache.get(uri) {
            if let Some(info) = self.find_signature_in_items(&ast.items, name) {
                return Some(info);
            }
        }

        for module in self.workspace_modules(uri) {
            if let Some(info) = self.find_signature_in_items(&module.ast.items, name) {
                return Some(info);
            }
        }

        None
    }

    fn find_signature_in_items(&self, items: &[Item], name: &str) -> Option<SignatureInformation> {
        for item in items {
            match item {
                Item::Action(a) if a.name == name => {
                    let params: Vec<ParameterInformation> = a
                        .params
                        .iter()
                        .map(|p| ParameterInformation {
                            label: ParameterLabel::Simple(format!("{}: {}", p.name, type_to_string(&p.ty))),
                            documentation: None,
                        })
                        .collect();
                    let return_type = a.return_type.as_ref().map(type_to_string).unwrap_or_default();
                    let label = format!(
                        "action {}({}) -> {}",
                        a.name,
                        params
                            .iter()
                            .map(|p| match &p.label {
                                ParameterLabel::Simple(s) => s.clone(),
                                ParameterLabel::Labelled { left, right } => format!("{}:{}", left, right),
                            })
                            .collect::<Vec<_>>()
                            .join(", "),
                        return_type
                    );
                    return Some(SignatureInformation { label, documentation: a.doc_comment.clone(), parameters: params });
                }
                Item::Function(f) if f.name == name => {
                    let params: Vec<ParameterInformation> = f
                        .params
                        .iter()
                        .map(|p| ParameterInformation {
                            label: ParameterLabel::Simple(format!("{}: {}", p.name, type_to_string(&p.ty))),
                            documentation: None,
                        })
                        .collect();
                    let return_type = f.return_type.as_ref().map(type_to_string).unwrap_or_default();
                    let label = format!(
                        "fn {}({}) -> {}",
                        f.name,
                        params
                            .iter()
                            .map(|p| match &p.label {
                                ParameterLabel::Simple(s) => s.clone(),
                                ParameterLabel::Labelled { left, right } => format!("{}:{}", left, right),
                            })
                            .collect::<Vec<_>>()
                            .join(", "),
                        return_type
                    );
                    return Some(SignatureInformation { label, documentation: f.doc_comment.clone(), parameters: params });
                }
                Item::Lock(l) if l.name == name => {
                    let params: Vec<ParameterInformation> = l
                        .params
                        .iter()
                        .map(|p| ParameterInformation {
                            label: ParameterLabel::Simple(format!("{}: {}", p.name, type_to_string(&p.ty))),
                            documentation: None,
                        })
                        .collect();
                    let label = format!(
                        "lock {}({}) -> {}",
                        l.name,
                        params
                            .iter()
                            .map(|p| match &p.label {
                                ParameterLabel::Simple(s) => s.clone(),
                                ParameterLabel::Labelled { left, right } => format!("{}:{}", left, right),
                            })
                            .collect::<Vec<_>>()
                            .join(", "),
                        type_to_string(&l.return_type)
                    );
                    return Some(SignatureInformation { label, documentation: None, parameters: params });
                }
                _ => {}
            }
        }
        None
    }

    fn block_folding_range(&self, content: &str, stmts: &[Stmt], _name: &str) -> Option<FoldingRange> {
        if stmts.is_empty() {
            return None;
        }
        let first_span = stmt_span(stmts.first()?);
        let last_span = stmt_span(stmts.last()?);
        let start_range = span_to_range(content, first_span);
        let end_range = span_to_range(content, last_span);
        Some(FoldingRange {
            start_line: start_range.start.line,
            start_character: Some(start_range.start.character),
            end_line: end_range.end.line,
            end_character: Some(end_range.end.character),
            kind: Some(FoldingRangeKind::Region),
        })
    }

    fn symbol_at_position(&self, uri: &str, position: Position) -> Option<String> {
        let content = self.documents.get(uri)?;
        let offset = position_to_offset(content, position)?;
        word_at_offset(content, offset)
    }

    fn find_top_level_symbol(&self, uri: &str, symbol: &str) -> Option<Location> {
        if let (Some(ast), Some(source)) = (self.ast_cache.get(uri), self.documents.get(uri)) {
            if let Some(location) = ast.items.iter().find_map(|item| {
                let name = item_name(item)?;
                if name == symbol {
                    Some(Location { uri: uri.to_string(), range: span_to_range(source, item_span(item)) })
                } else {
                    None
                }
            }) {
                return Some(location);
            }
        }

        for module in self.workspace_modules(uri) {
            if let Some(location) = module.ast.items.iter().find_map(|item| {
                let name = item_name(item)?;
                if name == symbol {
                    Some(Location { uri: utf8_path_to_file_uri(&module.path), range: span_to_range(&module.source, item_span(item)) })
                } else {
                    None
                }
            }) {
                return Some(location);
            }
        }

        None
    }

    fn workspace_modules(&self, uri: &str) -> Vec<crate::LoadedModule> {
        let Some(path) = file_uri_to_utf8_path(uri) else {
            return Vec::new();
        };

        let mut modules = crate::load_modules_for_input(&path).unwrap_or_default();

        if let (Some(content), Some(ast)) = (self.documents.get(uri), self.ast_cache.get(uri)) {
            if let Some(module) = modules.iter_mut().find(|module| same_workspace_path(&module.path, &path)) {
                module.source = content.clone();
                module.ast = ast.clone();
            } else {
                modules.push(crate::LoadedModule { path, source: content.clone(), ast: ast.clone() });
            }
        }

        modules
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextEdit {
    pub range: Range,
    pub new_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeAction {
    pub title: String,
    pub kind: String,
    pub edit: Option<WorkspaceEdit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceEdit {
    pub changes: HashMap<String, Vec<TextEdit>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureHelp {
    pub signatures: Vec<SignatureInformation>,
    pub active_signature: Option<u32>,
    pub active_parameter: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInformation {
    pub label: String,
    pub documentation: Option<String>,
    pub parameters: Vec<ParameterInformation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterInformation {
    pub label: ParameterLabel,
    pub documentation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParameterLabel {
    Simple(String),
    Labelled { left: String, right: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentHighlight {
    pub range: Range,
    pub kind: DocumentHighlightKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DocumentHighlightKind {
    Text = 1,
    Read = 2,
    Write = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoldingRange {
    pub start_line: u32,
    pub start_character: Option<u32>,
    pub end_line: u32,
    pub end_character: Option<u32>,
    pub kind: Option<FoldingRangeKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FoldingRangeKind {
    Comment,
    Imports,
    Region,
}

/// Context for completion at a given position.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CompletionContext {
    /// At a type position (after `:`, `->`, `<`).
    Type,
    /// At a member access position (after `.`), with the type name before the dot.
    Member { type_name: String },
    /// At a top-level declaration position.
    Declaration,
    /// Inside an expression body.
    Expression,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionRange {
    pub range: Range,
    pub parent: Option<Box<SelectionRange>>,
}

/// Incremental text change event sent by the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextDocumentContentChangeEvent {
    /// The range of the document that changed. If `None`, the whole document changed.
    pub range: Option<Range>,
    /// An optional length of the range that got replaced.
    pub range_length: Option<u32>,
    /// The new text of the range/document.
    pub text: String,
}

/// Apply a single incremental text change to a document string.
///
/// Replaces the text in `range` with `new_text`.
fn apply_incremental_change(content: &str, range: Range, new_text: &str) -> String {
    let Some(start_offset) = position_to_offset(content, range.start) else {
        return content.to_string();
    };
    let Some(end_offset) = position_to_offset(content, range.end) else {
        return content.to_string();
    };
    if start_offset > end_offset {
        return content.to_string();
    }
    let mut result = String::with_capacity(content.len() + new_text.len());
    result.push_str(&content[..start_offset]);
    result.push_str(new_text);
    result.push_str(&content[end_offset..]);
    result
}

fn span_to_range(source: &str, span: Span) -> Range {
    let start = offset_to_position(source, span.start.min(source.len()));
    let end = offset_to_position(source, span.end.min(source.len()));
    Range { start, end }
}

fn diagnostic_from_error(source: &str, error: &CompileError) -> Diagnostic {
    Diagnostic {
        range: span_to_range(source, error.span),
        severity: DiagnosticSeverity::Error,
        message: error.message.clone(),
        source: "cellscript".to_string(),
    }
}

fn lowering_diagnostics(source: &str, module: &Module, metadata: &crate::CompileMetadata) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for action in &metadata.actions {
        if action.elf_compatible && action.fail_closed_runtime_features.is_empty() {
            continue;
        }
        let span = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Action(def) if def.name == action.name => Some(def.span),
                _ => None,
            })
            .unwrap_or_default();
        diagnostics.push(Diagnostic {
            range: span_to_range(source, span),
            severity: DiagnosticSeverity::Warning,
            message: format!(
                "action '{}' {}; fail-closed runtime features: {}; CKB runtime features: {}; CKB accesses: {}",
                action.name,
                if action.elf_compatible { "emits fail-closed runtime traps" } else { "is not currently ELF-compatible" },
                diagnostic_list(&action.fail_closed_runtime_features),
                diagnostic_list(&action.ckb_runtime_features),
                diagnostic_access_list(&action.ckb_runtime_accesses)
            ),
            source: "cellscript-lowering".to_string(),
        });
    }

    for lock in &metadata.locks {
        if lock.elf_compatible && lock.fail_closed_runtime_features.is_empty() {
            continue;
        }
        let span = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Lock(def) if def.name == lock.name => Some(def.span),
                _ => None,
            })
            .unwrap_or_default();
        diagnostics.push(Diagnostic {
            range: span_to_range(source, span),
            severity: DiagnosticSeverity::Warning,
            message: format!(
                "lock '{}' {}; fail-closed runtime features: {}; CKB runtime features: {}; CKB accesses: {}",
                lock.name,
                if lock.elf_compatible { "emits fail-closed runtime traps" } else { "is not currently ELF-compatible" },
                diagnostic_list(&lock.fail_closed_runtime_features),
                diagnostic_list(&lock.ckb_runtime_features),
                diagnostic_access_list(&lock.ckb_runtime_accesses)
            ),
            source: "cellscript-lowering".to_string(),
        });
    }

    diagnostics
}

fn diagnostic_list(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

fn diagnostic_access_list(accesses: &[crate::CkbRuntimeAccessMetadata]) -> String {
    if accesses.is_empty() {
        return "none".to_string();
    }
    accesses
        .iter()
        .map(|access| format!("{}:{}#{} ({})", access.operation, access.source, access.index, access.binding))
        .collect::<Vec<_>>()
        .join(", ")
}

fn item_name(item: &Item) -> Option<&str> {
    match item {
        Item::Resource(r) => Some(&r.name),
        Item::Shared(s) => Some(&s.name),
        Item::Receipt(r) => Some(&r.name),
        Item::Struct(s) => Some(&s.name),
        Item::Const(c) => Some(&c.name),
        Item::Enum(e) => Some(&e.name),
        Item::Invariant(i) => Some(&i.name),
        Item::Action(a) => Some(&a.name),
        Item::Function(f) => Some(&f.name),
        Item::Lock(l) => Some(&l.name),
        Item::Use(_) => None,
    }
}

fn item_span(item: &Item) -> Span {
    match item {
        Item::Resource(r) => r.span,
        Item::Shared(s) => s.span,
        Item::Receipt(r) => r.span,
        Item::Struct(s) => s.span,
        Item::Const(c) => c.span,
        Item::Enum(e) => e.span,
        Item::Invariant(i) => i.span,
        Item::Action(a) => a.span,
        Item::Function(f) => f.span,
        Item::Lock(l) => l.span,
        Item::Use(u) => u.span,
    }
}

fn stmt_span(stmt: &Stmt) -> Span {
    match stmt {
        Stmt::Let(s) => s.span,
        Stmt::Return(_) => Span::default(),
        Stmt::If(s) => s.span,
        Stmt::For(s) => s.span,
        Stmt::While(s) => s.span,
        Stmt::Expr(_) => Span::default(),
    }
}

fn type_to_string(ty: &Type) -> String {
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
        Type::Array(inner, size) => format!("[{}; {}]", type_to_string(inner), size),
        Type::Tuple(types) => format!("({})", types.iter().map(type_to_string).collect::<Vec<_>>().join(", ")),
        Type::Named(name) => name.clone(),
        Type::Ref(inner) => format!("&{}", type_to_string(inner)),
        Type::MutRef(inner) => format!("&mut {}", type_to_string(inner)),
    }
}

fn position_in_range(pos: Position, range: Range) -> bool {
    position_le(range.start, pos) && position_le(pos, range.end)
}

fn receipt_lifecycle_hover(receipt: &ReceiptDef, metadata: Option<&crate::CompileMetadata>) -> String {
    if let Some(type_metadata) =
        metadata.and_then(|metadata| metadata.types.iter().find(|type_metadata| type_metadata.name == receipt.name))
    {
        if type_metadata.lifecycle_states.is_empty() {
            return String::new();
        }

        let transitions = if type_metadata.lifecycle_transitions.is_empty() {
            "none".to_string()
        } else {
            type_metadata
                .lifecycle_transitions
                .iter()
                .map(|transition| {
                    format!("{}[{}] -> {}[{}]", transition.from, transition.from_index, transition.to, transition.to_index)
                })
                .collect::<Vec<_>>()
                .join(", ")
        };

        return format!(
            "\n\n**Lifecycle metadata**\n\nStates: `{}`\n\nTransitions: `{}`",
            type_metadata.lifecycle_states.join(" -> "),
            transitions
        );
    }

    let Some(lifecycle) = &receipt.lifecycle else {
        return String::new();
    };
    let transitions = lifecycle.states.windows(2).map(|window| format!("{} -> {}", window[0], window[1])).collect::<Vec<_>>();
    let transitions = if transitions.is_empty() { "none".to_string() } else { transitions.join(", ") };
    format!("\n\n**Lifecycle**\n\nStates: `{}`\n\nTransitions: `{}`", lifecycle.states.join(" -> "), transitions)
}

fn action_metadata_hover(name: &str, metadata: Option<&crate::CompileMetadata>) -> String {
    let Some(metadata) = metadata else {
        return String::new();
    };
    let Some(action) = metadata.actions.iter().find(|action| action.name == name) else {
        return String::new();
    };

    let fail_closed_features = if action.fail_closed_runtime_features.is_empty() {
        "none".to_string()
    } else {
        action.fail_closed_runtime_features.join(", ")
    };
    let ckb_features =
        if action.ckb_runtime_features.is_empty() { "none".to_string() } else { action.ckb_runtime_features.join(", ") };
    let accesses = if action.ckb_runtime_accesses.is_empty() {
        "none".to_string()
    } else {
        action
            .ckb_runtime_accesses
            .iter()
            .map(|access| format!("{}:{}#{} ({})", access.operation, access.source, access.index, access.binding))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let obligations = if action.verifier_obligations.is_empty() {
        "none".to_string()
    } else {
        action
            .verifier_obligations
            .iter()
            .map(|obligation| format!("{}:{} ({})", obligation.category, obligation.feature, obligation.status))
            .collect::<Vec<_>>()
            .join(", ")
    };

    format!(
        "\n\n**Lowering metadata**\n\nEffect: `{}`\n\nELF compatible: `{}`\n\nStandalone runner compatible: `{}`\n\nFail-closed runtime features: `{}`\n\nCKB runtime features: `{}`\n\nCKB runtime accesses: `{}`\n\nVerifier obligations: `{}`",
        action.effect_class,
        action.elf_compatible,
        action.standalone_runner_compatible,
        fail_closed_features,
        ckb_features,
        accesses,
        obligations
    )
}

fn position_to_offset(source: &str, position: Position) -> Option<usize> {
    let mut line = 0u32;
    let mut col = 0u32;

    for (idx, ch) in source.char_indices() {
        if line == position.line && col == position.character {
            return Some(idx);
        }
        if ch == '\n' {
            line += 1;
            col = 0;
        } else {
            col = col.checked_add(ch.len_utf16() as u32)?;
            if line == position.line && col == position.character {
                return Some(idx + ch.len_utf8());
            }
            if line == position.line && col > position.character {
                return None;
            }
        }
    }

    if line == position.line && col == position.character {
        Some(source.len())
    } else {
        None
    }
}

fn offset_to_position(source: &str, offset: usize) -> Position {
    let mut line = 0u32;
    let mut col = 0u32;
    for (idx, ch) in source.char_indices() {
        if idx >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 0;
        } else {
            col += ch.len_utf16() as u32;
        }
    }
    Position { line, character: col }
}

fn end_position(source: &str) -> Position {
    offset_to_position(source, source.len())
}

fn ranges_overlap(left: Range, right: Range) -> bool {
    position_le(left.start, right.end) && position_le(right.start, left.end)
}

fn position_le(left: Position, right: Position) -> bool {
    left.line < right.line || (left.line == right.line && left.character <= right.character)
}

fn is_ident_char(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

fn word_at_offset(source: &str, offset: usize) -> Option<String> {
    if source.is_empty() || offset > source.len() {
        return None;
    }
    let mut start = offset;
    while start > 0 {
        let prev_idx = source[..start].char_indices().last()?.0;
        let ch = source[prev_idx..start].chars().next()?;
        if !is_ident_char(ch) {
            break;
        }
        start = prev_idx;
    }

    let mut end = offset;
    while end < source.len() {
        let ch = source[end..].chars().next()?;
        if !is_ident_char(ch) {
            break;
        }
        end += ch.len_utf8();
    }

    if start == end {
        None
    } else {
        Some(source[start..end].to_string())
    }
}

/// Get the word immediately before the given offset in `source`.
/// Unlike `word_at_offset`, this scans backwards from `offset` and stops at
/// the first non-identifier character, returning the identifier that ends
/// just before `offset`.
fn word_before_offset(source: &str, offset: usize) -> Option<String> {
    if source.is_empty() || offset == 0 || offset > source.len() {
        return None;
    }
    // Skip trailing whitespace.
    let mut end = offset;
    while end > 0 {
        let prev_idx = source[..end].char_indices().last()?.0;
        let ch = source[prev_idx..end].chars().next()?;
        if !ch.is_whitespace() {
            break;
        }
        end = prev_idx;
    }
    if end == 0 {
        return None;
    }
    // Scan the identifier backwards.
    let mut start = end;
    while start > 0 {
        let prev_idx = source[..start].char_indices().last()?.0;
        let ch = source[prev_idx..start].chars().next()?;
        if !is_ident_char(ch) {
            break;
        }
        start = prev_idx;
    }
    if start == end {
        None
    } else {
        Some(source[start..end].to_string())
    }
}

fn word_occurrences(source: &str, symbol: &str) -> Vec<(usize, usize)> {
    let mut matches = Vec::new();
    if symbol.is_empty() {
        return matches;
    }

    let Ok(tokens) = crate::lexer::lex(source) else {
        return matches;
    };
    for token in tokens {
        if let TokenKind::Identifier(name) = token.kind {
            if name == symbol {
                matches.push((token.span.start, token.span.end));
            }
        }
    }
    matches
}

fn file_uri_to_utf8_path(uri: &str) -> Option<Utf8PathBuf> {
    let path = uri.strip_prefix("file://")?;
    let decoded = percent_decode(path)?;
    let candidate = Utf8PathBuf::from(decoded);
    std::fs::canonicalize(&candidate).ok().and_then(|path| Utf8PathBuf::from_path_buf(path).ok()).or(Some(candidate))
}

fn is_valid_rename_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_alphabetic() || first == '_') {
        return false;
    }
    if !chars.all(|ch| ch.is_alphanumeric() || ch == '_') {
        return false;
    }
    matches!(keyword_or_identifier(name), TokenKind::Identifier(_))
}

fn utf8_path_to_file_uri(path: &camino::Utf8Path) -> String {
    format!("file://{}", path)
}

fn same_workspace_path(left: &camino::Utf8Path, right: &camino::Utf8Path) -> bool {
    left == right
        || std::fs::canonicalize(left).ok().zip(std::fs::canonicalize(right).ok()).map(|(left, right)| left == right).unwrap_or(false)
}

fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'%' {
            if idx + 2 >= bytes.len() {
                return None;
            }
            let hi = hex_nibble(bytes[idx + 1])?;
            let lo = hex_nibble(bytes[idx + 2])?;
            out.push((hi << 4) | lo);
            idx += 3;
        } else {
            out.push(bytes[idx]);
            idx += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(10 + byte - b'a'),
        b'A'..=b'F' => Some(10 + byte - b'A'),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_lsp_position_conversion_uses_utf16_columns() {
        let source = "a😀b\nβc";
        let b_offset = source.find('b').expect("b offset");
        let beta_offset = source.find('β').expect("beta offset");

        assert_eq!(offset_to_position(source, b_offset), Position { line: 0, character: 3 });
        assert_eq!(position_to_offset(source, Position { line: 0, character: 3 }), Some(b_offset));
        assert_eq!(position_to_offset(source, Position { line: 0, character: 2 }), None);
        assert_eq!(offset_to_position(source, beta_offset), Position { line: 1, character: 0 });
        assert_eq!(position_to_offset(source, Position { line: 1, character: 1 }), Some(beta_offset + 'β'.len_utf8()));
    }

    #[test]
    fn test_incremental_change_applies_utf16_ranges_after_non_bmp_text() {
        let source = "module demo\n// 😀 marker\n";
        let start = source.find("marker").expect("marker start");
        let end = start + "marker".len();
        let updated = apply_incremental_change(
            source,
            Range { start: offset_to_position(source, start), end: offset_to_position(source, end) },
            "done",
        );

        assert_eq!(updated, "module demo\n// 😀 done\n");
    }

    #[test]
    fn test_incremental_change_ignores_invalid_utf16_ranges() {
        let source = "module demo\n// 😀 marker\n";

        let invalid_surrogate_middle = apply_incremental_change(
            source,
            Range { start: Position { line: 1, character: 4 }, end: Position { line: 1, character: 4 } },
            "bad",
        );
        assert_eq!(invalid_surrogate_middle, source);

        let reversed = apply_incremental_change(
            source,
            Range { start: Position { line: 1, character: 12 }, end: Position { line: 1, character: 8 } },
            "bad",
        );
        assert_eq!(reversed, source);
    }

    #[test]
    fn test_lsp_server() {
        let mut server = LspServer::new();

        let uri = "file:///test.cell".to_string();
        let content = "module test;\n\naction answer() -> u64 {\n    42\n}\n".to_string();

        server.open_document(uri.clone(), content);
        assert!(server.get_diagnostics(&uri).is_empty());

        let completions = server.completion(&uri, Position { line: 0, character: 0 });
        assert!(!completions.is_empty());

        let keywords: Vec<_> = completions.iter().filter(|c| c.kind == CompletionItemKind::Keyword).collect();
        assert!(!keywords.is_empty());
    }

    #[test]
    fn test_keyword_completions() {
        let server = LspServer::new();
        let keywords = server.keyword_completions();

        assert!(keywords.iter().any(|k| k.label == "module"));
        assert!(keywords.iter().any(|k| k.label == "resource"));
        assert!(keywords.iter().any(|k| k.label == "action"));
        assert!(keywords.iter().any(|k| k.label == "require"));
        assert!(keywords.iter().any(|k| k.label == "protected"));
        assert!(keywords.iter().any(|k| k.label == "witness"));
        assert!(keywords.iter().any(|k| k.label == "lock_args"));
    }

    #[test]
    fn test_ckb_namespace_completions() {
        let server = LspServer::new();

        let env = server.member_completions("file:///test.cell", "env");
        assert!(env.iter().any(|item| item.label == "sighash_all"));

        let source = server.member_completions("file:///test.cell", "source");
        assert!(source.iter().any(|item| item.label == "group_input"));

        let witness = server.member_completions("file:///test.cell", "witness");
        assert!(witness.iter().any(|item| item.label == "lock"));

        let ckb = server.member_completions("file:///test.cell", "ckb");
        assert!(ckb.iter().any(|item| item.label == "input_since"));
    }

    #[test]
    fn test_parse_errors_become_diagnostics() {
        let mut server = LspServer::new();
        let uri = "file:///bad.cell".to_string();
        server.open_document(uri.clone(), "module bad;\naction broken( {\n".to_string());
        let diagnostics = server.get_diagnostics(&uri);
        assert!(!diagnostics.is_empty());
        assert_eq!(diagnostics[0].severity, DiagnosticSeverity::Error);
    }

    #[test]
    fn test_goto_definition_and_references() {
        let mut server = LspServer::new();
        let uri = "file:///defs.cell".to_string();
        let source = "module defs;\n\nresource Token {\n    amount: u64,\n}\n\naction make() -> u64 {\n    let token = Token { amount: 1 };\n    token.amount\n}\n";
        server.open_document(uri.clone(), source.to_string());

        let definition = server.goto_definition(&uri, Position { line: 7, character: 16 }).expect("definition");
        assert_eq!(definition.range.start.line, 2);

        let refs = server.find_references(&uri, Position { line: 7, character: 16 });
        assert!(refs.len() >= 2);
    }

    #[test]
    fn test_hover() {
        let mut server = LspServer::new();
        let uri = "file:///hover.cell".to_string();
        let source = "module hover;\n\naction demo(x: u64)->u64{\n    x\n}\n";
        server.open_document(uri.clone(), source.to_string());

        let hover = server.hover(&uri, Position { line: 2, character: 7 }).expect("hover");
        assert!(hover.contents.contains("action demo"));
    }

    #[test]
    fn test_action_hover_includes_lowering_metadata() {
        let mut server = LspServer::new();
        let uri = "file:///metadata_hover.cell".to_string();
        let source = r#"
module metadata_hover

shared Config {
    threshold: u64,
}

resource Token has store, transfer, destroy {
    amount: u64,
}

action update(amount: u64) -> u64 {
    let cfg = read_ref<Config>()
    let token = create Token { amount: amount }
    consume token
    return cfg.threshold
}
"#;
        server.open_document(uri.clone(), source.to_string());

        let hover = server.hover(&uri, Position { line: 11, character: 8 }).expect("hover");
        assert!(hover.contents.contains("Lowering metadata"));
        assert!(hover.contents.contains("ELF compatible: `true`"));
        // This action uses read_ref + consume, which require CKB runtime,
        // so standalone runner is not compatible.
        assert!(hover.contents.contains("Standalone runner compatible: `false`"));
        assert!(hover.contents.contains("Fail-closed runtime features: `none"));
        assert!(hover.contents.contains("CKB runtime features: `consume-input-cell, read-cell-dep, verify-output-cell`"));
        assert!(hover.contents.contains("consume:Input#0"));
        assert!(hover.contents.contains("read_ref:CellDep#0"));
        assert!(hover.contents.contains("create:Output#0"));
        assert!(hover.contents.contains("Verifier obligations"));
        assert!(hover.contents.contains("cell-access:consume:Input#0 (ckb-runtime)"));
    }

    #[test]
    fn test_receipt_hover_includes_lifecycle_metadata() {
        let mut server = LspServer::new();
        let uri = "file:///lifecycle_hover.cell".to_string();
        let source = r#"
module lifecycle_hover

#[lifecycle(Created -> Active)]
receipt Ticket has store {
    state: u8,
    id: u64,
}

action activate(ticket: Ticket) -> Ticket {
    let active = 1
    consume ticket
    return create Ticket {
        state: active,
        id: ticket.id,
    }
}
"#;
        server.open_document(uri.clone(), source.to_string());

        let hover = server.hover(&uri, Position { line: 4, character: 9 }).expect("hover");
        assert!(hover.contents.contains("receipt Ticket"));
        assert!(hover.contents.contains("Lifecycle metadata"));
        assert!(hover.contents.contains("States: `Created -> Active`"));
        assert!(hover.contents.contains("Created[0] -> Active[1]"));
    }

    #[test]
    fn test_lifecycle_errors_become_lsp_diagnostics() {
        let mut server = LspServer::new();
        let uri = "file:///bad_lifecycle.cell".to_string();
        let source = r#"
module bad_lifecycle

#[lifecycle(Created -> Created)]
receipt Ticket has store {
    state: u8,
    id: u64,
}
"#;
        server.open_document(uri.clone(), source.to_string());

        let diagnostics = server.get_diagnostics(&uri);
        let error = diagnostics.iter().find(|diagnostic| diagnostic.source == "cellscript").expect("lifecycle diagnostic");
        assert_eq!(error.severity, DiagnosticSeverity::Error);
        assert!(error.message.contains("duplicate lifecycle state: Created"));
    }

    #[test]
    fn test_lowering_diagnostics_warn_for_fail_closed_runtime_actions() {
        let mut server = LspServer::new();
        let uri = "file:///metadata_diagnostic.cell".to_string();
        let source = r#"
module metadata_diagnostic

shared Config {
    threshold: u64,
}

resource Token has store, transfer, destroy {
    amount: u64,
}

action update(amount: u64) -> u64 {
    let cfg = read_ref<Config>()
    let token = create Token { amount: amount }
    consume token
    return cfg.threshold
}
"#;
        server.open_document(uri.clone(), source.to_string());

        let diagnostics = server.get_diagnostics(&uri);
        // consume/create/read_ref now have real verifier lowering, so this program
        // is ELF-compatible and no longer triggers a lowering diagnostic.
        let lowering_warning = diagnostics.iter().find(|diagnostic| diagnostic.source == "cellscript-lowering");
        assert!(lowering_warning.is_none(), "consume/create/read_ref should not produce lowering warning: {:?}", lowering_warning);
    }

    #[test]
    fn test_code_actions_for_lowering_diagnostics() {
        let mut server = LspServer::new();
        let uri = "file:///metadata_action.cell".to_string();
        let source = r#"
module metadata_action

resource NFT {
    token_id: u64,
}

action use_collection() -> Vec<NFT> {
    let mut items = Vec::new()
    let nft = create NFT {
        token_id: 1,
    }
    items.push(nft)
    return items
}
"#;
        server.open_document(uri.clone(), source.to_string());

        let actions =
            server.code_action(&uri, Range { start: Position { line: 0, character: 0 }, end: Position { line: 20, character: 0 } });
        assert!(actions.iter().any(|action| action.title.contains("cellc metadata")));
        assert!(actions.iter().any(|action| action.title.contains("riscv64-asm")));
        assert!(actions.iter().all(|action| action.edit.is_none()));
    }

    #[test]
    fn test_format_document() {
        let mut server = LspServer::new();
        let uri = "file:///fmt.cell".to_string();
        let source = "module fmt\naction demo(x:u64)->u64{x}\n";
        server.open_document(uri.clone(), source.to_string());

        let edits = server.format_document(&uri);
        assert_eq!(edits.len(), 1);
        assert!(edits[0].new_text.contains("action demo(x: u64) -> u64 {"));
    }

    #[test]
    fn test_workspace_goto_definition_across_modules() {
        let temp = tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("Cell.toml"), "[package]\nentry = \"src/main.cell\"\n").unwrap();
        std::fs::write(root.join("src/types.cell"), "module demo::types\n\nresource Token {\n    amount: u64,\n}\n").unwrap();
        let main_source =
            "module demo::main\n\nuse demo::types::Token\n\naction inspect(token: Token) -> u64 {\n    token.amount\n}\n";
        let main_path = root.join("src/main.cell");
        std::fs::write(&main_path, main_source).unwrap();

        let mut server = LspServer::new();
        let main_uri = utf8_path_to_file_uri(&main_path);
        server.open_document(main_uri.clone(), main_source.to_string());

        let definition = server.goto_definition(&main_uri, Position { line: 4, character: 22 }).expect("cross-module definition");
        assert!(definition.uri.ends_with("/src/types.cell"));
        assert_eq!(definition.range.start.line, 2);
    }

    #[test]
    fn test_workspace_references_across_modules() {
        let temp = tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("Cell.toml"), "[package]\nentry = \"src/main.cell\"\n").unwrap();
        let types_source = "module demo::types\n\nresource Token {\n    amount: u64,\n}\n";
        let types_path = root.join("src/types.cell");
        std::fs::write(&types_path, types_source).unwrap();
        let main_source =
            "module demo::main\n\nuse demo::types::Token\n\naction inspect(token: Token) -> u64 {\n    token.amount\n}\n";
        std::fs::write(root.join("src/main.cell"), main_source).unwrap();

        let mut server = LspServer::new();
        let types_uri = utf8_path_to_file_uri(&types_path);
        server.open_document(types_uri.clone(), types_source.to_string());

        let refs = server.find_references(&types_uri, Position { line: 2, character: 10 });
        assert!(refs.iter().any(|location| location.uri.ends_with("/src/types.cell")));
        assert!(refs.iter().any(|location| location.uri.ends_with("/src/main.cell")));
        assert!(refs.len() >= 3);
    }

    #[test]
    fn test_workspace_rename_groups_edits_by_file() {
        let temp = tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("Cell.toml"), "[package]\nentry = \"src/main.cell\"\n").unwrap();
        let types_source = "module demo::types\n\nresource Token {\n    amount: u64,\n}\n";
        let types_path = root.join("src/types.cell");
        std::fs::write(&types_path, types_source).unwrap();
        let main_source =
            "module demo::main\n\nuse demo::types::Token\n\naction inspect(token: Token) -> u64 {\n    token.amount\n}\n";
        let main_path = root.join("src/main.cell");
        std::fs::write(&main_path, main_source).unwrap();

        let mut server = LspServer::new();
        let types_uri = utf8_path_to_file_uri(&types_path);
        server.open_document(types_uri.clone(), types_source.to_string());

        let changes = server.rename(&types_uri, Position { line: 2, character: 10 }, "Asset".to_string());

        let type_uri =
            changes.keys().find(|uri| uri.ends_with("/src/types.cell")).expect("rename should edit the defining file").clone();
        let main_uri = changes
            .keys()
            .find(|uri| uri.ends_with("/src/main.cell"))
            .expect("rename should edit referencing files separately")
            .clone();
        let type_edits = changes.get(&type_uri).expect("defining file edits should be present");
        let main_edits = changes.get(&main_uri).expect("referencing file edits should be present");
        assert_eq!(changes.len(), 2);
        assert_eq!(type_edits.len(), 1);
        assert!(main_edits.len() >= 2, "main file should include the import and parameter references: {:?}", main_edits);
        assert!(changes.values().flatten().all(|edit| edit.new_text == "Asset"));
    }

    #[test]
    fn test_workspace_rename_rejects_invalid_new_names() {
        let mut server = LspServer::new();
        let uri = "file:///rename.cell".to_string();
        let source = "module demo\n\nresource Token {\n    amount: u64,\n}\n";
        server.open_document(uri.clone(), source.to_string());

        for new_name in ["", "123Token", "Token-V2", "resource", "Address"] {
            let changes = server.rename(&uri, Position { line: 2, character: 10 }, new_name.to_string());
            assert!(changes.is_empty(), "rename should fail closed for invalid new name `{new_name}`");
        }
    }

    #[test]
    fn test_workspace_rename_respects_unicode_identifier_boundaries() {
        let mut server = LspServer::new();
        let uri = "file:///unicode_rename.cell".to_string();
        let source = r#"module unicode_rename

resource βToken {
    amount: u64,
}

resource Token {
    amount: u64,
}

action inspect(token: Token) -> u64 {
    token.amount
}
"#;
        server.open_document(uri.clone(), source.to_string());

        let changes = server.rename(&uri, Position { line: 6, character: 10 }, "Asset".to_string());
        let edits = changes.get(&uri).expect("rename should edit the current document");

        assert!(edits.iter().all(|edit| edit.range.start.line != 2), "rename must not edit the suffix of βToken: {edits:?}");
        assert!(edits.iter().any(|edit| edit.range.start.line == 6), "definition should be renamed: {edits:?}");
        assert!(edits.iter().any(|edit| edit.range.start.line == 10), "type reference should be renamed: {edits:?}");
    }

    #[test]
    fn test_workspace_rename_skips_comments_and_strings() {
        let mut server = LspServer::new();
        let uri = "file:///rename_text.cell".to_string();
        let source = r#"module rename_text

// Token in a comment must not be edited.
resource Token {
    amount: u64,
}

action inspect(token: Token) -> u64 {
    let label = "Token"
    token.amount
}
"#;
        server.open_document(uri.clone(), source.to_string());

        let changes = server.rename(&uri, Position { line: 3, character: 10 }, "Asset".to_string());
        let edits = changes.get(&uri).expect("rename should edit identifiers in the current document");

        assert!(edits.iter().all(|edit| edit.range.start.line != 2), "rename must not edit comments: {edits:?}");
        assert!(edits.iter().all(|edit| edit.range.start.line != 8), "rename must not edit string literals: {edits:?}");
        assert!(edits.iter().any(|edit| edit.range.start.line == 3), "definition should be renamed: {edits:?}");
        assert!(edits.iter().any(|edit| edit.range.start.line == 7), "type reference should be renamed: {edits:?}");
    }
}
