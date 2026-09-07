use crate::ast::*;
use crate::error::{CompileError, DiagnosticSeverity as CompilerDiagnosticSeverity, Span};
use crate::lexer::token::{keyword_or_identifier, TokenKind};
use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg(not(feature = "wasm"))]
pub mod server;

pub struct LspServer {
    documents: HashMap<String, String>,
    ast_cache: HashMap<String, Module>,
    diagnostics: HashMap<String, Vec<Diagnostic>>,
    edition_overrides: HashMap<String, crate::CellScriptEdition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub range: Range,
    pub severity: DiagnosticSeverity,
    pub code: Option<String>,
    pub code_description: Option<String>,
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
        Self { documents: HashMap::new(), ast_cache: HashMap::new(), diagnostics: HashMap::new(), edition_overrides: HashMap::new() }
    }

    pub fn open_document(&mut self, uri: String, content: String) {
        self.edition_overrides.remove(&uri);
        self.store_document(uri, content);
    }

    /// Open a virtual document under an explicit source edition.
    ///
    /// Native LSP clients normally resolve the edition from `Cell.toml`.
    /// Browser and other in-memory clients have no manifest path, so they use
    /// this entry point instead of silently falling back to Edition 2026.
    pub fn open_document_with_edition(&mut self, uri: String, content: String, edition: crate::CellScriptEdition) {
        self.edition_overrides.insert(uri.clone(), edition);
        self.store_document(uri, content);
    }

    pub fn update_document(&mut self, uri: String, content: String) {
        self.store_document(uri, content);
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
            if content.len() > crate::MAX_SOURCE_BYTES {
                self.reject_oversized_document(uri);
                return;
            }
        }

        self.store_document(uri.to_string(), content);
    }

    pub fn close_document(&mut self, uri: &str) {
        self.documents.remove(uri);
        self.ast_cache.remove(uri);
        self.diagnostics.remove(uri);
        self.edition_overrides.remove(uri);
    }

    fn store_document(&mut self, uri: String, content: String) {
        if content.len() > crate::MAX_SOURCE_BYTES {
            self.reject_oversized_document(&uri);
            return;
        }
        self.parse_document(&uri, &content);
        self.documents.insert(uri, content);
    }

    fn reject_oversized_document(&mut self, uri: &str) {
        self.documents.remove(uri);
        self.ast_cache.remove(uri);
        self.diagnostics.insert(
            uri.to_string(),
            vec![Diagnostic {
                range: Range { start: Position { line: 0, character: 0 }, end: Position { line: 0, character: 0 } },
                severity: DiagnosticSeverity::Error,
                code: None,
                code_description: None,
                message: format!("source exceeds the {} byte compiler limit", crate::MAX_SOURCE_BYTES),
                source: "cellscript".to_string(),
            }],
        );
    }

    fn parse_document(&mut self, uri: &str, content: &str) {
        self.ast_cache.remove(uri);
        let uri_path = file_uri_to_utf8_path(uri).filter(|path| path.exists());
        let edition = self.document_edition(uri);
        let ast = match crate::frontend::parse_diagnostics(content, edition) {
            Ok(ast) => ast,
            Err(errors) => {
                self.diagnostics.insert(uri.to_string(), errors.iter().map(|error| diagnostic_from_error(content, error)).collect());
                return;
            }
        };

        self.ast_cache.insert(uri.to_string(), ast.clone());
        let report = uri_path
            .as_ref()
            .map(|path| crate::compile_path_metadata_with_diagnostics_for_source(path, content, crate::CompileOptions::default()))
            .unwrap_or_else(|| crate::compile_metadata_with_diagnostics(content, edition, None));
        let mut diagnostics = report
            .diagnostics
            .iter()
            .filter(|error| diagnostic_belongs_to_uri(error, uri_path.as_ref()))
            .map(|error| diagnostic_from_error(content, error))
            .collect::<Vec<_>>();
        if let Some(metadata) = report.metadata.as_ref() {
            diagnostics.extend(lowering_diagnostics(content, &ast, metadata));
        }
        self.diagnostics.insert(uri.to_string(), diagnostics);
    }

    fn document_edition(&self, uri: &str) -> crate::CellScriptEdition {
        self.edition_overrides.get(uri).copied().unwrap_or_else(|| {
            file_uri_to_utf8_path(uri).as_ref().and_then(|path| crate::source_edition(path).ok()).unwrap_or(crate::CURRENT_EDITION)
        })
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
            CompletionContext::Namespace { type_name } => {
                // These built-in namespaces do not require a complete AST:
                // completion commonly runs while `witness::` is unfinished.
                if matches!(type_name.as_str(), "witness" | "ckb") {
                    items.extend(self.member_completions(uri, &type_name));
                }
                if let Some(ast) = self.ast_cache.get(uri) {
                    items.extend(self.namespace_symbol_completions(ast, &type_name));
                }
            }
            CompletionContext::Declaration => {
                items.extend(self.declaration_keyword_completions(uri));
            }
            CompletionContext::Expression => {
                items.extend(self.keyword_completions(uri));
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

        // Check for namespace access: `Type::Variant`.
        if let Some(scope_pos) = prefix.rfind("::") {
            let suffix = &prefix[scope_pos + 2..];
            if suffix.chars().all(is_ident_char) {
                let before_scope = &prefix[..scope_pos];
                let type_name = word_before_offset(before_scope, before_scope.len()).unwrap_or_default();
                return CompletionContext::Namespace { type_name };
            }
        }

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
    fn declaration_keyword_completions(&self, uri: &str) -> Vec<CompletionItem> {
        let edition = self.document_edition(uri);
        let mut declarations = vec![
            ("resource", "resource ${1:Name} {\n    $0\n}"),
            ("shared", "shared ${1:Name} {\n    $0\n}"),
            ("receipt", "receipt ${1:Name} {\n    $0\n}"),
            ("struct", "struct ${1:Name} {\n    $0\n}"),
            ("flow", "flow ${1:Name} for ${2:Type}.${3:state} {\n    ${4:Created} -> ${5:Live};\n}"),
            (
                "invariant",
                "invariant ${1:name} {\n    trigger: ${2:type_group}\n    scope: ${3:group}\n    reads: ${4:group_inputs<Token>.amount}, ${5:group_outputs<Token>.amount}\n    assert_conserved(${6:Token.amount}, scope = ${7:group})\n}",
            ),
            ("action", "action ${1:name}(input ${2:cell}: ${3:CellType}) -> ${4:output}: ${3:CellType} {\n    verification\n        $0\n}"),
            (
                "lock",
                "lock ${1:name}(protected ${2:cell}: ${3:CellType}) -> bool {\n    verification\n        require ${4:authorization_condition}\n        $0\n}",
            ),
            ("const", "const ${1:NAME}: ${2:u64} = $0;"),
            ("enum", "enum ${1:Name} {\n    $0\n}"),
            ("use", "use ${1:path};"),
            ("public", "public ${1:fn}"),
            ("private", "private ${1:fn}"),
            ("public(package)", "public(package) ${1:fn}"),
        ];
        if edition == crate::NEXT_EDITION {
            declarations.push((
                "type_script",
                "type_script ${1:Name} on type_group<${2:CellType}> {\n    entry ${3:verify}(\n        input ${4:before}: ${2:CellType} from group_input[0],\n        witness ${5:to}: Address from group_witness.input_type,\n        output ${6:after}: ${2:CellType} from group_output[0],\n    ) {\n        verify {\n            enforce ${4:before}.${7:amount} > 0\n        }\n\n        effects {\n            replace ${4:before} -> ${6:after} {\n                data {\n                    ${7:amount} = same\n                }\n                identity = same\n                type_script = same\n                lock_script = exact_hash(${5:to})\n                capacity = same\n                cardinality = one_to_one\n            }\n        }\n    }\n}",
            ));
            declarations.push((
                "lock_script",
                "lock_script ${1:Name} on lock_group {\n    entry ${2:unlock}(\n        protected ${3:cell}: ${4:CellType} from group_input[0],\n        lock_args ${5:owner}: Address from current_script.args,\n        witness ${6:claimed_owner}: Address from group_witness.input_type,\n    ) {\n        verify {\n            enforce ${3:cell}.${7:owner} == ${5:owner}\n            enforce ${6:claimed_owner} == ${5:owner}\n        }\n    }\n}",
            ));
        }
        declarations
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

    fn namespace_symbol_completions(&self, module: &Module, type_name: &str) -> Vec<CompletionItem> {
        let mut items = Vec::new();
        for item in &module.items {
            match item {
                Item::Enum(enum_def) if enum_def.name == type_name => {
                    items.extend(enum_def.variants.iter().map(|variant| {
                        let payload = variant.fields.iter().map(type_to_string).collect::<Vec<_>>();
                        let insert_text = if payload.is_empty() {
                            variant.name.clone()
                        } else {
                            format!(
                                "{}({})",
                                variant.name,
                                (0..payload.len()).map(|index| format!("value{}", index + 1)).collect::<Vec<_>>().join(", ")
                            )
                        };
                        CompletionItem {
                            label: variant.name.clone(),
                            kind: CompletionItemKind::EnumMember,
                            detail: Some(if payload.is_empty() {
                                format!("enum variant {}::{}", enum_def.name, variant.name)
                            } else {
                                format!("enum variant {}::{}({})", enum_def.name, variant.name, payload.join(", "))
                            }),
                            documentation: (!payload.is_empty()).then(|| {
                                "Fixed-width payload constructor; generic enum templates specialize to the same checked layout before IR."
                                    .to_string()
                            }),
                            insert_text: Some(insert_text),
                        }
                    }));
                }
                _ => {}
            }
        }
        items.extend(Self::flow_state_completions(module, type_name));
        items
    }

    fn flow_state_completions(module: &Module, type_name: &str) -> Vec<CompletionItem> {
        module
            .items
            .iter()
            .filter_map(|item| {
                let Item::Flow(machine) = item else {
                    return None;
                };
                (machine.target.base == type_name).then_some(machine)
            })
            .flat_map(|machine| {
                let states = Self::flow_enum_states(module, type_name, &machine.target.field)
                    .unwrap_or_else(|| Self::transition_states(machine));
                let field_name = machine.target.field.clone();
                states.into_iter().enumerate().map(move |(index, state)| CompletionItem {
                    label: state.clone(),
                    kind: CompletionItemKind::EnumMember,
                    detail: Some(format!("flow state {}::{}", type_name, state)),
                    documentation: Some(format!("State index {} for flow field `{}.{}`.", index, type_name, field_name)),
                    insert_text: Some(state),
                })
            })
            .collect()
    }

    fn flow_enum_states(module: &Module, type_name: &str, field_name: &str) -> Option<Vec<String>> {
        let enum_name = module.items.iter().find_map(|item| {
            let fields = match item {
                Item::Resource(def) if def.name == type_name => Some(&def.fields),
                Item::Shared(def) if def.name == type_name => Some(&def.fields),
                Item::Receipt(def) if def.name == type_name => Some(&def.fields),
                Item::Struct(def) if def.name == type_name => Some(&def.fields),
                _ => None,
            }?;
            fields.iter().find_map(|field| {
                if field.name == field_name
                    && let Type::Named(name) = &field.ty
                {
                    return Some(name.clone());
                }
                None
            })
        })?;

        module.items.iter().find_map(|item| {
            let Item::Enum(enum_def) = item else {
                return None;
            };
            (enum_def.name == enum_name && enum_def.variants.iter().all(|variant| variant.fields.is_empty()))
                .then(|| enum_def.variants.iter().map(|variant| variant.name.clone()).collect())
        })
    }

    fn transition_states(machine: &FlowDef) -> Vec<String> {
        let mut states = Vec::new();
        for transition in &machine.transitions {
            for raw in [&transition.from, &transition.to] {
                let state = raw.rsplit_once("::").map_or(raw.as_str(), |(_, state)| state);
                if !states.iter().any(|existing| existing == state) {
                    states.push(state.to_string());
                }
            }
        }
        states
    }

    /// Member completions for a given type name (after `.`).
    fn member_completions(&self, uri: &str, type_name: &str) -> Vec<CompletionItem> {
        let mut items = Vec::new();

        // Built-in namespace methods.
        match type_name {
            "Vec" => {
                for (name, insert) in [
                    ("new", "Vec::new()"),
                    ("with_capacity", "Vec::with_capacity($0)"),
                    ("capacity", "capacity()"),
                    ("push", "push($0)"),
                    ("extend_from_slice", "extend_from_slice($0)"),
                    ("len", "len()"),
                    ("is_empty", "is_empty()"),
                    ("first", "first()"),
                    ("last", "last()"),
                    ("contains", "contains($0)"),
                    ("set", "set($0)"),
                    ("remove", "remove($0)"),
                    ("pop", "pop()"),
                    ("insert", "insert($0)"),
                    ("reverse", "reverse()"),
                    ("truncate", "truncate($0)"),
                    ("swap", "swap($0)"),
                    ("clear", "clear()"),
                ] {
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
                items.push(CompletionItem {
                    label: "args".to_string(),
                    kind: CompletionItemKind::Function,
                    detail: Some("witness::args".to_string()),
                    documentation: Some("Named read-only WitnessArgs transaction view".to_string()),
                    insert_text: Some("witness::args(${1:0})".to_string()),
                });
                for name in ["raw", "lock", "input_type", "output_type", "size"] {
                    items.push(CompletionItem {
                        label: name.to_string(),
                        kind: CompletionItemKind::Function,
                        detail: Some(format!("witness::{}", name)),
                        documentation: None,
                        insert_text: Some(format!("witness::{}(${{1:source::group_input(0)}})", name)),
                    });
                }
                for (name, insert) in [
                    ("count", "witness::count()"),
                    ("byte", "witness::byte(${1:source::input(0)}, ${2:0})"),
                    ("u32_le", "witness::u32_le(${1:source::input(0)}, ${2:0})"),
                    ("u64_le", "witness::u64_le(${1:source::input(0)}, ${2:0})"),
                    ("blake2b_span", "witness::blake2b_span(${1:source::input(0)}, ${2:0}, ${3:32})"),
                    ("bytes32", "witness::bytes32(${1:source::input(0)}, ${2:0})"),
                    ("blake2b_select_chunks", "witness::blake2b_select_chunks(${1:source::input(0)}, ${2:0}, ${3:1}, ${4:selection}, ${5:prefix}, ${6:suffix})"),
                ] {
                    items.push(CompletionItem {
                        label: name.to_string(),
                        kind: CompletionItemKind::Function,
                        detail: Some(format!("witness::{}", name)),
                        documentation: Some(
                            "Exact raw witness access; short reads fail closed; count includes extra witnesses".to_string(),
                        ),
                        insert_text: Some(insert.to_string()),
                    });
                }
                return items;
            }
            "script" => {
                for (name, insert) in [
                    ("hash_type_data", "script::hash_type_data()"),
                    ("hash_type_type", "script::hash_type_type()"),
                    ("hash_type_data1", "script::hash_type_data1()"),
                    ("hash_type_data2", "script::hash_type_data2()"),
                    ("args_empty", "script::args_empty()"),
                    ("args", "script::args(${1:b\"owner\"})"),
                    ("new", "script::new(${1:code_hash}, ${2:hash_type}, ${3:args})"),
                    ("require_cell_lock_matches", "script::require_cell_lock_matches(${1:source::input(0)}, ${2:expected_script})"),
                    ("require_cell_type_matches", "script::require_cell_type_matches(${1:source::output(0)}, ${2:expected_script})"),
                ] {
                    items.push(CompletionItem {
                        label: name.to_string(),
                        kind: CompletionItemKind::Function,
                        detail: Some(format!("script::{}", name)),
                        documentation: None,
                        insert_text: Some(insert.to_string()),
                    });
                }
                return items;
            }
            "ckb" => {
                for (name, insert) in [
                    ("input", "ckb::input<${1:CellType}>(${2:0})"),
                    ("output", "ckb::output<${1:CellType}>(${2:0})"),
                    ("group_input", "ckb::group_input<${1:CellType}>(${2:0})"),
                    ("group_output", "ckb::group_output<${1:CellType}>(${2:0})"),
                    ("cell_dep", "ckb::cell_dep(${1:0})"),
                    ("header_dep", "ckb::header_dep(${1:0})"),
                    ("input_out_point", "ckb::input_out_point(${1:input})"),
                    ("lock_script", "ckb::lock_script(${1:cell})"),
                    ("type_script", "ckb::type_script(${1:cell})"),
                    ("header_epoch_number", "ckb::header_epoch_number()"),
                    ("header_epoch_start_block_number", "ckb::header_epoch_start_block_number()"),
                    ("header_epoch_length", "ckb::header_epoch_length()"),
                    ("input_since", "ckb::input_since()"),
                    ("since_epoch_absolute", "ckb::since_epoch_absolute(${1:number}, ${2:index}, ${3:length})"),
                    ("since_epoch_relative", "ckb::since_epoch_relative(${1:number}, ${2:index}, ${3:length})"),
                    ("since_absolute_epoch", "ckb::since_absolute_epoch(${1:number}, ${2:index}, ${3:length})"),
                    ("since_relative_epoch", "ckb::since_relative_epoch(${1:number}, ${2:index}, ${3:length})"),
                    ("since_absolute_block", "ckb::since_absolute_block(${1:block_number})"),
                    ("since_relative_block", "ckb::since_relative_block(${1:block_count})"),
                    ("since_absolute_timestamp", "ckb::since_absolute_timestamp(${1:seconds})"),
                    ("since_relative_timestamp", "ckb::since_relative_timestamp(${1:seconds})"),
                    ("since_decode", "ckb::since_decode(${1:encoded})"),
                    ("since_from_raw_checked", "ckb::since_from_raw_checked(${1:raw})"),
                    ("since_as_absolute_block", "ckb::since_as_absolute_block(${1:decoded})"),
                    ("since_as_relative_block", "ckb::since_as_relative_block(${1:decoded})"),
                    ("since_as_absolute_epoch", "ckb::since_as_absolute_epoch(${1:decoded})"),
                    ("since_as_relative_epoch", "ckb::since_as_relative_epoch(${1:decoded})"),
                    ("since_as_absolute_timestamp", "ckb::since_as_absolute_timestamp(${1:decoded})"),
                    ("since_as_relative_timestamp", "ckb::since_as_relative_timestamp(${1:decoded})"),
                    ("since_is_relative", "ckb::since_is_relative(${1:decoded})"),
                    ("since_is_disabled", "ckb::since_is_disabled(${1:decoded})"),
                    ("since_metric", "ckb::since_metric(${1:decoded})"),
                    ("since_value", "ckb::since_value(${1:decoded})"),
                    ("since_to_raw", "ckb::since_to_raw(${1:since})"),
                    ("epoch_number_to_u64", "ckb::epoch_number_to_u64(${1:epoch})"),
                    ("block_number_to_u64", "ckb::block_number_to_u64(${1:block})"),
                    ("epoch_length_to_u64", "ckb::epoch_length_to_u64(${1:length})"),
                    ("current_role", "ckb::current_role()"),
                    ("current_script_hash", "ckb::current_script_hash()"),
                    ("script_hash", "ckb::script_hash(${1:hash})"),
                    ("cell_capacity", "ckb::cell_capacity(${1:source::group_input(0)})"),
                    ("cell_occupied_capacity", "ckb::cell_occupied_capacity(${1:source::group_input(0)})"),
                    ("cell_unoccupied_capacity", "ckb::cell_unoccupied_capacity(${1:source::group_input(0)})"),
                    ("cell_output_index", "ckb::cell_output_index(${1:source::group_output(0)})"),
                    ("input_out_point_index", "ckb::input_out_point_index(${1:source::group_input(0)})"),
                    ("input_out_point_tx_hash_low", "ckb::input_out_point_tx_hash_low(${1:source::group_input(0)})"),
                    ("cell_lock_hash_low", "ckb::cell_lock_hash_low(${1:source::group_input(0)})"),
                    ("cell_type_hash_low", "ckb::cell_type_hash_low(${1:source::group_input(0)})"),
                    ("cell_lock_hash", "ckb::cell_lock_hash(${1:source::group_input(0)})"),
                    ("cell_data_blake2b_span", "ckb::cell_data_blake2b_span(${1:source::input(0)}, ${2:0}, ${3:32})"),
                    ("raw_transaction_hash_without_cell_deps", "ckb::raw_transaction_hash_without_cell_deps()"),
                    ("transaction_u32_le", "ckb::transaction_u32_le(${1:0})"),
                    ("transaction_blake2b_gather", "ckb::transaction_blake2b_gather(${1:offsets}, ${2:lengths}, ${3:prefix}, ${4:suffix})"),
                    ("cell_data_hash_field", "ckb::cell_data_hash_field(${1:source::cell_dep(0)})"),
                    ("cell_type_hash", "ckb::cell_type_hash(${1:source::group_input(0)})"),
                    ("cell_lock_code_hash", "ckb::cell_lock_code_hash(${1:source::group_input(0)})"),
                    ("cell_type_code_hash", "ckb::cell_type_code_hash(${1:source::group_input(0)})"),
                    ("cell_lock_hash_type", "ckb::cell_lock_hash_type(${1:source::group_input(0)})"),
                    ("cell_type_hash_type", "ckb::cell_type_hash_type(${1:source::group_input(0)})"),
                    ("cell_lock_args_empty", "ckb::cell_lock_args_empty(${1:source::group_input(0)})"),
                    ("cell_type_args_empty", "ckb::cell_type_args_empty(${1:source::group_input(0)})"),
                    ("cell_lock_args_hash", "ckb::cell_lock_args_hash(${1:source::group_input(0)})"),
                    ("cell_type_args_hash", "ckb::cell_type_args_hash(${1:source::group_input(0)})"),
                    ("require_cell_lock_hash", "ckb::require_cell_lock_hash(${1:source::group_input(0)}, ${2:expected_lock_hash})"),
                    ("require_cell_type_hash", "ckb::require_cell_type_hash(${1:source::group_input(0)}, ${2:expected_type_hash})"),
                    ("require_cell_data_hash", "ckb::require_cell_data_hash(${1:source::cell_dep(0)}, ${2:expected_data_hash})"),
                    (
                        "require_bounded_cell_dep_data_hash",
                        "ckb::require_bounded_cell_dep_data_hash(${1:8}, ${2:expected_data_hash})",
                    ),
                    ("hash_sha256", "ckb::hash_sha256(${1:input})"),
                    ("hash_sha256d", "ckb::hash_sha256d(${1:input})"),
                    ("hash_sha256_pair", "ckb::hash_sha256_pair(${1:left}, ${2:right})"),
                    ("hash_sha256d_pair", "ckb::hash_sha256d_pair(${1:left}, ${2:right})"),
                    (
                        "require_sha256d_merkle_root",
                        "ckb::require_sha256d_merkle_root(${1:leaf}, ${2:siblings}, ${3:depth}, ${4:leaf_index}, ${5:expected_root})",
                    ),
                    ("require_current_script_args_empty", "ckb::require_current_script_args_empty()"),
                    ("require_cell_lock_args_empty", "ckb::require_cell_lock_args_empty(${1:source::group_input(0)})"),
                    ("require_cell_type_args_empty", "ckb::require_cell_type_args_empty(${1:source::group_input(0)})"),
                    (
                        "require_cell_lock_args_hash",
                        "ckb::require_cell_lock_args_hash(${1:source::group_input(0)}, ${2:expected_args_hash})",
                    ),
                    (
                        "require_cell_type_args_hash",
                        "ckb::require_cell_type_args_hash(${1:source::group_input(0)}, ${2:expected_args_hash})",
                    ),
                    (
                        "require_cell_lock_args_prefix_hash",
                        "ckb::require_cell_lock_args_prefix_hash(${1:source::group_input(0)}, ${2:expected_args_hash})",
                    ),
                    (
                        "require_cell_type_args_prefix_hash",
                        "ckb::require_cell_type_args_prefix_hash(${1:source::group_input(0)}, ${2:expected_args_hash})",
                    ),
                    (
                        "require_cell_lock_args_suffix_hash",
                        "ckb::require_cell_lock_args_suffix_hash(${1:source::group_input(0)}, ${2:expected_args_hash})",
                    ),
                    (
                        "require_cell_type_args_suffix_hash",
                        "ckb::require_cell_type_args_suffix_hash(${1:source::group_input(0)}, ${2:expected_args_hash})",
                    ),
                    (
                        "require_cell_lock_script_hash_type",
                        "ckb::require_cell_lock_script_hash_type(${1:source::group_input(0)}, ${2:expected_code_hash}, ${3:expected_hash_type})",
                    ),
                    (
                        "require_cell_type_script_hash_type",
                        "ckb::require_cell_type_script_hash_type(${1:source::group_input(0)}, ${2:expected_code_hash}, ${3:expected_hash_type})",
                    ),
                    (
                        "require_input_out_point_tx_hash",
                        "ckb::require_input_out_point_tx_hash(${1:source::group_input(0)}, ${2:expected_tx_hash})",
                    ),
                    (
                        "require_input_out_point",
                        "ckb::require_input_out_point(${1:source::group_input(0)}, ${2:expected_tx_hash}, ${3:expected_index})",
                    ),
                    (
                        "require_metapoint_relative",
                        "ckb::require_metapoint_relative(${1:source::group_input(0)}, ${2:source::group_input(1)}, ${3:relative_distance})",
                    ),
                    (
                        "require_lock_type_metapoint_pairs",
                        "ckb::require_lock_type_metapoint_pairs(${1:source::input(0)}, ${2:relative_distance})",
                    ),
                    (
                        "require_type_lock_metapoint_pairs",
                        "ckb::require_type_lock_metapoint_pairs(${1:source::input(0)}, ${2:relative_distance})",
                    ),
                    (
                        "require_lock_type_metapoint_pairs_from_i32_data",
                        "ckb::require_lock_type_metapoint_pairs_from_i32_data(${1:source::input(0)}, ${2:distance_offset})",
                    ),
                    (
                        "require_type_lock_metapoint_pairs_from_i32_data",
                        "ckb::require_type_lock_metapoint_pairs_from_i32_data(${1:source::input(0)}, ${2:distance_offset})",
                    ),
                    (
                        "require_lock_type_metapoint_pairs_from_i32_data_filtered",
                        "ckb::require_lock_type_metapoint_pairs_from_i32_data_filtered(${1:source::input(0)}, ${2:distance_offset}, ${3:expected_related_type_hash}, ${4:related_data_rule})",
                    ),
                    (
                        "require_type_lock_metapoint_pairs_from_i32_data_filtered",
                        "ckb::require_type_lock_metapoint_pairs_from_i32_data_filtered(${1:source::input(0)}, ${2:distance_offset}, ${3:expected_related_type_hash}, ${4:related_data_rule})",
                    ),
                    (
                        "require_lock_match_master_out_point_pairs_from_data",
                        "ckb::require_lock_match_master_out_point_pairs_from_data(${1:source::input(0)}, ${2:source::output(0)}, ${3:action_offset}, ${4:tx_hash_offset}, ${5:index_offset})",
                    ),
                    ("cell_data_size", "ckb::cell_data_size(${1:source::group_input(0)})"),
                    ("cell_count", "ckb::cell_count(${1:source::input(0)})"),
                    ("cell_has_type", "ckb::cell_has_type(${1:source::input(0)})"),
                    ("cell_data_u8", "ckb::cell_data_u8(${1:source::group_input(0)}, ${2:0})"),
                    ("cell_lock_size", "ckb::cell_lock_size(${1:source::group_input(0)})"),
                    ("cell_type_size", "ckb::cell_type_size(${1:source::group_input(0)})"),
                    ("cell_lock_u8", "ckb::cell_lock_u8(${1:source::group_input(0)}, ${2:0})"),
                    ("cell_type_u8", "ckb::cell_type_u8(${1:source::group_input(0)}, ${2:0})"),
                    ("input_since_at", "ckb::input_since_at(${1:source::input(0)})"),
                    ("exec_cell_dep_u8_args", "ckb::exec_cell_dep_u8_args(${1:0}, ${2:0}, ${3:0}, ${4:0}, ${5:0}, ${6:0})"),
                    ("trusted_exec_cell_dep_u8_args", "ckb::trusted_exec_cell_dep_u8_args(${1:0}, ${2:code_hash}, ${3:0}, ${4:0}, ${5:0}, ${6:0}, ${7:0})"),
                    ("exec_cell_dep_hex4", "ckb::exec_cell_dep_hex4(${1:0}, ${2:bytes}, ${3:0}, ${4:0}, ${5:0}, ${6:0})"),
                    ("trusted_exec_cell_dep_hex4", "ckb::trusted_exec_cell_dep_hex4(${1:0}, ${2:code_hash}, ${3:bytes}, ${4:0}, ${5:0}, ${6:0}, ${7:0})"),
                    ("spawn_wait_cell_dep_hex4", "ckb::spawn_wait_cell_dep_hex4(${1:0}, ${2:bytes}, ${3:0}, ${4:0}, ${5:0}, ${6:0})"),
                    ("trusted_spawn_wait_cell_dep_hex4", "ckb::trusted_spawn_wait_cell_dep_hex4(${1:0}, ${2:code_hash}, ${3:bytes}, ${4:0}, ${5:0}, ${6:0}, ${7:0})"),
                    ("cell_data_u32_le", "ckb::cell_data_u32_le(${1:source::group_input(0)}, ${2:0})"),
                    ("cell_data_u64_le", "ckb::cell_data_u64_le(${1:source::group_input(0)}, ${2:0})"),
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
            "verifier::btc::bip340" => {
                for (name, insert) in [
                    (
                        "require_signature",
                        "verifier::btc::bip340::require_signature(${1:message_hash}, ${2:pubkey}, ${3:signature})",
                    ),
                    (
                        "require_signature_from_cell_dep",
                        "verifier::btc::bip340::require_signature_from_cell_dep(${1:dep_index}, ${2:message_hash}, ${3:pubkey}, ${4:signature})",
                    ),
                ] {
                    items.push(CompletionItem {
                        label: name.to_string(),
                        kind: CompletionItemKind::Function,
                        detail: Some(format!("verifier::btc::bip340::{}", name)),
                        documentation: None,
                        insert_text: Some(insert.to_string()),
                    });
                }
                return items;
            }
            "dao" => {
                for (name, insert) in [
                    ("accumulated_rate", "dao::accumulated_rate(${1:source::header_dep(0)})"),
                    ("input_accumulated_rate", "dao::input_accumulated_rate(${1:source::group_input(0)})"),
                    ("has_dao_type", "dao::has_dao_type(${1:source::group_input(0)})"),
                    ("is_deposit_data", "dao::is_deposit_data(${1:source::group_input(0)})"),
                    ("is_withdrawal_request_data", "dao::is_withdrawal_request_data(${1:source::group_input(0)})"),
                    (
                        "require_header_dep_for_input",
                        "dao::require_header_dep_for_input(${1:source::group_input(0)}, ${2:source::header_dep(0)})",
                    ),
                    (
                        "require_input_since_at_least",
                        "dao::require_input_since_at_least(${1:source::group_input(0)}, ${2:required_since})",
                    ),
                    (
                        "require_input_relative_epoch_since_at_least",
                        "dao::require_input_relative_epoch_since_at_least(${1:source::group_input(0)}, ${2:number}, ${3:index}, ${4:length})",
                    ),
                ] {
                    items.push(CompletionItem {
                        label: name.to_string(),
                        kind: CompletionItemKind::Function,
                        detail: Some(format!("dao::{}", name)),
                        documentation: None,
                        insert_text: Some(insert.to_string()),
                    });
                }
                return items;
            }
            "c256" => {
                for (name, insert) in [
                    (
                        "require_product_lte",
                        "c256::require_product_lte(${1:left_amount}, ${2:left_multiplier}, ${3:right_amount}, ${4:right_multiplier})",
                    ),
                    (
                        "require_product_eq",
                        "c256::require_product_eq(${1:left_amount}, ${2:left_multiplier}, ${3:right_amount}, ${4:right_multiplier})",
                    ),
                    (
                        "require_sum2_products_lte",
                        "c256::require_sum2_products_lte(${1:left_amount_a}, ${2:left_multiplier_a}, ${3:left_amount_b}, ${4:left_multiplier_b}, ${5:right_amount_a}, ${6:right_multiplier_a}, ${7:right_amount_b}, ${8:right_multiplier_b})",
                    ),
                    (
                        "require_sum2_products_eq",
                        "c256::require_sum2_products_eq(${1:left_amount_a}, ${2:left_multiplier_a}, ${3:left_amount_b}, ${4:left_multiplier_b}, ${5:right_amount_a}, ${6:right_multiplier_a}, ${7:right_amount_b}, ${8:right_multiplier_b})",
                    ),
                ] {
                    items.push(CompletionItem {
                        label: name.to_string(),
                        kind: CompletionItemKind::Function,
                        detail: Some(format!("c256::{}", name)),
                        documentation: None,
                        insert_text: Some(insert.to_string()),
                    });
                }
                return items;
            }
            "xudt" => {
                for (name, insert) in [
                    ("amount_low", "xudt::amount_low(${1:source::group_input(0)})"),
                    ("amount_high", "xudt::amount_high(${1:source::group_input(0)})"),
                    ("owner_mode_input_type_hash", "xudt::owner_mode_input_type_hash(${1:source::group_input(0)})"),
                    (
                        "require_owner_mode_input_type",
                        "xudt::require_owner_mode_input_type(${1:source::group_input(0)}, ${2:expected_type_hash})",
                    ),
                    (
                        "require_owner_mode_type_args",
                        "xudt::require_owner_mode_type_args(${1:source::group_input(0)}, ${2:owner_hash}, ${3:2147483648})",
                    ),
                    (
                        "require_owner_mode_type_args_current_script",
                        "xudt::require_owner_mode_type_args_current_script(${1:source::group_input(0)}, ${2:2147483648})",
                    ),
                    ("require_group_amount_conserved", "xudt::require_group_amount_conserved()"),
                    ("require_group_amount_minted", "xudt::require_group_amount_minted(${1:delta})"),
                    ("require_group_amount_burned", "xudt::require_group_amount_burned(${1:delta})"),
                ] {
                    items.push(CompletionItem {
                        label: name.to_string(),
                        kind: CompletionItemKind::Function,
                        detail: Some(format!("xudt::{}", name)),
                        documentation: None,
                        insert_text: Some(insert.to_string()),
                    });
                }
                return items;
            }
            "Address" => {
                items.push(CompletionItem {
                    label: "zero".to_string(),
                    kind: CompletionItemKind::Function,
                    detail: Some("Address::zero".to_string()),
                    documentation: None,
                    insert_text: Some("Address::zero()".to_string()),
                });
                return items;
            }
            "Hash" => {
                for (name, insert) in [("zero", "Hash::zero()"), ("from_bytes", "Hash::from_bytes(${1:b\"\\\\x00\\\\x00...\"})")] {
                    items.push(CompletionItem {
                        label: name.to_string(),
                        kind: CompletionItemKind::Function,
                        detail: Some(format!("Hash::{}", name)),
                        documentation: None,
                        insert_text: Some(insert.to_string()),
                    });
                }
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
                if let Stmt::Let(let_stmt) = stmt
                    && let BindingPattern::Name(name) = &let_stmt.pattern
                {
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

        items
    }

    fn keyword_completions(&self, uri: &str) -> Vec<CompletionItem> {
        let edition = self.document_edition(uri);
        let mut keywords = vec![
            ("module", "module ${1:name}"),
            ("use", "use ${1:path}"),
            ("resource", "resource ${1:Name} {\n    $0\n}"),
            ("shared", "shared ${1:Name} {\n    $0\n}"),
            ("receipt", "receipt ${1:Name} {\n    $0\n}"),
            ("struct", "struct ${1:Name} {\n    $0\n}"),
            ("action", "action ${1:name}(input ${2:cell}: ${3:CellType}) -> ${4:output}: ${3:CellType} {\n    verification\n        $0\n}"),
            ("flow", "flow ${1:Name} for ${2:Type}.${3:state} {\n    ${4:Created} -> ${5:Live};\n}"),
            ("input", "input ${1:name}: ${2:CellType}"),
            ("transition", "transition ${1:input} -> ${2:output}"),
            (
                "lock",
                "lock ${1:name}(protected ${2:cell}: ${3:CellType}) -> bool {\n    verification\n        require ${4:authorization_condition}\n        $0\n}",
            ),
            ("let", "let ${1:name} = $0"),
            ("if", "if ${1:condition} {\n    $0\n}"),
            ("for", "for ${1:item} in ${2:iterable} {\n    $0\n}"),
            ("while", "while ${1:condition} {\n    $0\n}"),
            ("label", "label ${1:name}: ${2:while} ${3:condition} {\n    $0\n}"),
            ("break", "break${1: label}"),
            ("continue", "continue${1: label}"),
            ("borrow", "borrow ${1:root} as ${2:view} {\n    $0\n}"),
            ("return", "return $0"),
            ("create", "create ${1:output} = ${2:Type} { $0 }"),
            ("consume", "consume ${1:input}"),
            ("destroy", "destroy ${1:expr}"),
            ("require", "require ${1:condition}"),
            (
                "forall",
                "forall ${1:output} ${2:item} in ${3:group_outputs<CellType>} {\n    require ${2:item}.${4:field} ${5:>} ${6:0}\n}",
            ),
            ("count", "count(${1:outputs<CellType>} where ${2:field} == ${3:value}) == ${4:1}"),
            (
                "consume_each",
                "consume_each ${1:item} in ${2:inputs} {\n    require ${1:item}.${3:field} ${4:>} ${5:0}\n}",
            ),
            (
                "create_each",
                "create_each ${1:plan} in ${2:plans} {\n    require ${1:plan}.${3:field} ${4:>} ${5:0}\n    create ${6:CellType} { $0 }\n}",
            ),
            ("verification", "verification\n    $0"),
            ("validity", "validity\n    require ${1:field} ${2:>} ${3:0}"),
            ("require_block", "require {\n    ${1:condition}\n}"),
            ("preserve", "preserve ${1:output} from ${2:input} {\n    ${3:field}\n}"),
            ("std::cell::same_lock", "std::cell::same_lock(${1:output}, ${2:input})"),
            ("std::cell::preserve_lock", "std::cell::preserve_lock(${1:output}, ${2:input})"),
            ("std::cell::preserve_type", "std::cell::preserve_type(${1:output}, ${2:input})"),
            ("std::cell::preserve_capacity", "std::cell::preserve_capacity(${1:output}, ${2:input})"),
            ("std::lifecycle::transfer", "std::lifecycle::transfer(${1:input}, ${2:output}, ${3:to}) {\n    ${4:field}\n}"),
            ("std::receipt::claim", "std::receipt::claim(${1:receipt}, ${2:output}, ${3:lock}) {\n    ${4:field}\n}"),
            ("std::lifecycle::settle", "std::lifecycle::settle(${1:input}, ${2:output}, ${3:lock}) {\n    ${4:field}\n}"),
            ("protected", "protected ${1:cell}: ${2:CellType}"),
            ("witness", "witness ${1:arg}: ${2:Address}"),
            ("lock_args", "lock_args ${1:args}: ${2:OwnerArgs}"),
        ];
        if edition == crate::NEXT_EDITION {
            keywords.extend([
                ("type_script", "type_script ${1:Name} on type_group<${2:CellType}> {\n    $0\n}"),
                ("lock_script", "lock_script ${1:Name} on lock_group {\n    $0\n}"),
            ]);
        }
        if edition == crate::NEXT_EDITION && self.documents.get(uri).is_some_and(|source| crate::frontend::uses_native_preview(source))
        {
            keywords.retain(|(label, _)| !matches!(*label, "consume" | "consume_each"));
            keywords.extend([
                ("lock_group", "lock_group"),
                ("current_script", "current_script.args"),
                ("entry", "entry ${1:name}($0)"),
                ("verify", "verify {\n    enforce ${1:condition}\n}"),
                ("enforce", "enforce ${1:condition}"),
                ("effects", "effects {\n    $0\n}"),
                ("replace", "replace ${1:input} -> ${2:output} {\n    $0\n}"),
                ("pool", "pool ${1:name} {\n    inputs { ${2:input} }\n    outputs { ${3:output} }\n    data {\n        ${4:amount} = conserve\n    }\n    identity = pooled\n    type_script = same\n    lock_script { ${3:output} = exact_hash(${5:recipient}) }\n    capacity = builder_computed\n    cardinality = declared\n}"),
                ("retire", "retire ${1:input} {\n    absence = ${2:field(identity)}\n    data = discarded\n    lock_script = none\n    type_script = absent\n    capacity = released\n    cardinality = one\n}"),
                ("fresh", "fresh ${1:output} {\n    data {\n        ${2:field} = ${3:value}\n    }\n    identity = ${4:none}\n    type_script = declared\n    lock_script = exact_hash(${5:recipient})\n    capacity = builder_computed\n    cardinality = one\n}"),
                ("audit", "audit ${1:name} {\n    expected_evidence = external_policy(${2:subject})\n}"),
                ("exact_hash", "exact_hash(${1:script_hash})"),
            ]);
        }

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
            "u8",
            "u16",
            "u32",
            "u64",
            "u128",
            "i8",
            "i16",
            "i32",
            "i64",
            "i128",
            "bool",
            "String",
            "Address",
            "Hash",
            "ScriptHash",
            "EpochNumber",
            "BlockNumber",
            "EpochLength",
            "EncodedSince",
            "DecodedSince",
            "AbsoluteBlockSince",
            "AbsoluteEpochSince",
            "AbsoluteTimestampSince",
            "RelativeBlockSince",
            "RelativeEpochSince",
            "RelativeTimestampSince",
            "Bytes",
            "Option",
            "Vec",
            "BoundedCellSet",
            "BoundedList",
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
                    Some(Location { uri: module_uri.clone(), range: item_name_range(&module.source, item, name) })
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
                if let Stmt::Let(let_stmt) = stmt
                    && let BindingPattern::Name(name) = &let_stmt.pattern
                    && name == symbol
                {
                    return Some(Location { uri: uri.to_string(), range: span_to_range(content, let_stmt.span) });
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
            let edition = self.document_edition(uri);
            let metadata = crate::compile_metadata(source, edition, None).ok();
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
            let metadata = crate::compile_metadata(&module.source, module.edition, None).ok();
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
                    let note = if param.is_mut {
                        "\n\nLeading `mut` only applies to local-style mutable value bindings; Cell state updates should be modeled with `action(before: T) -> after: T` plus `transition` and `require` constraints."
                    } else if param.source == ParamSource::Input {
                        "\n\n`input` marks a consumed transaction input Cell explicitly. Omitting it is equivalent for Cell-backed action parameters."
                    } else if param.source == ParamSource::Output {
                        "\n\n`output` marks a proposed transaction output Cell. Use `transition input.state: Live -> output.state: Filled` for state transitions and `require` for field continuity."
                    } else if param.source == ParamSource::LockArgs {
                        "\n\n`lock_args` is decoded from the executing lock Script.args bytes."
                    } else {
                        ""
                    };
                    return Some(Hover {
                        contents: format!("```cellscript\n{}: {}\n```\n\nParameter{}", param.name, type_to_string(&param.ty), note),
                        range: Some(span_to_range(content, param.span)),
                    });
                }
            }
            if let Item::Action(action) = item {
                for output in &action.outputs {
                    if output.name == symbol {
                        return Some(Hover {
                            contents: format!(
                                "```cellscript\n{}: {}\n```\n\nAction output binding: proposed transaction output Cell.",
                                output.name,
                                type_to_string(&output.ty)
                            ),
                            range: Some(span_to_range(content, output.span)),
                        });
                    }
                }
            }

            // Check local let bindings.
            for stmt in body {
                if let Stmt::Let(let_stmt) = stmt
                    && let BindingPattern::Name(name) = &let_stmt.pattern
                    && name == symbol
                {
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
        None
    }

    fn item_hover(&self, source: &str, item: &Item, metadata: Option<&crate::CompileMetadata>) -> Option<Hover> {
        let range = span_to_range(source, item_span(item));
        match item {
            Item::Resource(r) => Some(Hover {
                contents: format!(
                    "```cellscript\nresource {}\n```{}{}",
                    r.name,
                    capability_hover(&r.capabilities),
                    type_validity_hover(&r.name, metadata)
                ),
                range: Some(range),
            }),
            Item::Shared(s) => Some(Hover {
                contents: format!(
                    "```cellscript\nshared {}\n```{}{}",
                    s.name,
                    capability_hover(&s.capabilities),
                    type_validity_hover(&s.name, metadata)
                ),
                range: Some(range),
            }),
            Item::Receipt(r) => Some(Hover {
                contents: format!(
                    "```cellscript\nreceipt {}\n```{}{}{}",
                    r.name,
                    capability_hover(&r.capabilities),
                    receipt_flow_hover(r, metadata),
                    type_validity_hover(&r.name, metadata)
                ),
                range: Some(range),
            }),
            Item::Struct(s) => Some(Hover {
                contents: format!(
                    "```cellscript\nstruct {}{}{}\n```{}",
                    s.name,
                    generic_params_hover(&s.type_params),
                    value_abilities_hover(&s.abilities),
                    type_validity_hover(&s.name, metadata)
                ),
                range: Some(range),
            }),
            Item::Enum(e) => Some(Hover { contents: payload_enum_hover(e, metadata), range: Some(range) }),
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
                contents: format!(
                    "```cellscript\nfn {}{}\n```\n\n{}{}",
                    f.name,
                    generic_params_hover(&f.type_params),
                    f.doc_comment.as_deref().unwrap_or("No documentation"),
                    function_metadata_hover(&f.name, f, metadata)
                ),
                range: Some(range),
            }),
            Item::Lock(l) => Some(Hover { contents: format!("```cellscript\nlock {}\n```", l.name), range: Some(range) }),
            Item::Invariant(i) => Some(Hover {
                contents: format!(
                    "```cellscript\ninvariant {}\n```\n\nReads: {}\n\nBounded quantifiers: {}{}",
                    i.name,
                    i.reads.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
                    i.quantifiers.len(),
                    if i.quantifiers.is_empty() {
                        ""
                    } else {
                        " (runtime-helper-required; scan cost and vacuous/count policy are emitted in ProofPlan)"
                    }
                ),
                range: Some(range),
            }),
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
                Item::Shared(s) if !s.fields.is_empty() => {
                    let range = span_to_range(content, s.span);
                    ranges.push(FoldingRange {
                        start_line: range.start.line,
                        start_character: Some(range.start.character),
                        end_line: range.end.line,
                        end_character: Some(range.end.character),
                        kind: Some(FoldingRangeKind::Region),
                    });
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
        if let Some(ast) = self.ast_cache.get(uri)
            && let Some(info) = self.find_signature_in_items(&ast.items, name)
        {
            return Some(info);
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
                        .map(|p| ParameterInformation { label: ParameterLabel::Simple(param_to_string(p)), documentation: None })
                        .collect();
                    let return_type = if !a.outputs.is_empty() {
                        action_outputs_to_string(&a.outputs)
                    } else {
                        a.return_type.as_ref().map(type_to_string).unwrap_or_default()
                    };
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
                        .map(|p| ParameterInformation { label: ParameterLabel::Simple(param_to_string(p)), documentation: None })
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
                        .map(|p| ParameterInformation { label: ParameterLabel::Simple(param_to_string(p)), documentation: None })
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
        if let (Some(ast), Some(source)) = (self.ast_cache.get(uri), self.documents.get(uri))
            && let Some(location) = ast.items.iter().find_map(|item| {
                let name = item_name(item)?;
                if name == symbol {
                    Some(Location { uri: uri.to_string(), range: item_name_range(source, item, name) })
                } else {
                    None
                }
            })
        {
            return Some(location);
        }

        for module in self.workspace_modules(uri) {
            if let Some(location) = module.ast.items.iter().find_map(|item| {
                let name = item_name(item)?;
                if name == symbol {
                    Some(Location { uri: utf8_path_to_file_uri(&module.path), range: item_name_range(&module.source, item, name) })
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
                let edition = self.document_edition(uri);
                modules.push(crate::LoadedModule { path, source: content.clone(), ast: ast.clone(), edition });
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
    /// At a namespace access position (after `::`), with the type name before the scope separator.
    Namespace { type_name: String },
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
    let code = error.code.clone();
    let code_description = code.as_deref().and_then(|code| {
        crate::error::compiler_error_info_by_code(code).map(|_| {
            format!(
                "https://github.com/CellScript-Labs/CellScript/blob/nightly-0.22/docs/CELLSCRIPT_COMPILER_ERROR_CODES.md#{}",
                code.to_ascii_lowercase()
            )
        })
    });
    Diagnostic {
        range: span_to_range(source, error.span),
        severity: match error.severity {
            CompilerDiagnosticSeverity::Error => DiagnosticSeverity::Error,
            CompilerDiagnosticSeverity::Warning => DiagnosticSeverity::Warning,
        },
        code,
        code_description,
        message: error.message.clone(),
        source: "cellscript".to_string(),
    }
}

fn diagnostic_belongs_to_uri(error: &CompileError, uri_path: Option<&Utf8PathBuf>) -> bool {
    match (&error.file, uri_path) {
        (Some(file), Some(path)) => same_workspace_path(file, path),
        (Some(_), None) => false,
        (None, _) => true,
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
            code: None,
            code_description: None,
            message: format!(
                "action '{}' {}; fail-closed runtime features: {}; CKB runtime features: {}; CKB accesses: {}",
                action.name,
                if action.elf_compatible { "emits fail-closed runtime traps" } else { "is not currently ELF-compatible" },
                diagnostic_fail_closed_features(&action.fail_closed_runtime_features, &action.verifier_obligations),
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
            code: None,
            code_description: None,
            message: format!(
                "lock '{}' {}; fail-closed runtime features: {}; CKB runtime features: {}; CKB accesses: {}",
                lock.name,
                if lock.elf_compatible { "emits fail-closed runtime traps" } else { "is not currently ELF-compatible" },
                diagnostic_fail_closed_features(&lock.fail_closed_runtime_features, &lock.verifier_obligations),
                diagnostic_list(&lock.ckb_runtime_features),
                diagnostic_access_list(&lock.ckb_runtime_accesses)
            ),
            source: "cellscript-lowering".to_string(),
        });
    }

    for function in &metadata.functions {
        if function.elf_compatible && function.fail_closed_runtime_features.is_empty() {
            continue;
        }
        let span = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(def) if def.name == function.name => Some(def.span),
                _ => None,
            })
            .unwrap_or_default();
        diagnostics.push(Diagnostic {
            range: span_to_range(source, span),
            severity: DiagnosticSeverity::Warning,
            code: None,
            code_description: None,
            message: format!(
                "fn '{}' {}; fail-closed runtime features: {}; CKB runtime features: {}; CKB accesses: {}",
                function.name,
                if function.elf_compatible { "emits fail-closed runtime traps" } else { "is not currently ELF-compatible" },
                diagnostic_fail_closed_features(&function.fail_closed_runtime_features, &function.verifier_obligations),
                diagnostic_list(&function.ckb_runtime_features),
                diagnostic_access_list(&function.ckb_runtime_accesses)
            ),
            source: "cellscript-lowering".to_string(),
        });
    }

    diagnostics
}

fn diagnostic_fail_closed_features(features: &[String], obligations: &[crate::VerifierObligationMetadata]) -> String {
    let descriptions = features
        .iter()
        .map(|feature| {
            obligations
                .iter()
                .find(|obligation| obligation.feature == *feature && obligation.status == "fail-closed")
                .map(|obligation| format!("{} ({})", feature, obligation.detail))
                .unwrap_or_else(|| feature.clone())
        })
        .collect::<Vec<_>>();
    diagnostic_list(&descriptions)
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
        Item::Flow(machine) => machine.name.as_deref(),
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
        Item::Flow(machine) => machine.span,
        Item::Const(c) => c.span,
        Item::Enum(e) => e.span,
        Item::Invariant(i) => i.span,
        Item::Action(a) => a.span,
        Item::Function(f) => f.span,
        Item::Lock(l) => l.span,
        Item::Use(u) => u.span,
    }
}

fn item_name_range(source: &str, item: &Item, name: &str) -> Range {
    let span = item_span(item);
    let start = span.start.min(source.len());
    let end = span.end.min(source.len()).max(start);
    let slice = &source[start..end];
    if let Some((relative_start, relative_end)) = word_occurrences(slice, name).into_iter().next() {
        return Range {
            start: offset_to_position(source, start + relative_start),
            end: offset_to_position(source, start + relative_end),
        };
    }
    span_to_range(source, span)
}

fn stmt_span(stmt: &Stmt) -> Span {
    match stmt {
        Stmt::Let(s) => s.span,
        Stmt::Return(s) => s.span,
        Stmt::If(s) => s.span,
        Stmt::For(s) => s.span,
        Stmt::While(s) => s.span,
        Stmt::Break(s) | Stmt::Continue(s) => s.span,
        Stmt::Borrow(s) => s.span,
        Stmt::Expr(_) => Span::default(),
    }
}

fn type_to_string(ty: &Type) -> String {
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
        Type::Array(inner, size) => format!("[{}; {}]", type_to_string(inner), size),
        Type::Tuple(types) => format!("({})", types.iter().map(type_to_string).collect::<Vec<_>>().join(", ")),
        Type::Named(name) => name.clone(),
        Type::Ref(inner) => format!("&{}", type_to_string(inner)),
        Type::MutRef(inner) => format!("&mut {}", type_to_string(inner)),
    }
}

fn param_to_string(param: &Param) -> String {
    let mut rendered = String::new();
    if param.is_mut {
        rendered.push_str("mut ");
    }
    if param.is_ref {
        rendered.push('&');
    }
    match param.source {
        ParamSource::Input => rendered.push_str("input "),
        ParamSource::Output => rendered.push_str("output "),
        ParamSource::Protected => rendered.push_str("protected "),
        ParamSource::Witness => rendered.push_str("witness "),
        ParamSource::LockArgs => rendered.push_str("lock_args "),
        ParamSource::Default if param.is_read_ref => rendered.push_str("read "),
        ParamSource::Default => {}
    }
    rendered.push_str(&param.name);
    rendered.push_str(": ");
    let ty = match (&param.source, &param.ty) {
        (ParamSource::Protected, Type::Ref(inner)) => inner.as_ref(),
        (ParamSource::Default, Type::Ref(inner)) if param.is_read_ref => inner.as_ref(),
        _ => &param.ty,
    };
    rendered.push_str(&type_to_string(ty));
    rendered
}

fn action_outputs_to_string(outputs: &[ActionOutput]) -> String {
    if outputs.len() == 1 {
        format!("{}: {}", outputs[0].name, type_to_string(&outputs[0].ty))
    } else {
        format!(
            "({})",
            outputs.iter().map(|output| format!("{}: {}", output.name, type_to_string(&output.ty))).collect::<Vec<_>>().join(", ")
        )
    }
}

fn position_in_range(pos: Position, range: Range) -> bool {
    position_le(range.start, pos) && position_le(pos, range.end)
}

fn capability_hover(capabilities: &[Capability]) -> String {
    let rendered = if capabilities.is_empty() {
        "none".to_string()
    } else {
        Capability::ALL
            .into_iter()
            .filter(|capability| capabilities.contains(capability))
            .map(|capability| capability.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "\n\nCapabilities (set v{}, entailment v{}): `{}`\n\nDerived rules: `destroy <= consume + burn`; `replace_unique <= replace + identity-preservation`. Authority is per resource and never inherited.",
        Capability::REGISTRY_VERSION,
        CapabilityOperation::ENTAILMENT_VERSION,
        rendered
    )
}

fn receipt_flow_hover(receipt: &ReceiptDef, metadata: Option<&crate::CompileMetadata>) -> String {
    if let Some(type_metadata) =
        metadata.and_then(|metadata| metadata.types.iter().find(|type_metadata| type_metadata.name == receipt.name))
    {
        if type_metadata.flow_states.is_empty() {
            return String::new();
        }

        let transitions = if type_metadata.flow_transitions.is_empty() {
            "none".to_string()
        } else {
            type_metadata
                .flow_transitions
                .iter()
                .map(|transition| {
                    format!("{}[{}] -> {}[{}]", transition.from, transition.from_index, transition.to, transition.to_index)
                })
                .collect::<Vec<_>>()
                .join(", ")
        };

        return format!(
            "\n\n**Flow metadata**\n\nState model: `{}`\n\nInitial: `{}`\n\nTerminals: `{}`\n\nTerminal discharge: `{}`\n\nTerminal evidence: `{}`\n\nStates: `{}`\n\nTransitions: `{}`",
            type_metadata.flow_state_model.as_deref().unwrap_or("unspecified"),
            type_metadata.flow_initial_state.as_deref().unwrap_or("legacy-undeclared"),
            if type_metadata.flow_terminal_states.is_empty() {
                "legacy-undeclared".to_string()
            } else {
                type_metadata.flow_terminal_states.join(", ")
            },
            type_metadata.flow_terminal_discharge.as_deref().unwrap_or("legacy-undeclared"),
            type_metadata.flow_terminal_evidence_tier.map_or("legacy-undeclared", crate::EvidenceTier::as_str),
            type_metadata.flow_states.join(" -> "),
            transitions
        );
    }

    String::new()
}

fn payload_enum_hover(enum_def: &EnumDef, metadata: Option<&crate::CompileMetadata>) -> String {
    let variants = enum_def
        .variants
        .iter()
        .map(|variant| {
            if variant.fields.is_empty() {
                variant.name.clone()
            } else {
                format!("{}({})", variant.name, variant.fields.iter().map(type_to_string).collect::<Vec<_>>().join(", "))
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let mut hover = format!(
        "```cellscript\nenum {}{}{} {{ {} }}\n```",
        enum_def.name,
        generic_params_hover(&enum_def.type_params),
        value_abilities_hover(&enum_def.abilities),
        variants
    );
    if let Some(layout) = metadata.and_then(|metadata| metadata.enum_layouts.iter().find(|layout| layout.name == enum_def.name)) {
        hover.push_str(&format!(
            "\n\n**Layout metadata**\n\nLayout: `{}`\n\nABI: `{}`\n\nStorage: `{}`\n\nTag: `{}` byte\n\nEncoded size: `{}` bytes\n\nLinear payload: `{}`",
            layout.layout,
            layout.abi,
            layout.storage,
            layout.tag_width_bytes,
            layout.encoded_size_bytes,
            layout.contains_linear_payload
        ));
    } else if enum_def.variants.iter().any(|variant| !variant.fields.is_empty()) {
        hover.push_str("\n\nFixed-width payload enum; generic templates use deterministic pre-IR monomorphization.");
    }
    hover
}

fn generic_params_hover(params: &[TypeParam]) -> String {
    if params.is_empty() {
        return String::new();
    }
    format!(
        "<{}>",
        params
            .iter()
            .map(|param| {
                let mut value = if param.phantom { format!("phantom {}", param.name) } else { param.name.clone() };
                if !param.constraints.is_empty() {
                    value.push_str(": ");
                    value.push_str(&param.constraints.iter().map(|ability| ability.as_str()).collect::<Vec<_>>().join(" + "));
                }
                value
            })
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn value_abilities_hover(abilities: &[ValueAbility]) -> String {
    if abilities.is_empty() {
        String::new()
    } else {
        format!(" has {}", abilities.iter().map(|ability| ability.as_str()).collect::<Vec<_>>().join(", "))
    }
}

fn type_validity_hover(name: &str, metadata: Option<&crate::CompileMetadata>) -> String {
    let Some(type_metadata) = metadata.and_then(|metadata| metadata.types.iter().find(|type_metadata| type_metadata.name == name))
    else {
        return String::new();
    };
    if type_metadata.validity_predicates.is_empty() {
        return String::new();
    }

    let predicates = type_metadata
        .validity_predicates
        .iter()
        .map(|predicate| {
            format!(
                "- `{}` — `{}`; create: `{}` ({}/{} paths); update: `{}` ({} paths)",
                predicate.expression,
                predicate.evidence_tier.as_str(),
                predicate.create_path_status,
                predicate.create_paths_checked,
                predicate.create_paths_selected,
                predicate.update_path_status,
                predicate.update_paths_selected
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("\n\n**Validity metadata**\n\n{predicates}")
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

fn function_metadata_hover(name: &str, function: &FnDef, metadata: Option<&crate::CompileMetadata>) -> String {
    if let Some(metadata) = metadata
        && let Some(function_metadata) = metadata.functions.iter().find(|candidate| candidate.name == name)
    {
        let declared = function_metadata.declared_effect_class.as_deref().unwrap_or("inferred");
        return format!(
            "\n\n**Effect metadata**\n\nDeclared: `{}`\n\nInferred: `{}`\n\nEffective: `{}`\n\nEvidence: `{}`",
            declared,
            function_metadata.inferred_effect_class,
            function_metadata.effect_class,
            function_metadata.effect_evidence_tier.as_str()
        );
    }

    if function.effect_declared {
        format!("\n\n**Declared effect**: `{}`", function.effect.as_str())
    } else {
        "\n\n**Effect**: inferred from the transitive call graph".to_string()
    }
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
        if let TokenKind::Identifier(name) = token.kind
            && name == symbol
        {
            matches.push((token.span.start, token.span.end));
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
        let content = "module test;\n\naction answer() -> u64 {\n    verification\n        42\n}\n".to_string();

        server.open_document(uri.clone(), content);
        assert!(server.get_diagnostics(&uri).is_empty());

        let completions = server.completion(&uri, Position { line: 0, character: 0 });
        assert!(!completions.is_empty());

        let keywords: Vec<_> = completions.iter().filter(|c| c.kind == CompletionItemKind::Keyword).collect();
        assert!(!keywords.is_empty());
    }

    #[test]
    fn lsp_rejects_oversized_documents_without_retaining_them() {
        let mut server = LspServer::new();
        let uri = "file:///oversized.cell".to_string();
        let source = " ".repeat(crate::MAX_SOURCE_BYTES + 1);

        server.open_document(uri.clone(), source.clone());
        assert!(!server.documents.contains_key(&uri));
        assert!(server.get_diagnostics(&uri)[0].message.contains("source exceeds"));

        server.open_document(uri.clone(), "module ok".to_string());
        assert!(server.documents.contains_key(&uri));
        server.update_document(uri.clone(), source);
        assert!(!server.documents.contains_key(&uri));
        assert!(server.get_diagnostics(&uri)[0].message.contains("source exceeds"));
    }

    #[test]
    fn test_keyword_completions() {
        let server = LspServer::new();
        let keywords = server.keyword_completions("file:///stable.cell");

        assert!(keywords.iter().any(|k| k.label == "module"));
        assert!(keywords.iter().any(|k| k.label == "resource"));
        assert!(keywords.iter().any(|k| k.label == "action"));
        assert!(keywords.iter().any(|k| k.label == "flow"));
        assert!(keywords.iter().any(|k| k.label == "input"));
        assert!(!keywords.iter().any(|k| k.label == "output"));
        assert!(keywords.iter().any(|k| k.label == "transition"));
        assert!(!keywords.iter().any(|k| k.label == "move"));
        assert!(keywords.iter().any(|k| k.label == "require"));
        assert!(keywords.iter().any(|k| k.label == "validity"));
        assert!(keywords.iter().any(|k| k.label == "forall"));
        assert!(keywords.iter().any(|k| k.label == "count"));
        assert!(keywords.iter().any(|k| k.label == "consume_each"));
        assert!(keywords.iter().any(|k| k.label == "create_each"));
        assert!(keywords.iter().any(|k| k.label == "break"));
        assert!(keywords.iter().any(|k| k.label == "continue"));
        assert!(keywords.iter().any(|k| k.label == "label"));
        assert!(!keywords.iter().any(|k| k.label == "transfer"));
        assert!(keywords.iter().any(|k| k.label == "std::cell::same_lock"));
        assert!(keywords.iter().any(|k| k.label == "std::cell::preserve_capacity"));
        assert!(keywords.iter().any(|k| k.label == "std::lifecycle::transfer"));
        assert!(keywords.iter().any(|k| k.label == "std::receipt::claim"));
        assert!(keywords.iter().any(|k| k.label == "std::lifecycle::settle"));
        assert!(keywords.iter().any(|k| k.label == "protected"));
        assert!(keywords.iter().any(|k| k.label == "witness"));
        assert!(keywords.iter().any(|k| k.label == "lock_args"));
        let types = server.type_completions();
        assert!(types.iter().any(|item| item.label == "BoundedCellSet"));
        assert!(types.iter().any(|item| item.label == "BoundedList"));
        assert!(types.iter().any(|item| item.label == "DecodedSince"));
        assert!(types.iter().any(|item| item.label == "AbsoluteBlockSince"));
        assert!(types.iter().any(|item| item.label == "RelativeTimestampSince"));
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
        assert!(witness.iter().any(|item| item.label == "blake2b_span"));
        assert!(witness.iter().any(|item| item.label == "bytes32"));

        let script = server.member_completions("file:///test.cell", "script");
        assert!(script.iter().any(|item| item.label == "new"));
        assert!(script.iter().any(|item| item.label == "args"));
        assert!(script.iter().any(|item| item.label == "require_cell_lock_matches"));

        let hash = server.member_completions("file:///test.cell", "Hash");
        assert!(hash.iter().any(|item| item.label == "zero"));
        assert!(hash.iter().any(|item| item.label == "from_bytes"));

        let ckb = server.member_completions("file:///test.cell", "ckb");
        assert!(ckb.iter().any(|item| item.label == "input_since"));
        assert!(ckb.iter().any(|item| item.label == "since_epoch_relative"));
        assert!(ckb.iter().any(|item| item.label == "since_absolute_epoch"));
        assert!(ckb.iter().any(|item| item.label == "since_relative_epoch"));
        assert!(ckb.iter().any(|item| item.label == "since_absolute_block"));
        assert!(ckb.iter().any(|item| item.label == "since_relative_block"));
        assert!(ckb.iter().any(|item| item.label == "since_absolute_timestamp"));
        assert!(ckb.iter().any(|item| item.label == "since_relative_timestamp"));
        assert!(ckb.iter().any(|item| item.label == "since_decode"));
        assert!(ckb.iter().any(|item| item.label == "since_from_raw_checked"));
        assert!(ckb.iter().any(|item| item.label == "since_as_absolute_epoch"));
        assert!(ckb.iter().any(|item| item.label == "since_metric"));
        assert!(ckb.iter().any(|item| item.label == "since_to_raw"));
        assert!(ckb.iter().any(|item| item.label == "epoch_number_to_u64"));
        assert!(ckb.iter().any(|item| item.label == "cell_lock_code_hash"));
        assert!(ckb.iter().any(|item| item.label == "cell_type_args_hash"));
        assert!(ckb.iter().any(|item| item.label == "require_cell_lock_args_prefix_hash"));
        assert!(ckb.iter().any(|item| item.label == "require_cell_type_args_suffix_hash"));
        assert!(ckb.iter().any(|item| item.label == "require_cell_lock_args_empty"));
        assert!(ckb.iter().any(|item| item.label == "require_bounded_cell_dep_data_hash"));
        assert!(ckb.iter().any(|item| item.label == "hash_sha256d"));
        assert!(ckb.iter().any(|item| item.label == "require_sha256d_merkle_root"));
        assert!(ckb.iter().any(|item| item.label == "raw_transaction_hash_without_cell_deps"));
        assert!(ckb.iter().any(|item| item.label == "trusted_exec_cell_dep_u8_args"));
        assert!(ckb.iter().any(|item| item.label == "trusted_spawn_wait_cell_dep_hex4"));

        let bip340 = server.member_completions("file:///test.cell", "verifier::btc::bip340");
        assert!(bip340.iter().any(|item| item.label == "require_signature_from_cell_dep"));

        let dao = server.member_completions("file:///test.cell", "dao");
        assert!(dao.iter().any(|item| item.label == "require_input_relative_epoch_since_at_least"));
    }

    #[test]
    fn test_payload_enum_namespace_completions_expose_constructor_shape() {
        let source = "module payload_completion\nenum Limit { None, Some(u64) }\n";
        let tokens = crate::lexer::lex(source).unwrap();
        let module = crate::parser::parse(&tokens).unwrap();
        let server = LspServer::new();
        let completions = server.namespace_symbol_completions(&module, "Limit");
        let some = completions.iter().find(|item| item.label == "Some").expect("Some completion");
        assert_eq!(some.insert_text.as_deref(), Some("Some(value1)"));
        assert!(some.detail.as_deref().is_some_and(|detail| detail.contains("Some(u64)")));
        let none = completions.iter().find(|item| item.label == "None").expect("None completion");
        assert_eq!(none.insert_text.as_deref(), Some("None"));
    }

    #[test]
    fn test_vec_member_completions_match_supported_helpers() {
        let server = LspServer::new();
        let completions = server.member_completions("file:///test.cell", "Vec");
        let labels = completions.iter().map(|item| item.label.as_str()).collect::<std::collections::BTreeSet<_>>();

        for helper in [
            "new",
            "with_capacity",
            "capacity",
            "push",
            "extend_from_slice",
            "len",
            "is_empty",
            "first",
            "last",
            "contains",
            "set",
            "remove",
            "pop",
            "insert",
            "reverse",
            "truncate",
            "swap",
            "clear",
        ] {
            assert!(labels.contains(helper), "missing Vec completion for {helper}");
        }
        assert!(!labels.contains("get"), "Vec completion should not advertise unsupported get()");
    }

    #[test]
    fn test_flow_u8_namespace_completions() {
        let mut server = LspServer::new();
        let uri = "file:///flow_completion.cell".to_string();
        let source = r#"
module flow_completion

receipt Ticket has store {
    state: u8,
    id: u64,
}

receipt OtherTicket has store {
    state: u8,
    id: u64,
}

flow Ticket.state {
    Created -> Active;
    Active -> Closed;
}

flow OtherTicket.state {
    Draft -> Live;
}

action activate(ticket: Ticket) -> active_ticket: Ticket {
    transition ticket.state: Created -> active_ticket.state: Active
    verification
        require ticket.state < Ticket::Closed, "closed"
        require active_ticket.state == Ticket::Active
        require active_ticket.id == ticket.id
}
"#
        .to_string();

        server.open_document(uri.clone(), source.clone());
        assert!(server.get_diagnostics(&uri).is_empty());

        let offset = source.find("Ticket::Active").expect("qualified state") + "Ticket::".len();
        let completions = server.completion(&uri, offset_to_position(&source, offset));
        let labels = completions.iter().map(|item| item.label.as_str()).collect::<std::collections::BTreeSet<_>>();

        assert!(labels.contains("Created"));
        assert!(labels.contains("Active"));
        assert!(labels.contains("Closed"));
        assert!(!labels.contains("Live"), "Ticket:: completion must not leak OtherTicket flow states");
        assert!(completions.iter().any(|item| {
            item.label == "Active"
                && item.kind == CompletionItemKind::EnumMember
                && item.detail.as_deref() == Some("flow state Ticket::Active")
        }));
    }

    #[test]
    fn test_flow_namespace_completions() {
        let mut server = LspServer::new();
        let uri = "file:///flow_completion.cell".to_string();
        let source = r#"
module flow_completion

enum OfferState {
    Created,
    Live,
    Filled,
}

resource Offer has store {
    state: OfferState,
    amount: u64,
}

flow OfferFlow for Offer.state {
    Created -> Live;
    Live -> Filled by accept;
}

action accept(input: Offer) -> output: Offer {
    transition input.state: Live -> output.state: Filled
    verification
        require output.state == Offer::Filled
        require output.amount == input.amount
}
"#
        .to_string();

        server.open_document(uri.clone(), source.clone());
        assert!(server.get_diagnostics(&uri).is_empty());

        let offset = source.find("Offer::Filled").expect("qualified state") + "Offer::".len();
        let completions = server.completion(&uri, offset_to_position(&source, offset));
        let labels = completions.iter().map(|item| item.label.as_str()).collect::<std::collections::BTreeSet<_>>();

        assert!(labels.contains("Created"));
        assert!(labels.contains("Live"));
        assert!(labels.contains("Filled"));
        assert!(completions.iter().any(|item| {
            item.label == "Filled"
                && item.kind == CompletionItemKind::EnumMember
                && item.detail.as_deref() == Some("flow state Offer::Filled")
        }));
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
    fn parse_failure_drops_the_previous_successful_ast() {
        let mut server = LspServer::new();
        let uri = "file:///changing.cell".to_string();
        server.open_document(uri.clone(), "module changing\naction ok() -> bool { verification true }\n".to_string());
        assert!(server.ast_cache.contains_key(&uri));

        server.update_document(uri.clone(), "module changing\naction broken( {\n".to_string());

        assert!(!server.ast_cache.contains_key(&uri));
        assert!(!server.get_diagnostics(&uri).is_empty());
    }

    #[test]
    fn compiler_diagnostic_codes_keep_their_lsp_documentation_link() {
        let error = CompileError::without_span("instruction encoding failed").with_code("E2202");
        let diagnostic = diagnostic_from_error("", &error);

        assert_eq!(diagnostic.code.as_deref(), Some("E2202"));
        assert!(diagnostic.code_description.as_deref().is_some_and(|url| url.ends_with("#e2202")));
    }

    #[test]
    fn test_parse_recovery_collects_multiple_diagnostics() {
        let mut server = LspServer::new();
        let uri = "file:///multi_parse_errors.cell".to_string();
        let source = r#"
module multi_parse_errors

action bad() -> bool {
    verification
        let first: u64 true
        let second: bool 1
        return true
}
"#;
        server.open_document(uri.clone(), source.to_string());
        let diagnostics = server.get_diagnostics(&uri);
        assert_eq!(diagnostics.len(), 2);
        assert!(diagnostics.iter().any(|diagnostic| diagnostic.message.contains("expected '=', found 'true'")));
        assert!(diagnostics.iter().any(|diagnostic| diagnostic.message.contains("expected '=', found integer 1")));
    }

    #[test]
    fn test_type_errors_collect_multiple_diagnostics() {
        let mut server = LspServer::new();
        let uri = "file:///multi_errors.cell".to_string();
        let source = r#"
module multi_errors

action bad_one() -> u64 {
    verification
        return true
}

action bad_two() -> bool {
    verification
        return 1
}
"#;
        server.open_document(uri.clone(), source.to_string());
        let diagnostics = server.get_diagnostics(&uri);
        assert_eq!(diagnostics.len(), 2);
        assert!(diagnostics.iter().any(|diagnostic| diagnostic.message.contains("expected U64, found Bool")));
        assert!(diagnostics.iter().any(|diagnostic| diagnostic.message.contains("expected Bool, found U64")));
    }

    #[test]
    fn compiler_warning_diagnostics_keep_warning_severity() {
        let error = CompileError::warning("compatibility note", Span::new(0, 4, 1, 1));
        let diagnostic = diagnostic_from_error("note", &error);
        assert_eq!(diagnostic.severity, DiagnosticSeverity::Warning);
    }

    #[test]
    fn test_goto_definition_and_references() {
        let mut server = LspServer::new();
        let uri = "file:///defs.cell".to_string();
        let source =
            "module defs;\n\nresource Token {\n    amount: u64,\n}\n\naction make() -> u64 {\n    verification\n        let token = Token { amount: 1 };\n        token.amount\n}\n";
        server.open_document(uri.clone(), source.to_string());

        let definition = server.goto_definition(&uri, Position { line: 8, character: 20 }).expect("definition");
        assert_eq!(definition.range.start.line, 2);
        assert_eq!(definition.range.start.character, 9);
        assert_eq!(definition.range.end.character, 14);

        let refs = server.find_references(&uri, Position { line: 8, character: 20 });
        assert!(refs.len() >= 2);
    }

    #[test]
    fn test_hover() {
        let mut server = LspServer::new();
        let uri = "file:///hover.cell".to_string();
        let source = "module hover;\n\naction demo(x: u64)->u64 {\n    verification\n        x\n}\n";
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

resource Token has store, create, consume, replace, burn, relock {
    amount: u64,
}

action update(amount: u64) -> u64 {
    verification
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
    fn test_receipt_hover_includes_flow_metadata() {
        let mut server = LspServer::new();
        let uri = "file:///flow_hover.cell".to_string();
        let source = r#"
module flow_hover

receipt Ticket has store {
    state: u8,
    id: u64,
}

flow Ticket.state {
    Created -> Active;
}

action activate(ticket: Ticket) -> active_ticket: Ticket {
    transition ticket.state: Created -> active_ticket.state: Active
    verification
        let active = Ticket::Active
        require active_ticket.state == active
        require active_ticket.id == ticket.id
}
"#;
        server.open_document(uri.clone(), source.to_string());

        let offset = source.find("Ticket has").expect("receipt name");
        let hover = server.hover(&uri, offset_to_position(source, offset)).expect("hover");
        assert!(hover.contents.contains("receipt Ticket"));
        assert!(hover.contents.contains("Flow metadata"));
        assert!(hover.contents.contains("States: `Created -> Active`"));
        assert!(hover.contents.contains("Created[0] -> Active[1]"));
    }

    #[test]
    fn test_type_hover_includes_validity_evidence() {
        let mut server = LspServer::new();
        let uri = "file:///validity_hover.cell".to_string();
        let source = r#"
module validity_hover

resource Token has store, create {
    amount: u64
    height: u64

    validity
        require amount > 0
        require height > env::block_number()
}

action mint(amount: u64, height: u64) -> Token {
    verification
        return create Token { amount: amount, height: height }
}
"#;
        server.open_document(uri.clone(), source.to_string());

        let offset = source.find("Token has").expect("resource name");
        let hover = server.hover(&uri, offset_to_position(source, offset)).expect("hover");
        assert!(hover.contents.contains("Validity metadata"));
        assert!(hover.contents.contains("`amount > 0` — `checked-runtime`"));
        assert!(hover.contents.contains("create: `checked-runtime`"));
        assert!(hover.contents.contains("`height > env::block_number()` — `builder-evidence-required`"));
        assert!(hover.contents.contains("create: `builder-header-evidence-required`"));
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

resource Token has store, create, consume, replace, burn, relock {
    amount: u64,
}

action update(amount: u64) -> u64 {
    verification
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
    fn test_lowering_diagnostics_explain_deferred_runtime_in_locks_and_helpers() {
        let fixtures = [
            (
                "lock 'unlock'",
                "lock:unlock",
                "lock unlock",
                "module deferred_digest\nlock unlock() -> bool { verification let value = env::sighash_all(source::group_input(0)) return value == value }\n",
            ),
            (
                "fn 'digest'",
                "fn:digest",
                "fn digest",
                "module deferred_digest\nfn digest() -> Hash { return env::sighash_all(source::group_input(0)) }\n",
            ),
            (
                "fn 'digest'",
                "fn:digest",
                "fn digest",
                "module deferred_digest\nfn digest() -> Hash { return env::sighash_all(source::group_input(0)) }\nlock unlock() -> bool { verification let value = digest() return value == value }\n",
            ),
        ];
        for edition in [crate::CURRENT_EDITION, crate::NEXT_EDITION] {
            for (callable, scope, declaration, source) in fixtures {
                let source = if edition == crate::NEXT_EDITION { source.replace("verification", "") } else { source.to_string() };
                let metadata = crate::compile_metadata(&source, edition, None).expect("audit metadata remains available");
                let obligation = metadata
                    .runtime
                    .verifier_obligations
                    .iter()
                    .find(|obligation| {
                        obligation.scope == scope
                            && obligation.feature == "ckb-sighash-all-deferred"
                            && obligation.status == "fail-closed"
                    })
                    .expect("shared metadata must explain the deferred operation");
                let mut server = LspServer::new();
                let uri = "file:///deferred_digest.cell".to_string();
                server.open_document_with_edition(uri.clone(), source.clone(), edition);
                let diagnostics = server.get_diagnostics(&uri);
                assert!(diagnostics.iter().all(|diagnostic| diagnostic.severity != DiagnosticSeverity::Error), "{diagnostics:?}");
                let warning = diagnostics
                    .iter()
                    .find(|diagnostic| diagnostic.source == "cellscript-lowering" && diagnostic.message.contains(callable))
                    .expect("a lock or helper must expose its unsupported runtime operation");
                assert_eq!(warning.severity, DiagnosticSeverity::Warning);
                assert!(warning.message.contains(&obligation.feature), "{warning:?}");
                assert!(warning.message.contains(&obligation.detail), "{warning:?}");
                assert_eq!(warning.range.start, offset_to_position(&source, source.find(declaration).unwrap()));
                assert!(warning.range.end.line >= warning.range.start.line);
            }
        }
    }

    #[test]
    fn test_code_actions_for_lowering_diagnostics() {
        let mut server = LspServer::new();
        let uri = "file:///metadata_action.cell".to_string();
        let diagnostic_range = Range { start: Position { line: 2, character: 0 }, end: Position { line: 5, character: 1 } };
        server.diagnostics.insert(
            uri.clone(),
            vec![Diagnostic {
                range: diagnostic_range,
                severity: DiagnosticSeverity::Warning,
                code: None,
                code_description: None,
                message: "action emits fail-closed runtime traps".to_string(),
                source: "cellscript-lowering".to_string(),
            }],
        );

        let actions = server.code_action(&uri, diagnostic_range);
        assert!(actions.iter().any(|action| action.title.contains("cellc metadata")));
        assert!(actions.iter().any(|action| action.title.contains("riscv64-asm")));
        assert!(actions.iter().all(|action| action.edit.is_none()));
    }

    #[test]
    fn test_format_document() {
        let mut server = LspServer::new();
        let uri = "file:///fmt.cell".to_string();
        let source = "module fmt\naction demo(x:u64)->u64 {\nverification\nx\n}\n";
        server.open_document(uri.clone(), source.to_string());

        let edits = server.format_document(&uri);
        assert_eq!(edits.len(), 1);
        assert!(edits[0].new_text.contains("action demo(x: u64) -> u64 {\n    verification"));
    }

    #[test]
    fn test_manifest_edition_selects_the_preview_frontend() {
        let temp = tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            "[package]\nedition = \"2027\"\nname = \"preview\"\nversion = \"0.1.0\"\nentry = \"src/main.cell\"\n",
        )
        .unwrap();
        let source = "module preview\naction main(value: u64) -> u64 { return value }\n";
        let source_path = root.join("src/main.cell");
        std::fs::write(&source_path, source).unwrap();

        let mut server = LspServer::new();
        let uri = utf8_path_to_file_uri(&source_path);
        server.open_document(uri.clone(), source.to_string());

        let diagnostics = server.get_diagnostics(&uri);
        assert!(diagnostics.is_empty(), "unexpected diagnostics: {diagnostics:?}");
        let completions = server.completion(&uri, Position { line: 1, character: 64 });
        assert!(server.keyword_completions(&uri).iter().any(|item| item.label == "consume"));
        assert!(server.keyword_completions(&uri).iter().any(|item| item.label == "consume_each"));
        assert!(completions.iter().any(|item| item.label == "type_script"));
        assert!(completions.iter().any(|item| item.label == "lock_script"));
        for label in ["effects", "pool", "retire", "fresh", "audit"] {
            assert!(!server.keyword_completions(&uri).iter().any(|item| item.label == label));
        }

        let native = r#"module preview
resource Token has store, replace, relock { owner: Address, amount: u64 }
type_script TokenTransfer on type_group<Token> {
    entry transfer(
        input token: Token from group_input[0],
        witness recipient: Address from group_witness.input_type,
        output next: Token from group_output[0],
    ) {
        verify { enforce token.amount > 0 }
        effects {
            replace token -> next {
                data { owner = same; amount = same }
                identity = same
                type_script = same
                lock_script = exact_hash(recipient)
                capacity = same
                cardinality = one_to_one
            }
        }
    }
}
"#;
        std::fs::write(&source_path, native).unwrap();
        server.update_document(uri.clone(), native.to_string());
        assert!(server.get_diagnostics(&uri).is_empty());
        for label in ["effects", "pool", "retire", "fresh", "audit"] {
            assert!(server.keyword_completions(&uri).iter().any(|item| item.label == label));
        }
        assert!(!server.keyword_completions(&uri).iter().any(|item| item.label == "consume" || item.label == "consume_each"));
        let edits = server.format_document(&uri);
        assert_eq!(edits.len(), 1);
        assert!(edits[0].new_text.contains("type_script TokenTransfer on type_group<Token>"));

        let native_lock = r#"module preview
resource Vault has store { owner: Address }
lock_script VaultOwner on lock_group {
    entry unlock(
        protected vault: Vault from group_input[0],
        lock_args owner: Address from current_script.args,
        witness claimed_owner: Address from group_witness.input_type,
    ) {
        verify {
            enforce vault.owner == owner
            enforce claimed_owner == owner
        }
    }
}
"#;
        std::fs::write(&source_path, native_lock).unwrap();
        server.update_document(uri.clone(), native_lock.to_string());
        assert!(server.get_diagnostics(&uri).is_empty());
        let edits = server.format_document(&uri);
        assert_eq!(edits.len(), 1);
        assert!(edits[0].new_text.contains("lock_script VaultOwner on lock_group"));
    }

    #[test]
    fn test_workspace_goto_definition_across_modules() {
        let temp = tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            "[package]\nedition = \"2026\"\nname = \"demo\"\nversion = \"0.1.0\"\nentry = \"src/main.cell\"\n",
        )
        .unwrap();
        std::fs::write(root.join("src/types.cell"), "module demo::types\n\nresource Token {\n    amount: u64,\n}\n").unwrap();
        let main_source =
            "module demo::main\n\nuse demo::types::Token\n\naction inspect(token: Token) -> u64 {\n    verification\n        token.amount\n}\n";
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
        std::fs::write(
            root.join("Cell.toml"),
            "[package]\nedition = \"2026\"\nname = \"demo\"\nversion = \"0.1.0\"\nentry = \"src/main.cell\"\n",
        )
        .unwrap();
        let types_source = "module demo::types\n\nresource Token {\n    amount: u64,\n}\n";
        let types_path = root.join("src/types.cell");
        std::fs::write(&types_path, types_source).unwrap();
        let main_source =
            "module demo::main\n\nuse demo::types::Token\n\naction inspect(token: Token) -> u64 {\n    verification\n        token.amount\n}\n";
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
        std::fs::write(
            root.join("Cell.toml"),
            "[package]\nedition = \"2026\"\nname = \"demo\"\nversion = \"0.1.0\"\nentry = \"src/main.cell\"\n",
        )
        .unwrap();
        let types_source = "module demo::types\n\nresource Token {\n    amount: u64,\n}\n";
        let types_path = root.join("src/types.cell");
        std::fs::write(&types_path, types_source).unwrap();
        let main_source =
            "module demo::main\n\nuse demo::types::Token\n\naction inspect(token: Token) -> u64 {\n    verification\n        token.amount\n}\n";
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
    verification
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
    verification
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
