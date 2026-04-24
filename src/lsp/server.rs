//! Tower-LSP transport layer for the CellScript language server.
//!
//! This module wraps the in-process `LspServer` behind the `tower_lsp::LanguageServer`
//! trait so that `cellc --lsp` can act as a full JSON-RPC language server.

use crate::lsp;
use std::collections::HashMap;
use std::sync::Mutex;
use tower_lsp::jsonrpc::Result as LspResult;
use tower_lsp::lsp_types::{
    CodeAction, CodeActionKind, CodeActionOrCommand, CodeActionParams, CodeActionProviderCapability, CodeActionResponse,
    CompletionItem, CompletionItemKind, CompletionOptions, CompletionParams, CompletionResponse, Diagnostic, DiagnosticSeverity,
    DidChangeTextDocumentParams, DidCloseTextDocumentParams, DidOpenTextDocumentParams, DocumentFormattingParams, DocumentHighlight,
    DocumentHighlightKind, DocumentHighlightParams, DocumentSymbolParams, DocumentSymbolResponse, Documentation, FoldingRange,
    FoldingRangeKind, FoldingRangeParams, FoldingRangeProviderCapability, GotoDefinitionParams, GotoDefinitionResponse, Hover,
    HoverContents, HoverParams, HoverProviderCapability, InitializeParams, InitializeResult, InitializedParams, InsertTextFormat,
    Location, MarkupContent, MarkupKind, MessageType, OneOf, ParameterInformation, ParameterLabel, Position, Range, ReferenceParams,
    RenameParams, SelectionRange, SelectionRangeParams, SelectionRangeProviderCapability, ServerCapabilities, ServerInfo,
    SignatureHelp, SignatureHelpOptions, SignatureHelpParams, SignatureInformation, SymbolInformation, SymbolKind,
    TextDocumentSyncCapability, TextDocumentSyncKind, TextDocumentSyncOptions, TextEdit, Url, WorkDoneProgressOptions, WorkspaceEdit,
};
use tower_lsp::{Client, LanguageServer, LspService, Server};

struct CellScriptBackend {
    client: Client,
    state: Mutex<lsp::LspServer>,
}

impl CellScriptBackend {
    fn new(client: Client) -> Self {
        Self { client, state: Mutex::new(lsp::LspServer::new()) }
    }

    /// Publish diagnostics for a given URI.
    async fn publish_diagnostics_for(&self, uri: &Url) {
        let uri_str = uri.to_string();
        let diagnostics = self.state.lock().unwrap().get_diagnostics(&uri_str);
        let lsp_diagnostics: Vec<Diagnostic> = diagnostics.into_iter().map(convert_diagnostic).collect();
        self.client.publish_diagnostics(uri.clone(), lsp_diagnostics, None).await;
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for CellScriptBackend {
    async fn initialize(&self, _: InitializeParams) -> LspResult<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Options(TextDocumentSyncOptions {
                    open_close: Some(true),
                    change: Some(TextDocumentSyncKind::INCREMENTAL),
                    will_save: None,
                    will_save_wait_until: None,
                    save: None,
                })),
                completion_provider: Some(CompletionOptions {
                    resolve_provider: None,
                    trigger_characters: Some(vec![".".to_string(), ":".to_string()]),
                    all_commit_characters: None,
                    work_done_progress_options: WorkDoneProgressOptions { work_done_progress: None },
                    completion_item: None,
                }),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                definition_provider: Some(OneOf::Left(true)),
                references_provider: Some(OneOf::Left(true)),
                rename_provider: Some(OneOf::Left(true)),
                document_symbol_provider: Some(OneOf::Left(true)),
                code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
                document_formatting_provider: Some(OneOf::Left(true)),
                signature_help_provider: Some(SignatureHelpOptions {
                    trigger_characters: Some(vec!["(".to_string(), ",".to_string()]),
                    retrigger_characters: None,
                    work_done_progress_options: WorkDoneProgressOptions { work_done_progress: None },
                }),
                document_highlight_provider: Some(OneOf::Left(true)),
                folding_range_provider: Some(FoldingRangeProviderCapability::Simple(true)),
                selection_range_provider: Some(SelectionRangeProviderCapability::Simple(true)),
                ..ServerCapabilities::default()
            },
            server_info: Some(ServerInfo {
                name: "cellscript-language-server".to_string(),
                version: Some(crate::VERSION.to_string()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client.log_message(MessageType::INFO, "CellScript language server initialized").await;
    }

    async fn shutdown(&self) -> LspResult<()> {
        Ok(())
    }

    // ---- document sync ----

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        let uri_str = uri.to_string();
        self.state.lock().unwrap().open_document(uri_str, params.text_document.text);
        self.publish_diagnostics_for(&uri).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        let uri_str = uri.to_string();
        {
            let mut state = self.state.lock().unwrap();
            // Apply incremental changes. If the client sends a full update
            // (single change with no range), treat it as a full replacement.
            if params.content_changes.len() == 1 {
                let change = &params.content_changes[0];
                if change.range.is_none() {
                    state.update_document(uri_str, change.text.clone());
                } else {
                    state.update_document_incremental(
                        &uri_str,
                        params
                            .content_changes
                            .iter()
                            .map(|c| lsp::TextDocumentContentChangeEvent {
                                range: c.range.map(convert_range_back),
                                range_length: c.range_length,
                                text: c.text.clone(),
                            })
                            .collect(),
                    );
                }
            } else {
                // For multiple incremental changes, apply them one by one.
                state.update_document_incremental(
                    &uri_str,
                    params
                        .content_changes
                        .iter()
                        .map(|c| lsp::TextDocumentContentChangeEvent {
                            range: c.range.map(convert_range_back),
                            range_length: c.range_length,
                            text: c.text.clone(),
                        })
                        .collect(),
                );
            }
        }
        self.publish_diagnostics_for(&uri).await;
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri_str = params.text_document.uri.to_string();
        self.state.lock().unwrap().close_document(&uri_str);
    }

    // ---- language features ----

    async fn completion(&self, params: CompletionParams) -> LspResult<Option<CompletionResponse>> {
        let uri_str = params.text_document_position.text_document.uri.to_string();
        let position = convert_position_back(params.text_document_position.position);
        let items = self.state.lock().unwrap().completion(&uri_str, position);
        if items.is_empty() {
            Ok(None)
        } else {
            Ok(Some(CompletionResponse::Array(items.into_iter().map(convert_completion_item).collect())))
        }
    }

    async fn goto_definition(&self, params: GotoDefinitionParams) -> LspResult<Option<GotoDefinitionResponse>> {
        let uri_str = params.text_document_position_params.text_document.uri.to_string();
        let position = convert_position_back(params.text_document_position_params.position);
        let location = self.state.lock().unwrap().goto_definition(&uri_str, position);
        Ok(location.map(|loc| GotoDefinitionResponse::Scalar(convert_location(loc))))
    }

    async fn references(&self, params: ReferenceParams) -> LspResult<Option<Vec<Location>>> {
        let uri_str = params.text_document_position.text_document.uri.to_string();
        let position = convert_position_back(params.text_document_position.position);
        let refs = self.state.lock().unwrap().find_references(&uri_str, position);
        if refs.is_empty() {
            Ok(None)
        } else {
            Ok(Some(refs.into_iter().map(convert_location).collect()))
        }
    }

    async fn hover(&self, params: HoverParams) -> LspResult<Option<Hover>> {
        let uri_str = params.text_document_position_params.text_document.uri.to_string();
        let position = convert_position_back(params.text_document_position_params.position);
        let hover = self.state.lock().unwrap().hover(&uri_str, position);
        Ok(hover.map(|h| Hover {
            contents: HoverContents::Markup(MarkupContent { kind: MarkupKind::Markdown, value: h.contents }),
            range: h.range.map(convert_range),
        }))
    }

    async fn document_symbol(&self, params: DocumentSymbolParams) -> LspResult<Option<DocumentSymbolResponse>> {
        let uri_str = params.text_document.uri.to_string();
        let symbols = self.state.lock().unwrap().document_symbols(&uri_str);
        if symbols.is_empty() {
            Ok(None)
        } else {
            Ok(Some(DocumentSymbolResponse::Flat(symbols.into_iter().map(convert_symbol_information).collect())))
        }
    }

    async fn rename(&self, params: RenameParams) -> LspResult<Option<WorkspaceEdit>> {
        let uri_str = params.text_document_position.text_document.uri.to_string();
        let position = convert_position_back(params.text_document_position.position);
        let changes = self.state.lock().unwrap().rename(&uri_str, position, params.new_name);
        if changes.is_empty() {
            Ok(None)
        } else {
            let mut lsp_changes = HashMap::new();
            for (uri, edits) in changes {
                let url = Url::parse(&uri).unwrap_or_else(|_| Url::from_file_path(&uri).unwrap());
                lsp_changes.insert(url, edits.into_iter().map(convert_text_edit).collect());
            }
            Ok(Some(WorkspaceEdit { changes: Some(lsp_changes), document_changes: None, change_annotations: None }))
        }
    }

    async fn code_action(&self, params: CodeActionParams) -> LspResult<Option<CodeActionResponse>> {
        let uri_str = params.text_document.uri.to_string();
        let range = convert_range_back(params.range);
        let actions = self.state.lock().unwrap().code_action(&uri_str, range);
        if actions.is_empty() {
            Ok(None)
        } else {
            Ok(Some(
                actions
                    .into_iter()
                    .map(|a| {
                        CodeActionOrCommand::CodeAction(CodeAction {
                            title: a.title,
                            kind: Some(CodeActionKind::from(a.kind)),
                            diagnostics: None,
                            edit: a.edit.map(|we| WorkspaceEdit {
                                changes: Some(
                                    we.changes
                                        .into_iter()
                                        .map(|(uri, edits)| {
                                            let url = Url::parse(&uri).unwrap_or_else(|_| Url::from_file_path(&uri).unwrap());
                                            (url, edits.into_iter().map(convert_text_edit).collect())
                                        })
                                        .collect(),
                                ),
                                document_changes: None,
                                change_annotations: None,
                            }),
                            command: None,
                            is_preferred: None,
                            disabled: None,
                            data: None,
                        })
                    })
                    .collect(),
            ))
        }
    }

    async fn formatting(&self, params: DocumentFormattingParams) -> LspResult<Option<Vec<TextEdit>>> {
        let uri_str = params.text_document.uri.to_string();
        let edits = self.state.lock().unwrap().format_document(&uri_str);
        if edits.is_empty() {
            Ok(None)
        } else {
            Ok(Some(edits.into_iter().map(convert_text_edit).collect()))
        }
    }

    async fn signature_help(&self, params: SignatureHelpParams) -> LspResult<Option<SignatureHelp>> {
        let uri_str = params.text_document_position_params.text_document.uri.to_string();
        let position = convert_position_back(params.text_document_position_params.position);
        let help = self.state.lock().unwrap().signature_help(&uri_str, position);
        Ok(help.map(convert_signature_help))
    }

    async fn document_highlight(&self, params: DocumentHighlightParams) -> LspResult<Option<Vec<DocumentHighlight>>> {
        let uri_str = params.text_document_position_params.text_document.uri.to_string();
        let position = convert_position_back(params.text_document_position_params.position);
        let highlights = self.state.lock().unwrap().document_highlight(&uri_str, position);
        if highlights.is_empty() {
            Ok(None)
        } else {
            Ok(Some(
                highlights
                    .into_iter()
                    .map(|h| DocumentHighlight {
                        range: convert_range(h.range),
                        kind: Some(match h.kind {
                            lsp::DocumentHighlightKind::Text => DocumentHighlightKind::TEXT,
                            lsp::DocumentHighlightKind::Read => DocumentHighlightKind::READ,
                            lsp::DocumentHighlightKind::Write => DocumentHighlightKind::WRITE,
                        }),
                    })
                    .collect(),
            ))
        }
    }

    async fn folding_range(&self, params: FoldingRangeParams) -> LspResult<Option<Vec<FoldingRange>>> {
        let uri_str = params.text_document.uri.to_string();
        let ranges = self.state.lock().unwrap().folding_range(&uri_str);
        if ranges.is_empty() {
            Ok(None)
        } else {
            Ok(Some(
                ranges
                    .into_iter()
                    .map(|r| FoldingRange {
                        start_line: r.start_line,
                        start_character: r.start_character,
                        end_line: r.end_line,
                        end_character: r.end_character,
                        kind: Some(match r.kind {
                            Some(lsp::FoldingRangeKind::Comment) => FoldingRangeKind::Comment,
                            Some(lsp::FoldingRangeKind::Imports) => FoldingRangeKind::Imports,
                            Some(lsp::FoldingRangeKind::Region) => FoldingRangeKind::Region,
                            None => FoldingRangeKind::Region,
                        }),
                        collapsed_text: None,
                    })
                    .collect(),
            ))
        }
    }

    async fn selection_range(&self, params: SelectionRangeParams) -> LspResult<Option<Vec<SelectionRange>>> {
        let uri_str = params.text_document.uri.to_string();
        let mut results = Vec::new();
        for pos in &params.positions {
            let position = convert_position_back(*pos);
            if let Some(range) = self.state.lock().unwrap().selection_range(&uri_str, position) {
                results.push(convert_selection_range(range));
            }
        }
        if results.is_empty() {
            Ok(None)
        } else {
            Ok(Some(results))
        }
    }
}

// ---------------------------------------------------------------------------
// Type conversion helpers
// ---------------------------------------------------------------------------

fn convert_position(p: lsp::Position) -> Position {
    Position { line: p.line, character: p.character }
}

fn convert_position_back(p: Position) -> lsp::Position {
    lsp::Position { line: p.line, character: p.character }
}

fn convert_range(r: lsp::Range) -> Range {
    Range { start: convert_position(r.start), end: convert_position(r.end) }
}

fn convert_range_back(r: Range) -> lsp::Range {
    lsp::Range { start: convert_position_back(r.start), end: convert_position_back(r.end) }
}

fn convert_diagnostic(d: lsp::Diagnostic) -> Diagnostic {
    Diagnostic {
        range: convert_range(d.range),
        severity: Some(match d.severity {
            lsp::DiagnosticSeverity::Error => DiagnosticSeverity::ERROR,
            lsp::DiagnosticSeverity::Warning => DiagnosticSeverity::WARNING,
            lsp::DiagnosticSeverity::Information => DiagnosticSeverity::INFORMATION,
            lsp::DiagnosticSeverity::Hint => DiagnosticSeverity::HINT,
        }),
        code: None,
        code_description: None,
        source: Some(d.source),
        message: d.message,
        related_information: None,
        tags: None,
        data: None,
    }
}

fn convert_completion_item(item: lsp::CompletionItem) -> CompletionItem {
    CompletionItem {
        label: item.label,
        kind: Some(match item.kind {
            lsp::CompletionItemKind::Text => CompletionItemKind::TEXT,
            lsp::CompletionItemKind::Method => CompletionItemKind::METHOD,
            lsp::CompletionItemKind::Function => CompletionItemKind::FUNCTION,
            lsp::CompletionItemKind::Constructor => CompletionItemKind::CONSTRUCTOR,
            lsp::CompletionItemKind::Field => CompletionItemKind::FIELD,
            lsp::CompletionItemKind::Variable => CompletionItemKind::VARIABLE,
            lsp::CompletionItemKind::Class => CompletionItemKind::CLASS,
            lsp::CompletionItemKind::Interface => CompletionItemKind::INTERFACE,
            lsp::CompletionItemKind::Module => CompletionItemKind::MODULE,
            lsp::CompletionItemKind::Property => CompletionItemKind::PROPERTY,
            lsp::CompletionItemKind::Unit => CompletionItemKind::UNIT,
            lsp::CompletionItemKind::Value => CompletionItemKind::VALUE,
            lsp::CompletionItemKind::Enum => CompletionItemKind::ENUM,
            lsp::CompletionItemKind::Keyword => CompletionItemKind::KEYWORD,
            lsp::CompletionItemKind::Snippet => CompletionItemKind::SNIPPET,
            lsp::CompletionItemKind::Color => CompletionItemKind::COLOR,
            lsp::CompletionItemKind::File => CompletionItemKind::FILE,
            lsp::CompletionItemKind::Reference => CompletionItemKind::REFERENCE,
            lsp::CompletionItemKind::Folder => CompletionItemKind::FOLDER,
            lsp::CompletionItemKind::EnumMember => CompletionItemKind::ENUM_MEMBER,
            lsp::CompletionItemKind::Constant => CompletionItemKind::CONSTANT,
            lsp::CompletionItemKind::Struct => CompletionItemKind::STRUCT,
            lsp::CompletionItemKind::Event => CompletionItemKind::EVENT,
            lsp::CompletionItemKind::Operator => CompletionItemKind::OPERATOR,
            lsp::CompletionItemKind::TypeParameter => CompletionItemKind::TYPE_PARAMETER,
        }),
        detail: item.detail,
        documentation: item.documentation.map(Documentation::String),
        insert_text: item.insert_text,
        insert_text_format: Some(InsertTextFormat::SNIPPET),
        ..CompletionItem::default()
    }
}

fn convert_location(loc: lsp::Location) -> Location {
    let url = Url::parse(&loc.uri).unwrap_or_else(|_| Url::from_file_path(&loc.uri).unwrap());
    Location { uri: url, range: convert_range(loc.range) }
}

#[allow(deprecated)]
fn convert_symbol_information(sym: lsp::SymbolInformation) -> SymbolInformation {
    SymbolInformation {
        name: sym.name,
        kind: match sym.kind {
            lsp::SymbolKind::File => SymbolKind::FILE,
            lsp::SymbolKind::Module => SymbolKind::MODULE,
            lsp::SymbolKind::Namespace => SymbolKind::NAMESPACE,
            lsp::SymbolKind::Package => SymbolKind::PACKAGE,
            lsp::SymbolKind::Class => SymbolKind::CLASS,
            lsp::SymbolKind::Method => SymbolKind::METHOD,
            lsp::SymbolKind::Property => SymbolKind::PROPERTY,
            lsp::SymbolKind::Field => SymbolKind::FIELD,
            lsp::SymbolKind::Constructor => SymbolKind::CONSTRUCTOR,
            lsp::SymbolKind::Enum => SymbolKind::ENUM,
            lsp::SymbolKind::Interface => SymbolKind::INTERFACE,
            lsp::SymbolKind::Function => SymbolKind::FUNCTION,
            lsp::SymbolKind::Variable => SymbolKind::VARIABLE,
            lsp::SymbolKind::Constant => SymbolKind::CONSTANT,
            lsp::SymbolKind::String => SymbolKind::STRING,
            lsp::SymbolKind::Number => SymbolKind::NUMBER,
            lsp::SymbolKind::Boolean => SymbolKind::BOOLEAN,
            lsp::SymbolKind::Array => SymbolKind::ARRAY,
            lsp::SymbolKind::Object => SymbolKind::OBJECT,
            lsp::SymbolKind::Key => SymbolKind::KEY,
            lsp::SymbolKind::Null => SymbolKind::NULL,
            lsp::SymbolKind::EnumMember => SymbolKind::ENUM_MEMBER,
            lsp::SymbolKind::Struct => SymbolKind::STRUCT,
            lsp::SymbolKind::Event => SymbolKind::EVENT,
            lsp::SymbolKind::Operator => SymbolKind::OPERATOR,
            lsp::SymbolKind::TypeParameter => SymbolKind::TYPE_PARAMETER,
        },
        deprecated: None,
        location: convert_location(sym.location),
        container_name: sym.container_name,
        tags: None,
    }
}

fn convert_text_edit(edit: lsp::TextEdit) -> TextEdit {
    TextEdit { range: convert_range(edit.range), new_text: edit.new_text }
}

fn convert_signature_help(help: lsp::SignatureHelp) -> SignatureHelp {
    SignatureHelp {
        signatures: help
            .signatures
            .into_iter()
            .map(|sig| SignatureInformation {
                label: sig.label,
                documentation: sig.documentation.map(Documentation::String),
                parameters: Some(
                    sig.parameters
                        .into_iter()
                        .map(|p| ParameterInformation {
                            label: ParameterLabel::Simple(match p.label {
                                lsp::ParameterLabel::Simple(s) => s,
                                lsp::ParameterLabel::Labelled { left, right } => {
                                    format!("{}:{}", left, right)
                                }
                            }),
                            documentation: p.documentation.map(Documentation::String),
                        })
                        .collect(),
                ),
                active_parameter: None,
            })
            .collect(),
        active_signature: help.active_signature,
        active_parameter: help.active_parameter,
    }
}

fn convert_selection_range(range: lsp::SelectionRange) -> SelectionRange {
    SelectionRange { range: convert_range(range.range), parent: range.parent.map(|b| Box::new(convert_selection_range(*b))) }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub async fn run_lsp_server() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(CellScriptBackend::new);
    Server::new(stdin, stdout, socket).serve(service).await;
}

/// Blocking entry point for use from synchronous `main`.
pub fn run_lsp_server_blocking() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime for LSP server")
        .block_on(run_lsp_server());
}
