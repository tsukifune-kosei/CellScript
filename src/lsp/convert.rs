//! Type conversion between the internal `LspServer` types and `tower_lsp::lsp_types`.
//!
//! The conversion functions are implemented inline in `server.rs` within the
//! `CellScriptBackend` implementation. This module exists as a placeholder for
//! future cross-module reuse. When shared conversion helpers are needed by
//! other consumers (e.g. a DAP bridge or an HTTP gateway), move them here and
//! make them `pub`.
