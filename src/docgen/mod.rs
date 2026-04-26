//! Minimal CellScript documentation generator.

use crate::ast::*;
use crate::error::Result;
use crate::{
    CompileMetadata, PoolInvariantMetadata, PoolPrimitiveMetadata, PoolRuntimeInputRequirementMetadata,
    TransactionRuntimeInputRequirementMetadata, VerifierObligationMetadata,
};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Html,
    Markdown,
    Json,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleDoc {
    pub name: String,
    pub items: Vec<ItemDoc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ItemDoc {
    pub kind: String,
    pub name: String,
    pub signature: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditDoc {
    pub metadata_schema_version: u32,
    pub compiler_version: String,
    pub module: String,
    pub artifact_format: String,
    pub artifact_hash: Option<String>,
    pub artifact_size_bytes: Option<usize>,
    pub source_hash: Option<String>,
    pub source_content_hash: Option<String>,
    pub source_units: Vec<AuditSourceUnitDoc>,
    pub target_profile: String,
    pub target_chain: String,
    pub target_hash_domain: String,
    pub target_syscall_set: String,
    pub target_artifact_packaging: String,
    pub target_header_abi: String,
    pub target_scheduler_abi: String,
    pub vm_abi_format: String,
    pub vm_abi_version: u16,
    pub vm_abi_embedded_in_artifact: bool,
    pub vm_abi_scope: String,
    pub ckb_runtime_required: bool,
    pub standalone_runner_compatible: bool,
    pub ckb_runtime_features: Vec<String>,
    pub fail_closed_runtime_features: Vec<String>,
    pub verifier_obligations: Vec<AuditObligationDoc>,
    pub transaction_invariant_checked_subconditions: Vec<AuditTransactionInvariantSubconditionDoc>,
    pub transaction_runtime_input_requirements: Vec<TransactionRuntimeInputRequirementMetadata>,
    pub pool_primitives: Vec<PoolPrimitiveMetadata>,
    pub pool_runtime_input_requirements: Vec<AuditPoolRuntimeInputRequirementDoc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditSourceUnitDoc {
    pub path: String,
    pub role: String,
    pub hash: String,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditObligationDoc {
    pub scope: String,
    pub category: String,
    pub feature: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditPoolRuntimeInputRequirementDoc {
    pub scope: String,
    pub feature: String,
    pub component: String,
    pub source: String,
    pub index: usize,
    pub binding: String,
    pub field: Option<String>,
    pub abi: String,
    pub byte_len: usize,
    pub blocker: Option<String>,
    pub blocker_class: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditTransactionInvariantSubconditionDoc {
    pub scope: String,
    pub feature: String,
    pub status: String,
    pub checked_subconditions: Vec<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DocumentationBundle {
    pub modules: Vec<ModuleDoc>,
    pub audit: Option<AuditDoc>,
}

pub struct DocGenerator {
    modules: Vec<ModuleDoc>,
    audit: Option<AuditDoc>,
    format: OutputFormat,
    /// Cross-reference index: type name -> module name that defines it.
    type_index: HashMap<String, String>,
}

impl DocGenerator {
    pub fn new(format: OutputFormat) -> Self {
        Self { modules: Vec::new(), audit: None, format, type_index: HashMap::new() }
    }

    pub fn add_module(&mut self, module: &Module) {
        let items = module.items.iter().filter_map(item_doc).collect::<Vec<_>>();
        // Build cross-reference index for types
        for item in &module.items {
            if let Some(name) = item_name_for_xref(item) {
                self.type_index.entry(name).or_insert_with(|| module.name.clone());
            }
        }
        self.modules.push(ModuleDoc { name: module.name.clone(), items });
    }

    pub fn set_compile_metadata(&mut self, metadata: &CompileMetadata) {
        self.audit = Some(AuditDoc {
            metadata_schema_version: metadata.metadata_schema_version,
            compiler_version: metadata.compiler_version.clone(),
            module: metadata.module.clone(),
            artifact_format: metadata.artifact_format.clone(),
            artifact_hash: metadata.artifact_hash.clone(),
            artifact_size_bytes: metadata.artifact_size_bytes,
            source_hash: metadata.source_hash.clone(),
            source_content_hash: metadata.source_content_hash.clone(),
            source_units: metadata
                .source_units
                .iter()
                .map(|unit| AuditSourceUnitDoc {
                    path: unit.path.clone(),
                    role: unit.role.clone(),
                    hash: unit.hash.clone(),
                    size_bytes: unit.size_bytes,
                })
                .collect(),
            target_profile: metadata.target_profile.name.clone(),
            target_chain: metadata.target_profile.target_chain.clone(),
            target_hash_domain: metadata.target_profile.hash_domain.clone(),
            target_syscall_set: metadata.target_profile.syscall_set.clone(),
            target_artifact_packaging: metadata.target_profile.artifact_packaging.clone(),
            target_header_abi: metadata.target_profile.header_abi.clone(),
            target_scheduler_abi: metadata.target_profile.scheduler_abi.clone(),
            vm_abi_format: metadata.runtime.vm_abi.format.clone(),
            vm_abi_version: metadata.runtime.vm_abi.version,
            vm_abi_embedded_in_artifact: metadata.runtime.vm_abi.embedded_in_artifact,
            vm_abi_scope: metadata.runtime.vm_abi.scope.clone(),
            ckb_runtime_required: metadata.runtime.ckb_runtime_required,
            standalone_runner_compatible: metadata.runtime.standalone_runner_compatible,
            ckb_runtime_features: metadata.runtime.ckb_runtime_features.clone(),
            fail_closed_runtime_features: metadata.runtime.fail_closed_runtime_features.clone(),
            verifier_obligations: metadata
                .runtime
                .verifier_obligations
                .iter()
                .map(|obligation| AuditObligationDoc {
                    scope: obligation.scope.clone(),
                    category: obligation.category.clone(),
                    feature: obligation.feature.clone(),
                    status: obligation.status.clone(),
                    detail: obligation.detail.clone(),
                })
                .collect(),
            transaction_invariant_checked_subconditions: transaction_invariant_checked_subcondition_docs(
                &metadata.runtime.verifier_obligations,
            ),
            transaction_runtime_input_requirements: metadata.runtime.transaction_runtime_input_requirements.clone(),
            pool_primitives: metadata.runtime.pool_primitives.clone(),
            pool_runtime_input_requirements: pool_runtime_input_requirement_docs(&metadata.runtime.pool_primitives),
        });
    }

    pub fn generate(&self) -> Result<String> {
        match self.format {
            OutputFormat::Markdown => Ok(self.generate_markdown()),
            OutputFormat::Html => Ok(self.generate_html()),
            OutputFormat::Json => {
                Ok(serde_json::to_string_pretty(&DocumentationBundle { modules: self.modules.clone(), audit: self.audit.clone() })
                    .map_err(|error| {
                        crate::error::CompileError::new(format!("failed to serialize docs: {}", error), crate::error::Span::default())
                    })?)
            }
        }
    }

    /// Generate a search index as JSON for client-side search.
    /// Returns a JSON array of { name, kind, module } entries.
    pub fn generate_search_index(&self) -> String {
        let entries: Vec<serde_json::Value> = self
            .modules
            .iter()
            .flat_map(|module| {
                module.items.iter().map(|item| {
                    serde_json::json!({
                        "name": item.name,
                        "kind": item.kind,
                        "module": module.name,
                    })
                })
            })
            .collect();
        serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".to_string())
    }

    /// Look up the module that defines a given type name.
    pub fn resolve_type(&self, type_name: &str) -> Option<&str> {
        self.type_index.get(type_name).map(|s| s.as_str())
    }

    fn generate_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# CellScript API Documentation\n\n");
        for module in &self.modules {
            out.push_str(&format!("## Module `{}`\n\n", module.name));
            if module.items.is_empty() {
                out.push_str("_No documentable items._\n\n");
                continue;
            }
            for item in &module.items {
                out.push_str(&format!("### {} `{}`\n\n", item.kind, item.name));
                out.push_str("```cellscript\n");
                out.push_str(&item.signature);
                out.push_str("\n```\n\n");
                if !item.summary.is_empty() {
                    out.push_str(&item.summary);
                    out.push_str("\n\n");
                }
            }
        }
        if let Some(audit) = &self.audit {
            out.push_str(&audit.generate_markdown());
        }
        out
    }

    fn generate_html(&self) -> String {
        let mut out = String::new();
        out.push_str("<!doctype html><html><head><meta charset=\"utf-8\"><title>CellScript API Documentation</title>");
        out.push_str(
            "<style>body{font-family:ui-sans-serif,system-ui,sans-serif;max-width:960px;margin:0 auto;padding:32px;line-height:1.6;color:#1f2937}pre{background:#f3f4f6;padding:16px;border-radius:8px;overflow:auto}section{margin-bottom:32px}.kind{display:inline-block;padding:2px 8px;border-radius:999px;background:#e5e7eb;font-size:12px;color:#374151}</style>",
        );
        out.push_str("</head><body><h1>CellScript API Documentation</h1>");
        for module in &self.modules {
            out.push_str(&format!("<section><h2>Module <code>{}</code></h2>", escape_html(&module.name)));
            if module.items.is_empty() {
                out.push_str("<p><em>No documentable items.</em></p></section>");
                continue;
            }
            for item in &module.items {
                out.push_str(&format!(
                    "<article><p class=\"kind\">{}</p><h3><code>{}</code></h3><pre>{}</pre>",
                    escape_html(&item.kind),
                    escape_html(&item.name),
                    escape_html(&item.signature)
                ));
                if !item.summary.is_empty() {
                    out.push_str(&format!("<p>{}</p>", escape_html(&item.summary)));
                }
                out.push_str("</article>");
            }
            out.push_str("</section>");
        }
        if let Some(audit) = &self.audit {
            out.push_str(&audit.generate_html());
        }
        out.push_str("</body></html>");
        out
    }
}

impl AuditDoc {
    fn generate_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("## Lowering Audit Report\n\n");
        out.push_str(&format!("- Metadata schema version: `{}`\n", self.metadata_schema_version));
        out.push_str(&format!("- Compiler version: `{}`\n", self.compiler_version));
        out.push_str(&format!("- Module: `{}`\n", self.module));
        out.push_str(&format!("- Artifact format: `{}`\n", self.artifact_format));
        out.push_str(&format!("- Target profile: `{}`\n", self.target_profile));
        out.push_str(&format!("- Target chain: `{}`\n", self.target_chain));
        out.push_str(&format!("- Target hash domain: `{}`\n", self.target_hash_domain));
        out.push_str(&format!("- Target syscall set: `{}`\n", self.target_syscall_set));
        out.push_str(&format!("- Target artifact packaging: `{}`\n", self.target_artifact_packaging));
        out.push_str(&format!("- Target header ABI: `{}`\n", self.target_header_abi));
        out.push_str(&format!("- Target scheduler ABI: `{}`\n", self.target_scheduler_abi));
        if let Some(hash) = &self.artifact_hash {
            out.push_str(&format!("- Artifact hash (CKB Blake2b): `{}`\n", hash));
        }
        if let Some(size) = self.artifact_size_bytes {
            out.push_str(&format!("- Artifact size: `{}` bytes\n", size));
        }
        if let Some(hash) = &self.source_hash {
            out.push_str(&format!("- Source set hash (CKB Blake2b): `{}`\n", hash));
        }
        if let Some(hash) = &self.source_content_hash {
            out.push_str(&format!("- Source content hash (CKB Blake2b): `{}`\n", hash));
        }
        out.push_str(&format!("- VM ABI: `{}` (`0x{:04x}`)\n", self.vm_abi_format, self.vm_abi_version));
        out.push_str(&format!("- VM ABI embedded in artifact: `{}`\n", self.vm_abi_embedded_in_artifact));
        out.push_str(&format!("- VM ABI scope: `{}`\n", self.vm_abi_scope));
        out.push_str(&format!("- CKB runtime required: `{}`\n", self.ckb_runtime_required));
        out.push_str(&format!("- Standalone runner compatible: `{}`\n", self.standalone_runner_compatible));
        out.push_str(&format!("- CKB runtime features: `{}`\n", comma_or_none(&self.ckb_runtime_features)));
        out.push_str(&format!("- Fail-closed runtime features: `{}`\n\n", comma_or_none(&self.fail_closed_runtime_features)));

        if !self.source_units.is_empty() {
            out.push_str("### Source Units\n\n");
            out.push_str("| Role | Path | Hash | Size |\n");
            out.push_str("|---|---|---|---|\n");
            for unit in &self.source_units {
                out.push_str(&format!(
                    "| `{}` | `{}` | `{}` | `{}` bytes |\n",
                    escape_markdown_table_cell(&unit.role),
                    escape_markdown_table_cell(&unit.path),
                    escape_markdown_table_cell(&unit.hash),
                    unit.size_bytes
                ));
            }
            out.push('\n');
        }

        out.push_str("### Pool Pattern Metadata\n\n");
        if self.pool_primitives.is_empty() {
            out.push_str("_No pool pattern metadata emitted._\n\n");
        } else {
            out.push_str(
                "| Scope | Operation | Feature | Status | Invariant Families | Checked Components | Runtime Required | Runtime Input Requirements |\n",
            );
            out.push_str("|---|---|---|---|---|---|---|---|\n");
            for primitive in &self.pool_primitives {
                out.push_str(&format!(
                    "| `{}` | `{}` | `{}` | `{}` | {} | {} | {} | {} |\n",
                    escape_markdown_table_cell(&primitive.scope),
                    escape_markdown_table_cell(&primitive.operation),
                    escape_markdown_table_cell(&primitive.feature),
                    escape_markdown_table_cell(&primitive.status),
                    escape_markdown_table_cell(&pool_invariant_list(&primitive.invariant_families)),
                    escape_markdown_table_cell(&comma_or_none(&primitive.checked_components)),
                    escape_markdown_table_cell(&comma_or_none(&primitive.runtime_required_components)),
                    escape_markdown_table_cell(&pool_runtime_input_requirement_list(&primitive.runtime_input_requirements))
                ));
            }
            out.push('\n');
        }

        out.push_str("### Pool Runtime Input Requirements\n\n");
        if self.pool_runtime_input_requirements.is_empty() {
            out.push_str("_No pool runtime input requirements emitted._\n\n");
        } else {
            out.push_str("| Scope | Feature | Component | Source | Binding | Field | ABI | Bytes | Blocker | Blocker Class |\n");
            out.push_str("|---|---|---|---|---|---|---|---|---|---|\n");
            for requirement in &self.pool_runtime_input_requirements {
                out.push_str(&format!(
                    "| `{}` | `{}` | `{}` | `{}#{}` | `{}` | `{}` | `{}` | `{}` | {} | `{}` |\n",
                    escape_markdown_table_cell(&requirement.scope),
                    escape_markdown_table_cell(&requirement.feature),
                    escape_markdown_table_cell(&requirement.component),
                    escape_markdown_table_cell(&requirement.source),
                    requirement.index,
                    escape_markdown_table_cell(&requirement.binding),
                    escape_markdown_table_cell(requirement.field.as_deref().unwrap_or("")),
                    escape_markdown_table_cell(&requirement.abi),
                    requirement.byte_len,
                    escape_markdown_table_cell(requirement.blocker.as_deref().unwrap_or("")),
                    escape_markdown_table_cell(requirement.blocker_class.as_deref().unwrap_or(""))
                ));
            }
            out.push('\n');
        }

        out.push_str("### Transaction Invariant Checked Subconditions\n\n");
        if self.transaction_invariant_checked_subconditions.is_empty() {
            out.push_str("_No transaction invariant checked subconditions emitted._\n\n");
        } else {
            out.push_str("| Scope | Feature | Status | Checked Subconditions | Detail |\n");
            out.push_str("|---|---|---|---|---|\n");
            for subcondition in &self.transaction_invariant_checked_subconditions {
                out.push_str(&format!(
                    "| `{}` | `{}` | `{}` | {} | {} |\n",
                    escape_markdown_table_cell(&subcondition.scope),
                    escape_markdown_table_cell(&subcondition.feature),
                    escape_markdown_table_cell(&subcondition.status),
                    escape_markdown_table_cell(&comma_or_none(&subcondition.checked_subconditions)),
                    escape_markdown_table_cell(&subcondition.detail)
                ));
            }
            out.push('\n');
        }

        out.push_str("### Transaction Runtime Input Requirements\n\n");
        if self.transaction_runtime_input_requirements.is_empty() {
            out.push_str("_No transaction runtime input requirements emitted._\n\n");
        } else {
            out.push_str(
                "| Scope | Feature | Status | Component | Source | Binding | Field | ABI | Bytes | Blocker | Blocker Class |\n",
            );
            out.push_str("|---|---|---|---|---|---|---|---|---|---|---|\n");
            for requirement in &self.transaction_runtime_input_requirements {
                out.push_str(&format!(
                    "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | {} | {} |\n",
                    escape_markdown_table_cell(&requirement.scope),
                    escape_markdown_table_cell(&requirement.feature),
                    escape_markdown_table_cell(&requirement.status),
                    escape_markdown_table_cell(&requirement.component),
                    escape_markdown_table_cell(&requirement.source),
                    escape_markdown_table_cell(&requirement.binding),
                    escape_markdown_table_cell(requirement.field.as_deref().unwrap_or("")),
                    escape_markdown_table_cell(&requirement.abi),
                    requirement.byte_len.map(|byte_len| byte_len.to_string()).unwrap_or_default(),
                    escape_markdown_table_cell(requirement.blocker.as_deref().unwrap_or("")),
                    escape_markdown_table_cell(requirement.blocker_class.as_deref().unwrap_or(""))
                ));
            }
            out.push('\n');
        }

        out.push_str("### Verifier Obligations\n\n");
        if self.verifier_obligations.is_empty() {
            out.push_str("_No verifier obligations emitted._\n\n");
            return out;
        }

        out.push_str("| Scope | Category | Feature | Status | Detail |\n");
        out.push_str("|---|---|---|---|---|\n");
        for obligation in &self.verifier_obligations {
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | `{}` | {} |\n",
                escape_markdown_table_cell(&obligation.scope),
                escape_markdown_table_cell(&obligation.category),
                escape_markdown_table_cell(&obligation.feature),
                escape_markdown_table_cell(&obligation.status),
                escape_markdown_table_cell(&obligation.detail)
            ));
        }
        out.push('\n');
        out
    }

    fn generate_html(&self) -> String {
        let mut out = String::new();
        out.push_str("<section><h2>Lowering Audit Report</h2>");
        out.push_str("<ul>");
        out.push_str(&format!("<li>Metadata schema version: <code>{}</code></li>", self.metadata_schema_version));
        out.push_str(&format!("<li>Compiler version: <code>{}</code></li>", escape_html(&self.compiler_version)));
        out.push_str(&format!("<li>Module: <code>{}</code></li>", escape_html(&self.module)));
        out.push_str(&format!("<li>Artifact format: <code>{}</code></li>", escape_html(&self.artifact_format)));
        out.push_str(&format!("<li>Target profile: <code>{}</code></li>", escape_html(&self.target_profile)));
        out.push_str(&format!("<li>Target chain: <code>{}</code></li>", escape_html(&self.target_chain)));
        out.push_str(&format!("<li>Target hash domain: <code>{}</code></li>", escape_html(&self.target_hash_domain)));
        out.push_str(&format!("<li>Target syscall set: <code>{}</code></li>", escape_html(&self.target_syscall_set)));
        out.push_str(&format!("<li>Target artifact packaging: <code>{}</code></li>", escape_html(&self.target_artifact_packaging)));
        out.push_str(&format!("<li>Target header ABI: <code>{}</code></li>", escape_html(&self.target_header_abi)));
        out.push_str(&format!("<li>Target scheduler ABI: <code>{}</code></li>", escape_html(&self.target_scheduler_abi)));
        if let Some(hash) = &self.artifact_hash {
            out.push_str(&format!("<li>Artifact hash (CKB Blake2b): <code>{}</code></li>", escape_html(hash)));
        }
        if let Some(size) = self.artifact_size_bytes {
            out.push_str(&format!("<li>Artifact size: <code>{}</code> bytes</li>", size));
        }
        if let Some(hash) = &self.source_hash {
            out.push_str(&format!("<li>Source set hash (CKB Blake2b): <code>{}</code></li>", escape_html(hash)));
        }
        if let Some(hash) = &self.source_content_hash {
            out.push_str(&format!("<li>Source content hash (CKB Blake2b): <code>{}</code></li>", escape_html(hash)));
        }
        out.push_str(&format!(
            "<li>VM ABI: <code>{}</code> (<code>0x{:04x}</code>)</li>",
            escape_html(&self.vm_abi_format),
            self.vm_abi_version
        ));
        out.push_str(&format!("<li>VM ABI embedded in artifact: <code>{}</code></li>", self.vm_abi_embedded_in_artifact));
        out.push_str(&format!("<li>VM ABI scope: <code>{}</code></li>", escape_html(&self.vm_abi_scope)));
        out.push_str(&format!("<li>CKB runtime required: <code>{}</code></li>", self.ckb_runtime_required));
        out.push_str(&format!("<li>Standalone runner compatible: <code>{}</code></li>", self.standalone_runner_compatible));
        out.push_str(&format!(
            "<li>CKB runtime features: <code>{}</code></li>",
            escape_html(&comma_or_none(&self.ckb_runtime_features))
        ));
        out.push_str(&format!(
            "<li>Fail-closed runtime features: <code>{}</code></li>",
            escape_html(&comma_or_none(&self.fail_closed_runtime_features))
        ));
        out.push_str("</ul>");
        if !self.source_units.is_empty() {
            out.push_str("<h3>Source Units</h3>");
            out.push_str("<table><thead><tr><th>Role</th><th>Path</th><th>Hash</th><th>Size</th></tr></thead><tbody>");
            for unit in &self.source_units {
                out.push_str(&format!(
                    "<tr><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code> bytes</td></tr>",
                    escape_html(&unit.role),
                    escape_html(&unit.path),
                    escape_html(&unit.hash),
                    unit.size_bytes
                ));
            }
            out.push_str("</tbody></table>");
        }
        out.push_str("<h3>Pool Pattern Metadata</h3>");
        if self.pool_primitives.is_empty() {
            out.push_str("<p><em>No pool pattern metadata emitted.</em></p>");
        } else {
            out.push_str(
                "<table><thead><tr><th>Scope</th><th>Operation</th><th>Feature</th><th>Status</th><th>Invariant Families</th><th>Checked Components</th><th>Runtime Required</th><th>Runtime Input Requirements</th></tr></thead><tbody>",
            );
            for primitive in &self.pool_primitives {
                out.push_str(&format!(
                    "<tr><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    escape_html(&primitive.scope),
                    escape_html(&primitive.operation),
                    escape_html(&primitive.feature),
                    escape_html(&primitive.status),
                    escape_html(&pool_invariant_list(&primitive.invariant_families)),
                    escape_html(&comma_or_none(&primitive.checked_components)),
                    escape_html(&comma_or_none(&primitive.runtime_required_components)),
                    escape_html(&pool_runtime_input_requirement_list(&primitive.runtime_input_requirements))
                ));
            }
            out.push_str("</tbody></table>");
        }
        out.push_str("<h3>Pool Runtime Input Requirements</h3>");
        if self.pool_runtime_input_requirements.is_empty() {
            out.push_str("<p><em>No pool runtime input requirements emitted.</em></p>");
        } else {
            out.push_str(
                "<table><thead><tr><th>Scope</th><th>Feature</th><th>Component</th><th>Source</th><th>Binding</th><th>Field</th><th>ABI</th><th>Bytes</th><th>Blocker</th><th>Blocker Class</th></tr></thead><tbody>",
            );
            for requirement in &self.pool_runtime_input_requirements {
                out.push_str(&format!(
                    "<tr><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}#{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td><code>{}</code></td></tr>",
                    escape_html(&requirement.scope),
                    escape_html(&requirement.feature),
                    escape_html(&requirement.component),
                    escape_html(&requirement.source),
                    requirement.index,
                    escape_html(&requirement.binding),
                    escape_html(requirement.field.as_deref().unwrap_or("")),
                    escape_html(&requirement.abi),
                    requirement.byte_len,
                    escape_html(requirement.blocker.as_deref().unwrap_or("")),
                    escape_html(requirement.blocker_class.as_deref().unwrap_or(""))
                ));
            }
            out.push_str("</tbody></table>");
        }
        out.push_str("<h3>Transaction Invariant Checked Subconditions</h3>");
        if self.transaction_invariant_checked_subconditions.is_empty() {
            out.push_str("<p><em>No transaction invariant checked subconditions emitted.</em></p>");
        } else {
            out.push_str(
                "<table><thead><tr><th>Scope</th><th>Feature</th><th>Status</th><th>Checked Subconditions</th><th>Detail</th></tr></thead><tbody>",
            );
            for subcondition in &self.transaction_invariant_checked_subconditions {
                out.push_str(&format!(
                    "<tr><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                    escape_html(&subcondition.scope),
                    escape_html(&subcondition.feature),
                    escape_html(&subcondition.status),
                    escape_html(&comma_or_none(&subcondition.checked_subconditions)),
                    escape_html(&subcondition.detail)
                ));
            }
            out.push_str("</tbody></table>");
        }
        out.push_str("<h3>Transaction Runtime Input Requirements</h3>");
        if self.transaction_runtime_input_requirements.is_empty() {
            out.push_str("<p><em>No transaction runtime input requirements emitted.</em></p>");
        } else {
            out.push_str(
                "<table><thead><tr><th>Scope</th><th>Feature</th><th>Status</th><th>Component</th><th>Source</th><th>Binding</th><th>Field</th><th>ABI</th><th>Bytes</th><th>Blocker</th><th>Blocker Class</th></tr></thead><tbody>",
            );
            for requirement in &self.transaction_runtime_input_requirements {
                out.push_str(&format!(
                    "<tr><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                    escape_html(&requirement.scope),
                    escape_html(&requirement.feature),
                    escape_html(&requirement.status),
                    escape_html(&requirement.component),
                    escape_html(&requirement.source),
                    escape_html(&requirement.binding),
                    escape_html(requirement.field.as_deref().unwrap_or("")),
                    escape_html(&requirement.abi),
                    requirement.byte_len.map(|byte_len| byte_len.to_string()).unwrap_or_default(),
                    escape_html(requirement.blocker.as_deref().unwrap_or("")),
                    escape_html(requirement.blocker_class.as_deref().unwrap_or(""))
                ));
            }
            out.push_str("</tbody></table>");
        }
        out.push_str("<h3>Verifier Obligations</h3>");
        if self.verifier_obligations.is_empty() {
            out.push_str("<p><em>No verifier obligations emitted.</em></p></section>");
            return out;
        }
        out.push_str(
            "<table><thead><tr><th>Scope</th><th>Category</th><th>Feature</th><th>Status</th><th>Detail</th></tr></thead><tbody>",
        );
        for obligation in &self.verifier_obligations {
            out.push_str(&format!(
                "<tr><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>",
                escape_html(&obligation.scope),
                escape_html(&obligation.category),
                escape_html(&obligation.feature),
                escape_html(&obligation.status),
                escape_html(&obligation.detail)
            ));
        }
        out.push_str("</tbody></table></section>");
        out
    }
}

fn comma_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
}

fn pool_invariant_list(invariants: &[PoolInvariantMetadata]) -> String {
    if invariants.is_empty() {
        "none".to_string()
    } else {
        invariants
            .iter()
            .map(|invariant| {
                let blocker = invariant.blocker.as_deref().map(|blocker| format!(" blocker={}", blocker)).unwrap_or_default();
                let blocker_class =
                    invariant.blocker_class.as_deref().map(|class| format!(" blocker_class={}", class)).unwrap_or_default();
                format!("{}={} ({}){}{}", invariant.name, invariant.status, invariant.source, blocker, blocker_class)
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn pool_runtime_input_requirement_docs(primitives: &[PoolPrimitiveMetadata]) -> Vec<AuditPoolRuntimeInputRequirementDoc> {
    primitives
        .iter()
        .flat_map(|primitive| {
            primitive.runtime_input_requirements.iter().map(move |requirement| AuditPoolRuntimeInputRequirementDoc {
                scope: primitive.scope.clone(),
                feature: primitive.feature.clone(),
                component: requirement.component.clone(),
                source: requirement.source.clone(),
                index: requirement.index,
                binding: requirement.binding.clone(),
                field: requirement.field.clone(),
                abi: requirement.abi.clone(),
                byte_len: requirement.byte_len,
                blocker: requirement.blocker.clone(),
                blocker_class: requirement.blocker_class.clone(),
            })
        })
        .collect()
}

fn transaction_invariant_checked_subcondition_docs(
    obligations: &[VerifierObligationMetadata],
) -> Vec<AuditTransactionInvariantSubconditionDoc> {
    obligations
        .iter()
        .filter(|obligation| obligation.category == "transaction-invariant" && obligation.status == "runtime-required")
        .filter_map(|obligation| {
            let checked_subconditions = checked_runtime_subconditions(&obligation.detail);
            if checked_subconditions.is_empty() {
                None
            } else {
                Some(AuditTransactionInvariantSubconditionDoc {
                    scope: obligation.scope.clone(),
                    feature: obligation.feature.clone(),
                    status: obligation.status.clone(),
                    checked_subconditions,
                    detail: obligation.detail.clone(),
                })
            }
        })
        .collect()
}

fn checked_runtime_subconditions(detail: &str) -> Vec<String> {
    detail
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .filter_map(|part| part.trim().strip_suffix("=checked-runtime"))
        .map(|name| name.trim_matches(|ch: char| ch == '`' || ch == '.' || ch == ':').to_string())
        .filter(|name| !name.is_empty())
        .collect()
}

fn pool_runtime_input_requirement_list(requirements: &[PoolRuntimeInputRequirementMetadata]) -> String {
    if requirements.is_empty() {
        "none".to_string()
    } else {
        requirements
            .iter()
            .map(|requirement| {
                let field = requirement.field.as_deref().map(|field| format!(".{}", field)).unwrap_or_default();
                let blocker = requirement.blocker.as_deref().map(|blocker| format!(" blocker={}", blocker)).unwrap_or_default();
                let blocker_class =
                    requirement.blocker_class.as_deref().map(|class| format!(" blocker_class={}", class)).unwrap_or_default();
                format!(
                    "{}={}#{}:{}{}:{}[{}]{}{}",
                    requirement.component,
                    requirement.source,
                    requirement.index,
                    requirement.binding,
                    field,
                    requirement.abi,
                    requirement.byte_len,
                    blocker,
                    blocker_class
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn escape_markdown_table_cell(input: &str) -> String {
    input.replace('|', "\\|").replace('\n', " ")
}

fn item_doc(item: &Item) -> Option<ItemDoc> {
    match item {
        Item::Use(_) => None,
        Item::Resource(resource) => Some(ItemDoc {
            kind: "resource".to_string(),
            name: resource.name.clone(),
            signature: format!("resource {}{}", resource.name, format_capability_clause(&resource.capabilities)),
            summary: format!("Fields: {}", format_fields(&resource.fields)),
        }),
        Item::Shared(shared) => Some(ItemDoc {
            kind: "shared".to_string(),
            name: shared.name.clone(),
            signature: format!("shared {}{}", shared.name, format_capability_clause(&shared.capabilities)),
            summary: format!("Fields: {}", format_fields(&shared.fields)),
        }),
        Item::Receipt(receipt) => {
            let mut summary = String::new();
            if let Some(output) = &receipt.claim_output {
                summary.push_str(&format!("Claim output: {}. ", format_type(output)));
            }
            if let Some(lifecycle) = &receipt.lifecycle {
                summary.push_str(&format!("Lifecycle: {}. ", lifecycle.states.join(" -> ")));
                let transitions =
                    lifecycle.states.windows(2).map(|window| format!("{} -> {}", window[0], window[1])).collect::<Vec<_>>();
                if !transitions.is_empty() {
                    summary.push_str(&format!("Transitions: {}. ", transitions.join(", ")));
                }
            }
            summary.push_str(&format!("Fields: {}", format_fields(&receipt.fields)));
            Some(ItemDoc {
                kind: "receipt".to_string(),
                name: receipt.name.clone(),
                signature: format!(
                    "receipt {}{}{}",
                    receipt.name,
                    receipt.claim_output.as_ref().map(|ty| format!(" -> {}", format_type(ty))).unwrap_or_default(),
                    format_capability_clause(&receipt.capabilities)
                ),
                summary,
            })
        }
        Item::Struct(struct_def) => Some(ItemDoc {
            kind: "struct".to_string(),
            name: struct_def.name.clone(),
            signature: format!("struct {}", struct_def.name),
            summary: format!("Fields: {}", format_fields(&struct_def.fields)),
        }),
        Item::Const(constant) => Some(ItemDoc {
            kind: "const".to_string(),
            name: constant.name.clone(),
            signature: format!("const {}: {}", constant.name, format_type(&constant.ty)),
            summary: String::new(),
        }),
        Item::Enum(enum_def) => Some(ItemDoc {
            kind: "enum".to_string(),
            name: enum_def.name.clone(),
            signature: format!(
                "enum {} {{ {} }}",
                enum_def.name,
                enum_def
                    .variants
                    .iter()
                    .map(|variant| {
                        if variant.fields.is_empty() {
                            variant.name.clone()
                        } else {
                            format!("{}({})", variant.name, variant.fields.iter().map(format_type).collect::<Vec<_>>().join(", "))
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            summary: String::new(),
        }),
        Item::Action(action) => Some(ItemDoc {
            kind: "action".to_string(),
            name: action.name.clone(),
            signature: action_signature("action", action),
            summary: action.doc_comment.clone().unwrap_or_else(|| format!("Effect: {}.", format_effect(action.effect))),
        }),
        Item::Function(function) => Some(ItemDoc {
            kind: "fn".to_string(),
            name: function.name.clone(),
            signature: function_signature(function),
            summary: function.doc_comment.clone().unwrap_or_else(|| "Pure helper function.".to_string()),
        }),
        Item::Lock(lock) => Some(ItemDoc {
            kind: "lock".to_string(),
            name: lock.name.clone(),
            signature: format!(
                "lock {}({}) -> {}",
                lock.name,
                lock.params.iter().map(format_param).collect::<Vec<_>>().join(", "),
                format_type(&lock.return_type)
            ),
            summary: "Lock predicate; current compiler treats lock bodies as explicit validation logic.".to_string(),
        }),
    }
}

fn action_signature(keyword: &str, action: &ActionDef) -> String {
    let params = action.params.iter().map(format_param).collect::<Vec<_>>().join(", ");
    let mut signature = format!("{} {}({})", keyword, action.name, params);
    if let Some(return_type) = &action.return_type {
        signature.push_str(&format!(" -> {}", format_type(return_type)));
    }
    signature
}

fn function_signature(function: &FnDef) -> String {
    let params = function.params.iter().map(format_param).collect::<Vec<_>>().join(", ");
    let mut signature = format!("fn {}({})", function.name, params);
    if let Some(return_type) = &function.return_type {
        signature.push_str(&format!(" -> {}", format_type(return_type)));
    }
    signature
}

fn format_fields(fields: &[Field]) -> String {
    if fields.is_empty() {
        return "none".to_string();
    }
    fields.iter().map(|field| format!("{}: {}", field.name, format_type(&field.ty))).collect::<Vec<_>>().join(", ")
}

fn format_capability_clause(capabilities: &[Capability]) -> String {
    if capabilities.is_empty() {
        String::new()
    } else {
        format!(" has {}", capabilities.iter().map(format_capability).collect::<Vec<_>>().join(", "))
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
    if param.is_read_ref {
        rendered.push_str("read_ref ");
        let ty = match &param.ty {
            Type::Ref(inner) => inner.as_ref(),
            other => other,
        };
        rendered.push_str(&format_type(ty));
    } else {
        rendered.push_str(&format_type(&param.ty));
    }
    rendered
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

fn escape_html(input: &str) -> String {
    input.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

/// Extract a documentable name from an AST item for cross-reference indexing.
fn item_name_for_xref(item: &Item) -> Option<String> {
    match item {
        Item::Resource(r) => Some(r.name.clone()),
        Item::Shared(s) => Some(s.name.clone()),
        Item::Receipt(r) => Some(r.name.clone()),
        Item::Struct(s) => Some(s.name.clone()),
        Item::Enum(e) => Some(e.name.clone()),
        Item::Action(a) => Some(a.name.clone()),
        Item::Function(f) => Some(f.name.clone()),
        Item::Lock(l) => Some(l.name.clone()),
        Item::Const(c) => Some(c.name.clone()),
        Item::Use(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{lexer, parser};

    #[test]
    fn docgen_emits_markdown_for_action() {
        let source = r#"
module demo

/// adds two numbers
action add(x: u64, y: u64) -> u64 {
    return x + y
}
"#;
        let tokens = lexer::lex(source).unwrap();
        let module = parser::parse(&tokens).unwrap();

        let mut generator = DocGenerator::new(OutputFormat::Markdown);
        generator.add_module(&module);
        let docs = generator.generate().unwrap();

        assert!(docs.contains("## Module `demo`"));
        assert!(docs.contains("### action `add`"));
        assert!(docs.contains("action add(x: u64, y: u64) -> u64"));
    }

    #[test]
    fn docgen_html_escapes_module_and_item_text() {
        let generator = DocGenerator {
            modules: vec![ModuleDoc {
                name: "demo::<script>alert(1)</script>".to_string(),
                items: vec![ItemDoc {
                    kind: "action".to_string(),
                    name: "mint<script>".to_string(),
                    signature: "action mint<script>() -> u64".to_string(),
                    summary: "docs <b>must</b> be inert & quoted".to_string(),
                }],
            }],
            audit: None,
            format: OutputFormat::Html,
            type_index: HashMap::new(),
        };

        let docs = generator.generate().unwrap();

        assert!(docs.contains("demo::&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(docs.contains("mint&lt;script&gt;"));
        assert!(docs.contains("action mint&lt;script&gt;() -&gt; u64"));
        assert!(docs.contains("docs &lt;b&gt;must&lt;/b&gt; be inert &amp; quoted"));
        assert!(!docs.contains("<script>alert(1)</script>"));
        assert!(!docs.contains("<b>must</b>"));
    }

    #[test]
    fn docgen_emits_flat_pool_runtime_input_requirements() {
        let primitive = PoolPrimitiveMetadata {
            scope: "action:launch_token".to_string(),
            operation: "composition".to_string(),
            feature: "pool-composition:Pool".to_string(),
            ty: "Pool".to_string(),
            status: "runtime-required".to_string(),
            source: "call-return".to_string(),
            checked_components: Vec::new(),
            runtime_required_components: vec!["pool-id-continuity".to_string()],
            runtime_input_requirements: vec![PoolRuntimeInputRequirementMetadata {
                component: "pool-id-continuity".to_string(),
                source: "CallReturn".to_string(),
                index: 1,
                binding: "call_tmp".to_string(),
                field: Some("1.pool_id".to_string()),
                abi: "tuple-call-return-field-hash-32".to_string(),
                byte_len: 32,
                blocker: Some("deferred beyond Phase 2 controlled-flow boundary".to_string()),
                blocker_class: Some("phase2-deferred-pool-id-continuity".to_string()),
            }],
            invariant_families: Vec::new(),
            source_invariant_count: 0,
            binding: Some("call_tmp".to_string()),
            callee: Some("seed_pool".to_string()),
            input_source: None,
            input_index: None,
            output_source: None,
            output_index: None,
            transition_fields: Vec::new(),
            preserved_fields: Vec::new(),
        };

        let mut generator = DocGenerator::new(OutputFormat::Markdown);
        generator.audit = Some(AuditDoc {
            metadata_schema_version: crate::METADATA_SCHEMA_VERSION,
            compiler_version: "test".to_string(),
            module: "demo".to_string(),
            artifact_format: "RISC-V assembly".to_string(),
            artifact_hash: None,
            artifact_size_bytes: None,
            source_hash: None,
            source_content_hash: None,
            source_units: Vec::new(),
            target_profile: "ckb".to_string(),
            target_chain: "ckb".to_string(),
            target_hash_domain: "ckb-packed-molecule-blake2b".to_string(),
            target_syscall_set: "ckb-mainnet-syscalls".to_string(),
            target_artifact_packaging: "ckb-asm-sidecar".to_string(),
            target_header_abi: "ckb-header".to_string(),
            target_scheduler_abi: "none".to_string(),
            vm_abi_format: "molecule".to_string(),
            vm_abi_version: 0x8001,
            vm_abi_embedded_in_artifact: false,
            vm_abi_scope: "metadata".to_string(),
            ckb_runtime_required: false,
            standalone_runner_compatible: false,
            ckb_runtime_features: Vec::new(),
            fail_closed_runtime_features: Vec::new(),
            verifier_obligations: Vec::new(),
            transaction_invariant_checked_subconditions: Vec::new(),
            transaction_runtime_input_requirements: Vec::new(),
            pool_primitives: vec![primitive.clone()],
            pool_runtime_input_requirements: pool_runtime_input_requirement_docs(&[primitive]),
        });

        let docs = generator.generate().unwrap();
        assert!(docs.contains("### Pool Runtime Input Requirements"));
        assert!(docs.contains("`CallReturn#1`"));
        assert!(docs.contains("`call_tmp`"));
        assert!(docs.contains("`1.pool_id`"));
        assert!(docs.contains("`tuple-call-return-field-hash-32`"));
        assert!(docs.contains("phase2-deferred-pool-id-continuity"));
    }

    #[test]
    fn docgen_emits_transaction_invariant_checked_subconditions() {
        let obligation = crate::VerifierObligationMetadata {
            scope: "action:claim_vested".to_string(),
            category: "transaction-invariant".to_string(),
            feature: "claim-conditions:VestingGrant".to_string(),
            status: "runtime-required".to_string(),
            detail: "Source claim predicates are present as timepoint-check=checked-runtime, state-not-fully-claimed=checked-runtime, positive-claimable=checked-runtime, claim-witness-format=checked-runtime, claim-authorization-domain=checked-runtime; signature verification remains runtime-required".to_string(),
        };

        let mut generator = DocGenerator::new(OutputFormat::Markdown);
        generator.audit = Some(AuditDoc {
            metadata_schema_version: crate::METADATA_SCHEMA_VERSION,
            compiler_version: "test".to_string(),
            module: "demo".to_string(),
            artifact_format: "RISC-V assembly".to_string(),
            artifact_hash: None,
            artifact_size_bytes: None,
            source_hash: None,
            source_content_hash: None,
            source_units: Vec::new(),
            target_profile: "ckb".to_string(),
            target_chain: "ckb".to_string(),
            target_hash_domain: "ckb-packed-molecule-blake2b".to_string(),
            target_syscall_set: "ckb-mainnet-syscalls".to_string(),
            target_artifact_packaging: "ckb-asm-sidecar".to_string(),
            target_header_abi: "ckb-header".to_string(),
            target_scheduler_abi: "none".to_string(),
            vm_abi_format: "molecule".to_string(),
            vm_abi_version: 0x8001,
            vm_abi_embedded_in_artifact: false,
            vm_abi_scope: "metadata".to_string(),
            ckb_runtime_required: false,
            standalone_runner_compatible: false,
            ckb_runtime_features: Vec::new(),
            fail_closed_runtime_features: Vec::new(),
            verifier_obligations: vec![AuditObligationDoc {
                scope: obligation.scope.clone(),
                category: obligation.category.clone(),
                feature: obligation.feature.clone(),
                status: obligation.status.clone(),
                detail: obligation.detail.clone(),
            }],
            transaction_invariant_checked_subconditions: transaction_invariant_checked_subcondition_docs(&[obligation]),
            transaction_runtime_input_requirements: vec![TransactionRuntimeInputRequirementMetadata {
                scope: "action:claim_vested".to_string(),
                feature: "claim-conditions:VestingGrant".to_string(),
                status: "runtime-required".to_string(),
                component: "claim-witness-signature".to_string(),
                source: "Witness".to_string(),
                binding: "VestingGrant".to_string(),
                field: Some("signature".to_string()),
                abi: "claim-witness-signature-65".to_string(),
                byte_len: Some(65),
                blocker: Some(
                    "claim lowering checks witness shape but has no verifier-coverable signer key binding or secp256k1 verification call"
                        .to_string(),
                ),
                blocker_class: Some("witness-verification-gap".to_string()),
            }],
            pool_primitives: Vec::new(),
            pool_runtime_input_requirements: Vec::new(),
        });

        let docs = generator.generate().unwrap();
        assert!(docs.contains("### Transaction Invariant Checked Subconditions"));
        assert!(docs.contains("### Transaction Runtime Input Requirements"));
        assert!(docs
            .contains("| Scope | Feature | Status | Component | Source | Binding | Field | ABI | Bytes | Blocker | Blocker Class |"));
        assert!(docs.contains("`claim-conditions:VestingGrant`"));
        assert!(docs.contains("`runtime-required`"));
        assert!(docs.contains(
            "claim lowering checks witness shape but has no verifier-coverable signer key binding or secp256k1 verification call"
        ));
        assert!(docs.contains("witness-verification-gap"));
        assert!(docs.contains("timepoint-check"));
        assert!(docs.contains("state-not-fully-claimed"));
        assert!(docs.contains("positive-claimable"));
        assert!(docs.contains("claim-witness-format"));
        assert!(docs.contains("claim-authorization-domain"));
        assert!(docs.contains("`claim-witness-signature-65`"));
        assert!(docs.contains("signature verification remains runtime-required"));
    }
}
