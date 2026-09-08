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
            if let Some(name) = item.name() {
                match module.visibility_of(name) {
                    Visibility::LegacyPublic => {}
                    Visibility::Public => self.output.push_str("public "),
                    Visibility::Package => self.output.push_str("public(package) "),
                    Visibility::Private => self.output.push_str("private "),
                }
            }
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
                self.format_type_id_attr(resource.type_id.as_ref());
                self.format_type_def(
                    "resource",
                    &resource.name,
                    &resource.fields,
                    Some(&resource.capabilities),
                    None,
                    Some(&resource.identity),
                    resource.default_hash_type.as_ref(),
                    resource.capacity_floor.as_ref(),
                    resource.validity.as_ref(),
                )
            }
            Item::Shared(shared) => {
                self.format_type_id_attr(shared.type_id.as_ref());
                self.format_type_def(
                    "shared",
                    &shared.name,
                    &shared.fields,
                    Some(&shared.capabilities),
                    None,
                    Some(&shared.identity),
                    shared.default_hash_type.as_ref(),
                    shared.capacity_floor.as_ref(),
                    shared.validity.as_ref(),
                )
            }
            Item::Receipt(receipt) => {
                self.format_type_id_attr(receipt.type_id.as_ref());
                self.format_receipt_def(receipt)
            }
            Item::Struct(struct_def) => {
                self.format_type_id_attr(struct_def.type_id.as_ref());
                let name = format!("{}{}", struct_def.name, format_type_params(&struct_def.type_params));
                let derived = crate::generics::derive_template_value_abilities(
                    &struct_def.type_params,
                    struct_def.fields.iter().map(|field| &field.ty),
                );
                let abilities = if !struct_def.type_params.is_empty() && struct_def.abilities == derived {
                    &[][..]
                } else {
                    struct_def.abilities.as_slice()
                };
                self.format_type_def(
                    "struct",
                    &name,
                    &struct_def.fields,
                    None,
                    Some(abilities),
                    None,
                    struct_def.default_hash_type.as_ref(),
                    struct_def.capacity_floor.as_ref(),
                    struct_def.validity.as_ref(),
                )
            }
            Item::Flow(machine) => self.format_flow(machine),
            Item::Invariant(invariant) => self.format_invariant(invariant),
            Item::Const(constant) => {
                self.push_line(&format!(
                    "const {}: {} = {}",
                    constant.name,
                    format_type(&constant.ty),
                    self.format_expr(&constant.value)
                ));
                Ok(())
            }
            Item::Enum(enum_def) => {
                let mut header = format!("enum {}{}", enum_def.name, format_type_params(&enum_def.type_params));
                let derived = crate::generics::derive_template_value_abilities(
                    &enum_def.type_params,
                    enum_def.variants.iter().flat_map(|variant| variant.fields.iter()),
                );
                if !enum_def.abilities.is_empty() && (enum_def.type_params.is_empty() || enum_def.abilities != derived) {
                    header.push_str(&format!(" has {}", format_value_abilities(&enum_def.abilities)));
                }
                self.push_line(&format!("{} {{", header));
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
            Item::Action(action) if action.next_surface.is_some() => self.format_next_type_script(action),
            Item::Action(action) => self.format_action_like("action", action),
            Item::Function(function) => self.format_function(function),
            Item::Lock(lock) if lock.next_surface.is_some() => self.format_next_lock_script(lock),
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

    fn format_flow(&mut self, machine: &FlowDef) -> Result<()> {
        let header = if let Some(name) = &machine.name {
            format!("flow {} for {}.{} {{", name, machine.target.base, machine.target.field)
        } else {
            format!("flow {}.{} {{", machine.target.base, machine.target.field)
        };
        self.push_line(&header);
        self.indent_level += 1;
        if !machine.initial_states.is_empty() {
            self.push_line(&format!("initial {};", machine.initial_states.join(", ")));
        }
        if !machine.terminal_states.is_empty() {
            self.push_line(&format!("terminal {};", machine.terminal_states.join(", ")));
        }
        if (!machine.initial_states.is_empty() || !machine.terminal_states.is_empty()) && !machine.transitions.is_empty() {
            self.push_line("");
        }
        for transition in &machine.transitions {
            let mut line = format!("{} -> {}", transition.from, transition.to);
            if let Some(action) = &transition.action {
                line.push_str(&format!(" by {}", action));
            }
            line.push(';');
            self.push_line(&line);
        }
        self.indent_level -= 1;
        self.push_line("}");
        Ok(())
    }

    fn format_type_id_attr(&mut self, type_id: Option<&TypeIdentity>) {
        if let Some(type_id) = type_id {
            self.push_line(&format!("#[type_id({:?})]", type_id.value));
        }
    }

    fn format_type_def(
        &mut self,
        keyword: &str,
        name: &str,
        fields: &[Field],
        capabilities: Option<&[Capability]>,
        value_abilities: Option<&[ValueAbility]>,
        identity: Option<&IdentityPolicy>,
        default_hash_type: Option<&HashTypeDecl>,
        capacity_floor: Option<&CapacityFloorDecl>,
        validity: Option<&ValidityBlock>,
    ) -> Result<()> {
        let mut header = format!("{} {}", keyword, name);
        if let Some(capabilities) = capabilities
            && !capabilities.is_empty()
        {
            let rendered = capabilities.iter().map(format_capability).collect::<Vec<_>>().join(", ");
            header.push_str(&format!(" has {}", rendered));
        }
        if let Some(abilities) = value_abilities
            && !abilities.is_empty()
        {
            header.push_str(&format!(" has {}", format_value_abilities(abilities)));
        }
        if has_type_policy(identity, default_hash_type, capacity_floor) {
            self.push_line(&header);
            self.format_type_policy(identity, default_hash_type, capacity_floor);
            self.push_line("{");
        } else {
            self.push_line(&format!("{} {{", header));
        }
        self.indent_level += 1;
        for field in fields {
            self.push_line(&format!("{}: {},", field.name, format_type(&field.ty)));
        }
        self.format_validity_block(validity);
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
        if has_type_policy(Some(&receipt.identity), receipt.default_hash_type.as_ref(), receipt.capacity_floor.as_ref()) {
            self.push_line(&header);
            self.format_type_policy(Some(&receipt.identity), receipt.default_hash_type.as_ref(), receipt.capacity_floor.as_ref());
            self.push_line("{");
        } else {
            self.push_line(&format!("{} {{", header));
        }
        self.indent_level += 1;
        for field in &receipt.fields {
            self.push_line(&format!("{}: {},", field.name, format_type(&field.ty)));
        }
        self.format_validity_block(receipt.validity.as_ref());
        self.indent_level -= 1;
        self.push_line("}");
        Ok(())
    }

    fn format_validity_block(&mut self, validity: Option<&ValidityBlock>) {
        let Some(validity) = validity else {
            return;
        };
        self.push_line("");
        self.push_line("validity");
        self.indent_level += 1;
        for predicate in &validity.predicates {
            self.push_line(&self.format_expr(predicate));
        }
        self.indent_level -= 1;
    }

    fn format_type_policy(
        &mut self,
        identity: Option<&IdentityPolicy>,
        default_hash_type: Option<&HashTypeDecl>,
        capacity_floor: Option<&CapacityFloorDecl>,
    ) {
        if let Some(default_hash_type) = default_hash_type {
            self.push_line(&format!("with_default_hash_type({})", default_hash_type.value));
        }
        if let Some(capacity_floor) = capacity_floor {
            self.push_line(&format!("with_capacity_floor({})", capacity_floor.shannons));
        }
        if let Some(identity) = identity
            && !matches!(identity, IdentityPolicy::None)
        {
            self.push_line(&format!("identity({})", format_identity_policy(identity)));
        }
    }

    fn format_invariant(&mut self, invariant: &InvariantDef) -> Result<()> {
        self.push_line(&format!("invariant {} {{", invariant.name));
        self.indent_level += 1;
        if let Some(trigger) = &invariant.trigger {
            self.push_line(&format!("trigger: {}", trigger));
        }
        if let Some(scope) = &invariant.scope {
            self.push_line(&format!("scope: {}", scope));
        }
        if !invariant.reads.is_empty() {
            self.push_line(&format!("reads: {}", invariant.reads.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")));
        }
        for aggregate in &invariant.aggregates {
            self.push_line(&format_aggregate_invariant(aggregate));
        }
        for quantifier in &invariant.quantifiers {
            match quantifier.kind {
                BoundedQuantifierKind::ForAll => {
                    self.push_line(&format!(
                        "forall {} {} in {} {{",
                        quantifier.role.as_deref().unwrap_or("item"),
                        quantifier.binding.as_deref().unwrap_or("value"),
                        quantifier.range
                    ));
                    self.indent_level += 1;
                    for predicate in &quantifier.predicates {
                        self.push_line(&self.format_expr(predicate));
                    }
                    self.indent_level -= 1;
                    self.push_line("}");
                }
                BoundedQuantifierKind::Count => self.push_line(&format!(
                    "count({} where {}) {} {}",
                    quantifier.range,
                    quantifier.predicates.first().map(|predicate| self.format_expr(predicate)).unwrap_or_else(|| "false".to_string()),
                    quantifier.relation.map(format_aggregate_relation).unwrap_or("?"),
                    quantifier.expected.as_ref().map(|expected| self.format_expr(expected)).unwrap_or_else(|| "0".to_string())
                )),
            }
        }
        for expr in &invariant.asserts {
            self.push_line(&self.format_expr(expr));
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
        if !action.outputs.is_empty() {
            signature.push_str(&format!(" -> {}", format_action_outputs(&action.outputs)));
        } else if let Some(return_type) = &action.return_type {
            signature.push_str(&format!(" -> {}", format_type(return_type)));
        }
        self.push_line(&format!("{} {{", signature));
        self.indent_level += 1;
        for state_edge in &action.state_edges {
            self.push_line(&format_action_state_edge("transition ", state_edge));
        }
        if !action.state_edges.is_empty() && !action.body.is_empty() {
            self.push_line("");
        }
        self.push_line("verification");
        self.indent_level += 1;
        for stmt in &action.body {
            self.format_stmt(stmt);
        }
        self.indent_level -= 1;
        self.indent_level -= 1;
        self.push_line("}");
        Ok(())
    }

    fn format_next_type_script(&mut self, action: &ActionDef) -> Result<()> {
        let surface = action.next_surface.as_ref().expect("guarded by format_item");
        self.push_line(&format!("type_script {} on type_group<{}> {{", surface.container_name, surface.trigger_type));
        self.indent_level += 1;
        self.push_line(&format!("entry {}(", action.name));
        self.indent_level += 1;
        let mut input_ordinal = 0usize;
        for param in &action.params {
            let source = match param.source {
                ParamSource::Input => {
                    let source = format!("group_input[{input_ordinal}]");
                    input_ordinal += 1;
                    source
                }
                ParamSource::Witness => "group_witness.input_type".to_string(),
                ParamSource::Protected => "lock_group.input".to_string(),
                ParamSource::LockArgs => "script.args".to_string(),
                ParamSource::Default | ParamSource::Output => "unresolved".to_string(),
            };
            self.push_line(&format!(
                "{} {}: {} from {},",
                format_param_source(param.source),
                param.name,
                format_type(&param.ty),
                source
            ));
        }
        for (ordinal, output) in action.outputs.iter().enumerate() {
            self.push_line(&format!("output {}: {} from group_output[{}],", output.name, format_type(&output.ty), ordinal));
        }
        self.indent_level -= 1;
        self.push_line(") {");
        self.indent_level += 1;
        self.push_line("verify {");
        self.indent_level += 1;
        for expression in &surface.verify {
            self.push_line(&format!("enforce {}", self.format_expr(expression)));
        }
        self.indent_level -= 1;
        self.push_line("}");
        for audit in &surface.audits {
            self.push_line("");
            self.push_line(&format!("audit {} {{", audit.name));
            self.indent_level += 1;
            let evidence = match audit.evidence {
                NextAuditEvidence::ExternalPolicy => "external_policy",
            };
            self.push_line(&format!("expected_evidence = {evidence}({})", self.format_expr(&audit.subject)));
            self.indent_level -= 1;
            self.push_line("}");
        }
        self.push_line("");
        self.push_line("effects {");
        self.indent_level += 1;
        for disposition in &surface.dispositions {
            match disposition {
                NextDisposition::Replace(replacement) => {
                    self.push_line(&format!("replace {} -> {} {{", replacement.input, replacement.output));
                    self.indent_level += 1;
                    self.push_line("data {");
                    self.indent_level += 1;
                    for field in &replacement.data_fields {
                        self.push_line(&format!("{field} = same"));
                    }
                    self.indent_level -= 1;
                    self.push_line("}");
                    self.push_line("identity = same");
                    self.push_line("type_script = same");
                    self.push_line(&format!("lock_script = exact_hash({})", self.format_expr(&replacement.lock_script)));
                    self.push_line("capacity = same");
                    self.push_line("cardinality = one_to_one");
                    self.indent_level -= 1;
                    self.push_line("}");
                }
                NextDisposition::Pool(pool) => {
                    self.push_line(&format!("pool {} {{", pool.name));
                    self.indent_level += 1;
                    self.push_line("inputs {");
                    self.indent_level += 1;
                    for input in &pool.inputs {
                        self.push_line(input);
                    }
                    self.indent_level -= 1;
                    self.push_line("}");
                    self.push_line("outputs {");
                    self.indent_level += 1;
                    for output in &pool.outputs {
                        self.push_line(output);
                    }
                    self.indent_level -= 1;
                    self.push_line("}");
                    self.push_line("data {");
                    self.indent_level += 1;
                    for field in &pool.data_fields {
                        match &field.treatment {
                            NextPoolFieldTreatment::Conserve => self.push_line(&format!("{} = conserve", field.field)),
                            NextPoolFieldTreatment::Set(assignments) => {
                                self.push_line(&format!("{} {{", field.field));
                                self.indent_level += 1;
                                for (output, expression) in assignments {
                                    self.push_line(&format!("{output} = {}", self.format_expr(expression)));
                                }
                                self.indent_level -= 1;
                                self.push_line("}");
                            }
                        }
                    }
                    self.indent_level -= 1;
                    self.push_line("}");
                    self.push_line("identity = pooled");
                    self.push_line("type_script = same");
                    self.push_line("lock_script {");
                    self.indent_level += 1;
                    for (output, expression) in &pool.output_locks {
                        self.push_line(&format!("{output} = exact_hash({})", self.format_expr(expression)));
                    }
                    self.indent_level -= 1;
                    self.push_line("}");
                    self.push_line("capacity = builder_computed");
                    self.push_line("cardinality = declared");
                    self.indent_level -= 1;
                    self.push_line("}");
                }
                NextDisposition::Retire(retirement) => {
                    self.push_line(&format!("retire {} {{", retirement.input));
                    self.indent_level += 1;
                    self.push_line(&format!("absence = {}", format_next_absence_policy(&retirement.absence_policy)));
                    self.push_line("data = discarded");
                    self.push_line("lock_script = none");
                    self.push_line("type_script = absent");
                    self.push_line("capacity = released");
                    self.push_line("cardinality = one");
                    self.indent_level -= 1;
                    self.push_line("}");
                }
                NextDisposition::Fresh(fresh) => {
                    self.push_line(&format!("fresh {} {{", fresh.output));
                    self.indent_level += 1;
                    self.push_line("data {");
                    self.indent_level += 1;
                    for (field, value) in &fresh.data_fields {
                        self.push_line(&format!("{field} = {}", self.format_expr(value)));
                    }
                    self.indent_level -= 1;
                    self.push_line("}");
                    self.push_line(&format!("identity = {}", format_identity_policy(&fresh.identity)));
                    self.push_line("type_script = declared");
                    self.push_line(&format!("lock_script = exact_hash({})", self.format_expr(&fresh.lock_script)));
                    self.push_line("capacity = builder_computed");
                    self.push_line("cardinality = one");
                    self.indent_level -= 1;
                    self.push_line("}");
                }
            }
        }
        self.indent_level -= 1;
        self.push_line("}");
        self.indent_level -= 1;
        self.push_line("}");
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
        if function.effect_declared {
            self.push_line(&format!("#[effect({})]", function.effect.as_str()));
        }

        let params = function.params.iter().map(format_param).collect::<Vec<_>>().join(", ");
        let mut signature = format!("fn {}{}({})", function.name, format_type_params(&function.type_params), params);
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
        self.push_line("verification");
        self.indent_level += 1;
        for stmt in &lock.body {
            self.format_stmt(stmt);
        }
        self.indent_level -= 1;
        self.indent_level -= 1;
        self.push_line("}");
        Ok(())
    }

    fn format_next_lock_script(&mut self, lock: &LockDef) -> Result<()> {
        let surface = lock.next_surface.as_ref().expect("guarded by format_item");
        self.push_line(&format!("lock_script {} on lock_group {{", surface.container_name));
        self.indent_level += 1;
        self.push_line(&format!("entry {}(", lock.name));
        self.indent_level += 1;
        let mut protected_ordinal = 0usize;
        for param in &lock.params {
            let source = match param.source {
                ParamSource::Protected => {
                    let source = format!("group_input[{protected_ordinal}]");
                    protected_ordinal += 1;
                    source
                }
                ParamSource::Witness => "group_witness.input_type".to_string(),
                ParamSource::LockArgs => "current_script.args".to_string(),
                ParamSource::Default | ParamSource::Input | ParamSource::Output => "unresolved".to_string(),
            };
            let ty = match (&param.source, &param.ty) {
                (ParamSource::Protected, Type::Ref(inner)) => inner.as_ref(),
                _ => &param.ty,
            };
            self.push_line(&format!("{} {}: {} from {},", format_param_source(param.source), param.name, format_type(ty), source));
        }
        self.indent_level -= 1;
        self.push_line(") {");
        self.indent_level += 1;
        self.push_line("verify {");
        self.indent_level += 1;
        for expression in &surface.verify {
            self.push_line(&format!("enforce {}", self.format_expr(expression)));
        }
        self.indent_level -= 1;
        self.push_line("}");
        for audit in &surface.audits {
            self.push_line("");
            self.push_line(&format!("audit {} {{", audit.name));
            self.indent_level += 1;
            let evidence = match audit.evidence {
                NextAuditEvidence::ExternalPolicy => "external_policy",
            };
            self.push_line(&format!("expected_evidence = {evidence}({})", self.format_expr(&audit.subject)));
            self.indent_level -= 1;
            self.push_line("}");
        }
        self.indent_level -= 1;
        self.push_line("}");
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
            Stmt::Expr(Expr::Call(call)) if bounded_each_call_parts(call).is_some() => self.format_bounded_each(call),
            Stmt::Expr(expr) => self.push_line(&self.format_expr(expr)),
            Stmt::Return(ReturnStmt { value: None, .. }) => self.push_line("return"),
            Stmt::Return(ReturnStmt { value: Some(expr), .. }) => self.push_line(&format!("return {}", self.format_expr(expr))),
            Stmt::If(if_stmt) => self.format_if_stmt(if_stmt),
            Stmt::For(for_stmt) => self.format_for_stmt(for_stmt),
            Stmt::While(while_stmt) => self.format_while_stmt(while_stmt),
            Stmt::Break(control) => self.push_line(&match &control.label {
                Some(label) => format!("break {label}"),
                None => "break".to_string(),
            }),
            Stmt::Continue(control) => self.push_line(&match &control.label {
                Some(label) => format!("continue {label}"),
                None => "continue".to_string(),
            }),
            Stmt::Borrow(borrow_stmt) => self.format_borrow_stmt(borrow_stmt),
        }
    }

    fn format_bounded_each(&mut self, call: &CallExpr) {
        let Some((operation, binding, collection, body)) = bounded_each_call_parts(call) else {
            self.push_line(&self.format_expr(&Expr::Call(call.clone())));
            return;
        };
        self.push_line(&format!("{} {} in {} {{", operation, binding, self.format_expr(collection)));
        self.indent_level += 1;
        for stmt in body {
            self.format_stmt(stmt);
        }
        self.indent_level -= 1;
        self.push_line("}");
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
        let prefix = for_stmt.label.as_ref().map_or(String::new(), |label| format!("label {label}: "));
        self.push_line(&format!(
            "{prefix}for {} in {} {{",
            format_binding_pattern(&for_stmt.pattern),
            self.format_expr(&for_stmt.iterable)
        ));
        self.indent_level += 1;
        for stmt in &for_stmt.body {
            self.format_stmt(stmt);
        }
        self.indent_level -= 1;
        self.push_line("}");
    }

    fn format_while_stmt(&mut self, while_stmt: &WhileStmt) {
        let prefix = while_stmt.label.as_ref().map_or(String::new(), |label| format!("label {label}: "));
        self.push_line(&format!("{prefix}while {} {{", self.format_expr(&while_stmt.condition)));
        self.indent_level += 1;
        for stmt in &while_stmt.body {
            self.format_stmt(stmt);
        }
        self.indent_level -= 1;
        self.push_line("}");
    }

    fn format_borrow_stmt(&mut self, borrow_stmt: &BorrowStmt) {
        let source = std::iter::once(borrow_stmt.root.as_str())
            .chain(borrow_stmt.path.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(".");
        self.push_line(&format!("borrow {} as {} {{", source, borrow_stmt.binding));
        self.indent_level += 1;
        for stmt in &borrow_stmt.body {
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
                let precedence = binary_precedence(binary.op);
                let left = self.format_binary_operand(&binary.left, precedence, false);
                let right = self.format_binary_operand(&binary.right, precedence, true);
                format!("{} {} {}", left, format_binary_op(binary.op), right)
            }
            Expr::Unary(unary) => {
                let inner = self.format_expr(&unary.expr);
                if matches!(unary.expr.as_ref(), Expr::Assign(_) | Expr::Binary(_) | Expr::Range(_)) {
                    format!("{}({})", format_unary_op(unary.op), inner)
                } else {
                    format!("{}{}", format_unary_op(unary.op), inner)
                }
            }
            Expr::Call(call) => {
                let func = self.format_expr(&call.func);
                let type_args = if call.type_args.is_empty() {
                    String::new()
                } else {
                    format!("<{}>", call.type_args.iter().map(format_type).collect::<Vec<_>>().join(", "))
                };
                let args = call.args.iter().map(|arg| self.format_expr(arg)).collect::<Vec<_>>().join(", ");
                format!("{}{}({})", func, type_args, args)
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
                let mut rendered = if let Some(target) = &create.target {
                    format!("create {} = {} {{ {} }}", target, create.ty, fields)
                } else {
                    format!("create {} {{ {} }}", create.ty, fields)
                };
                if let Some(lock) = &create.lock {
                    rendered.push_str(&format!(" with_lock({})", self.format_expr(lock)));
                }
                rendered
            }
            Expr::Consume(consume) => format!("consume {}", self.format_expr(&consume.expr)),
            Expr::Destroy(destroy) => match &destroy.policy {
                DestructionPolicy::Default => format!("destroy {}", self.format_expr(&destroy.expr)),
                DestructionPolicy::SingletonType => format!("destroy_singleton_type({})", self.format_expr(&destroy.expr)),
                DestructionPolicy::Unique { identity } => {
                    format!("destroy_unique({}, identity = {})", self.format_expr(&destroy.expr), identity)
                }
                DestructionPolicy::Instance { identity_field } => {
                    format!("destroy_instance({}, identity_field = {})", self.format_expr(&destroy.expr), identity_field)
                }
                DestructionPolicy::BurnAmount { field } => {
                    format!("burn_amount({}, field = {})", self.format_expr(&destroy.expr), field)
                }
            },
            Expr::ReadRef(read_ref) => format!("read_ref<{}>()", read_ref.ty),
            Expr::Claim(claim) => format!("claim {}", self.format_expr(&claim.receipt)),
            Expr::Settle(settle) => format!("settle {}", self.format_expr(&settle.expr)),
            Expr::CreateUnique(cu) => {
                let fields = cu.fields.iter().map(|(n, v)| self.format_field_initializer(n, v)).collect::<Vec<_>>().join(", ");
                let mut rendered =
                    format!("create_unique<{}>(identity = {}) {{ {} }}", cu.ty, format_identity_policy(&cu.identity), fields);
                if let Some(lock) = &cu.lock {
                    rendered.push_str(&format!(" with_lock({})", self.format_expr(lock)));
                }
                rendered
            }
            Expr::ReplaceUnique(ru) => {
                let fields = ru.fields.iter().map(|(n, v)| self.format_field_initializer(n, v)).collect::<Vec<_>>().join(", ");
                format!(
                    "replace_unique<{}>(identity = {}) {} {{ {} }}",
                    ru.ty,
                    format_identity_policy(&ru.identity),
                    self.format_expr(&ru.expr),
                    fields
                )
            }
            Expr::Assert(assert_expr) => {
                format!("assert_invariant({}, {})", self.format_expr(&assert_expr.condition), self.format_expr(&assert_expr.message))
            }
            Expr::Require(require_expr) => {
                if let Some(message) = &require_expr.message {
                    if let Expr::String(label) = message.as_ref() {
                        if is_error_label(label) {
                            format!("require {} else {}", self.format_expr(&require_expr.condition), label)
                        } else {
                            format!("require {}, {}", self.format_expr(&require_expr.condition), self.format_expr(message))
                        }
                    } else {
                        format!("require {}, {}", self.format_expr(&require_expr.condition), self.format_expr(message))
                    }
                } else {
                    format!("require {}", self.format_expr(&require_expr.condition))
                }
            }
            Expr::RequireBlock(require_block) => {
                if require_block.expressions.len() == 1 {
                    // Single-expression require block: format as single-line
                    format!("require {{ {} }}", self.format_expr(&require_block.expressions[0]))
                } else {
                    let inner = require_block.expressions.iter().map(|e| self.format_expr(e)).collect::<Vec<_>>().join("\n");
                    format!("require {{\n{}\n}}", inner)
                }
            }
            Expr::Preserve(preserve) => {
                let fields = preserve.fields.join("\n");
                format!("preserve {} from {} {{\n{}\n}}", preserve.output_name, preserve.input_name, fields)
            }
            Expr::ReplaceRelation(relation) => {
                let data = match &relation.data {
                    ReplaceDataTreatment::Fields(treatments) => {
                        let entries = treatments
                            .iter()
                            .map(|treatment| match treatment {
                                ReplaceFieldTreatment::Same(field) => format!("{field} = same"),
                                ReplaceFieldTreatment::Assign(field, value) => {
                                    format!("{field} = {}", self.format_expr(value))
                                }
                            })
                            .collect::<Vec<_>>()
                            .join("\n");
                        format!("data {{\n{entries}\n}}")
                    }
                    ReplaceDataTreatment::SameExcept(assigned) => {
                        let entries = assigned
                            .iter()
                            .map(|(field, value)| format!("{field} = {}", self.format_expr(value)))
                            .collect::<Vec<_>>()
                            .join("\n");
                        format!("data = same except {{\n{entries}\n}}")
                    }
                };
                let lock = match &relation.lock {
                    ReplaceLockTreatment::Same => "lock = same".to_string(),
                    ReplaceLockTreatment::Exact(lock) => format!("lock = exact({})", self.format_expr(lock)),
                    ReplaceLockTreatment::ExactHash(lock) => format!("lock = exact_hash({})", self.format_expr(lock)),
                };
                format!(
                    "replace {} -> {} {{\n{}\n{}\ncapacity = same\nidentity = same\n}}",
                    relation.before, relation.after, data, lock
                )
            }
            Expr::Block(stmts) => format!("{{ {} }}", self.format_expr_block_body(stmts)),
            Expr::Tuple(items) => format!("({})", items.iter().map(|item| self.format_expr(item)).collect::<Vec<_>>().join(", ")),
            Expr::Array(items) => format!("[{}]", items.iter().map(|item| self.format_expr(item)).collect::<Vec<_>>().join(", ")),
            Expr::If(if_expr) => format!(
                "if {} {{ {} }} else {{ {} }}",
                self.format_expr(&if_expr.condition),
                self.format_branch_expr_body(&if_expr.then_branch),
                self.format_branch_expr_body(&if_expr.else_branch)
            ),
            Expr::Cast(cast) => {
                let inner = self.format_expr(&cast.expr);
                // Cast binds more tightly than every binary operator. Losing
                // these parentheses can change both arithmetic and Vec type
                // inference, e.g. `(count - removed) as u8` is not
                // `count - removed as u8`.
                if matches!(cast.expr.as_ref(), Expr::Assign(_) | Expr::Binary(_) | Expr::Range(_)) {
                    format!("({}) as {}", inner, format_type(&cast.ty))
                } else {
                    format!("{} as {}", inner, format_type(&cast.ty))
                }
            }
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
            Expr::StdlibCall(call) => {
                let args = call.args.iter().map(|arg| self.format_expr(arg)).collect::<Vec<_>>().join(", ");
                let base = format!("std::{}::{}({})", call.namespace, call.name, args);
                if call.preserve_fields.is_empty() {
                    base
                } else {
                    let field_indent = " ".repeat((self.indent_level + 1) * self.config.indent_width);
                    let closing_indent = " ".repeat(self.indent_level * self.config.indent_width);
                    let fields =
                        call.preserve_fields.iter().map(|field| format!("{}{}", field_indent, field)).collect::<Vec<_>>().join("\n");
                    format!("{} {{\n{}\n{}}}", base, fields, closing_indent)
                }
            }
        }
    }

    fn format_binary_operand(&self, expr: &Expr, parent_precedence: u8, right_operand: bool) -> String {
        let rendered = self.format_expr(expr);
        let Expr::Binary(binary) = expr else {
            return rendered;
        };
        let child_precedence = binary_precedence(binary.op);
        if child_precedence < parent_precedence || right_operand && child_precedence == parent_precedence {
            format!("({})", rendered)
        } else {
            rendered
        }
    }

    fn format_branch_expr_body(&self, expr: &Expr) -> String {
        match expr {
            Expr::Block(stmts) => self.format_expr_block_body(stmts),
            expr => self.format_expr(expr),
        }
    }

    fn format_expr_block_body(&self, stmts: &[Stmt]) -> String {
        stmts
            .iter()
            .map(|stmt| {
                let mut formatter = Formatter::new(self.config.clone());
                formatter.indent_level = 0;
                formatter.format_stmt(stmt);
                formatter.output.trim().to_string()
            })
            .collect::<Vec<_>>()
            .join(" ")
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
    capability.as_str()
}

fn has_type_policy(
    identity: Option<&IdentityPolicy>,
    default_hash_type: Option<&HashTypeDecl>,
    capacity_floor: Option<&CapacityFloorDecl>,
) -> bool {
    default_hash_type.is_some()
        || capacity_floor.is_some()
        || identity.is_some_and(|identity| !matches!(identity, IdentityPolicy::None))
}

fn format_identity_policy(policy: &IdentityPolicy) -> String {
    match policy {
        IdentityPolicy::None => "none".to_string(),
        IdentityPolicy::CkbTypeId => "ckb_type_id".to_string(),
        IdentityPolicy::Field(path) => format!("field({})", path),
        IdentityPolicy::ScriptArgs => "script_args".to_string(),
        IdentityPolicy::SingletonType => "singleton_type".to_string(),
    }
}

fn format_next_absence_policy(policy: &DestructionPolicy) -> String {
    match policy {
        DestructionPolicy::SingletonType => "singleton_type".to_string(),
        DestructionPolicy::Unique { .. } => "ckb_type_id".to_string(),
        DestructionPolicy::Instance { identity_field } => format!("field({identity_field})"),
        DestructionPolicy::Default | DestructionPolicy::BurnAmount { .. } => {
            unreachable!("Edition 2027 retire accepts only explicit absence policies")
        }
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

fn bounded_each_call_parts(call: &CallExpr) -> Option<(&'static str, &str, &Expr, &[Stmt])> {
    let Expr::Identifier(func) = call.func.as_ref() else {
        return None;
    };
    let operation = match func.as_str() {
        "__cellscript_consume_each" => "consume_each",
        "__cellscript_create_each" => "create_each",
        _ => return None,
    };
    let [Expr::Identifier(binding), collection, Expr::Block(body)] = call.args.as_slice() else {
        return None;
    };
    Some((operation, binding, collection, body))
}

fn format_aggregate_invariant(aggregate: &AggregateInvariant) -> String {
    match aggregate.kind {
        AggregateInvariantKind::Sum => format!(
            "assert_sum({}) {} assert_sum({})",
            aggregate.target,
            aggregate.relation.map(format_aggregate_relation).unwrap_or("?"),
            aggregate.rhs.as_ref().map(ToString::to_string).unwrap_or_else(|| "?".to_string())
        ),
        AggregateInvariantKind::Conserved => format!("assert_conserved({}, scope = {})", aggregate.target, aggregate.scope),
        AggregateInvariantKind::Delta => format!(
            "assert_delta({}, {}, scope = {})",
            aggregate.target,
            aggregate.argument.as_deref().unwrap_or("?"),
            aggregate.scope
        ),
        AggregateInvariantKind::Distinct => format!("assert_distinct({}, scope = {})", aggregate.target, aggregate.scope),
        AggregateInvariantKind::Singleton => format!("assert_singleton({}, scope = {})", aggregate.target, aggregate.scope),
    }
}

fn format_aggregate_relation(relation: AggregateRelation) -> &'static str {
    match relation {
        AggregateRelation::Lt => "<",
        AggregateRelation::Le => "<=",
        AggregateRelation::Eq => "==",
        AggregateRelation::Ge => ">=",
        AggregateRelation::Gt => ">",
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
    rendered.push_str(&format_type(ty));
    rendered
}

fn format_param_source(source: ParamSource) -> &'static str {
    match source {
        ParamSource::Input => "input",
        ParamSource::Output => "output",
        ParamSource::Protected => "protected",
        ParamSource::Witness => "witness",
        ParamSource::LockArgs => "lock_args",
        ParamSource::Default => "unresolved",
    }
}

fn format_action_outputs(outputs: &[ActionOutput]) -> String {
    if outputs.len() == 1 {
        format!("{}: {}", outputs[0].name, format_type(&outputs[0].ty))
    } else {
        format!(
            "({})",
            outputs.iter().map(|output| format!("{}: {}", output.name, format_type(&output.ty))).collect::<Vec<_>>().join(", ")
        )
    }
}

fn format_action_state_edge(prefix: &str, state_edge: &ActionStateEdge) -> String {
    let path = &state_edge.path;
    let to_path = &state_edge.to_path;
    if path.field.is_empty() && to_path.field.is_empty() && state_edge.from.is_empty() && state_edge.to.is_empty() {
        return format!("{}{} -> {}", prefix, path.base, to_path.base);
    }
    format!("{}{}.{}: {} -> {}.{}: {}", prefix, path.base, path.field, state_edge.from, to_path.base, to_path.field, state_edge.to)
}

fn is_error_label(label: &str) -> bool {
    let mut chars = label.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_uppercase() || first == '_') && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn format_binding_pattern(pattern: &BindingPattern) -> String {
    match pattern {
        BindingPattern::Name(name) => name.clone(),
        BindingPattern::Tuple(items) => format!("({})", items.iter().map(format_binding_pattern).collect::<Vec<_>>().join(", ")),
        BindingPattern::Wildcard => "_".to_string(),
    }
}

fn format_type_params(params: &[TypeParam]) -> String {
    if params.is_empty() {
        return String::new();
    }
    let rendered = params
        .iter()
        .map(|param| {
            let mut value = String::new();
            if param.phantom {
                value.push_str("phantom ");
            }
            value.push_str(&param.name);
            if !param.constraints.is_empty() {
                value.push_str(": ");
                if ValueAbility::is_fixed_value_profile(&param.constraints) {
                    value.push_str(ValueAbility::FIXED_VALUE_PROFILE_NAME);
                } else {
                    value.push_str(&param.constraints.iter().map(|ability| ability.as_str()).collect::<Vec<_>>().join(" + "));
                }
            }
            value
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("<{}>", rendered)
}

fn format_value_abilities(abilities: &[ValueAbility]) -> String {
    abilities.iter().map(|ability| ability.as_str()).collect::<Vec<_>>().join(", ")
}

fn format_type(ty: &Type) -> String {
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
        BinaryOp::BitAnd => "&",
        BinaryOp::BitOr => "|",
        BinaryOp::BitXor => "^",
        BinaryOp::Shl => "<<",
        BinaryOp::Shr => ">>",
    }
}

fn binary_precedence(op: BinaryOp) -> u8 {
    match op {
        BinaryOp::Or => 1,
        BinaryOp::And => 2,
        BinaryOp::BitOr => 3,
        BinaryOp::BitXor => 4,
        BinaryOp::BitAnd => 5,
        BinaryOp::Eq | BinaryOp::Ne => 6,
        BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => 7,
        BinaryOp::Shl | BinaryOp::Shr => 8,
        BinaryOp::Add | BinaryOp::Sub => 9,
        BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => 10,
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

pub(crate) fn format_expression(expr: &Expr) -> String {
    Formatter::new(FormatConfig::default()).format_expr(expr)
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
    fn format_preserves_labeled_loop_control() {
        let source = r#"
module demo

fn count() -> u64 {
    label outer: for i in 0..4 {
        if i == 1 {
            continue outer
        }
        break outer
    }
    return 0
}
"#;
        let formatted = verify_idempotent(source, FormatConfig::default()).and_then(|_| {
            let module = parser::parse(&lexer::lex(source)?)?;
            format_default(&module)
        });
        let formatted = formatted.unwrap();
        assert!(formatted.contains("label outer: for i in 0..4 {"), "{formatted}");
        assert!(formatted.contains("continue outer"), "{formatted}");
        assert!(formatted.contains("break outer"), "{formatted}");
    }

    #[test]
    fn format_round_trips_simple_module() {
        let source = r#"
module demo

action add(x: u64, y: u64) -> u64 {
    verification
        let z = x + y
        return z
}
"#;
        let tokens = lexer::lex(source).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let formatted = format_default(&module).unwrap();

        assert!(formatted.contains("module demo"));
        assert!(formatted.contains("action add(x: u64, y: u64) -> u64 {\n    verification"));
        assert!(formatted.contains("let z = x + y"));
        assert!(formatted.contains("return z"));
    }

    #[test]
    fn format_round_trips_the_explicit_source_preview_frontend() {
        let source = "module preview\naction main(witness value:u64)->u64 {\nverification\nreturn value\n}\n";
        let module = crate::frontend::parse(source, crate::NEXT_EDITION).unwrap();
        let formatted = format_default(&module).unwrap();
        crate::frontend::parse(&formatted, crate::NEXT_EDITION).unwrap();
        assert!(formatted.contains("action main(witness value: u64) -> u64"));
    }

    #[test]
    fn format_round_trips_typed_ckb_temporal_domains() {
        let source = r#"
module temporal_format

fn inspect(
    encoded: EncodedSince,
    epoch: EpochNumber,
    duration: EpochDuration,
    block: BlockNumber,
    length: EpochLength,
    timestamp: TimestampMillis,
) -> bool {
    let decoded = ckb::since_decode(encoded)
    let absolute = ckb::since_absolute_epoch(42, 3, 10)
    let relative = ckb::since_relative_timestamp(3600)
    let next = ckb::epoch_add(epoch, duration)
    return ckb::since_to_raw(absolute) > 0
        && ckb::since_to_raw(relative) > 0
        && ckb::since_metric(decoded) <= 2
        && ckb::epoch_number_to_u64(next) >= 42
        && ckb::block_number_to_u64(block) >= 0
        && ckb::epoch_length_to_u64(length) >= 0
        && ckb::timestamp_millis_to_u64(timestamp) >= 0
}
"#;
        let module = crate::frontend::parse(source, crate::NEXT_EDITION).unwrap();
        let formatted = format_default(&module).unwrap();
        crate::frontend::parse(&formatted, crate::NEXT_EDITION).unwrap();
        verify_idempotent(&formatted, FormatConfig::default()).unwrap();
        for token in [
            "EncodedSince",
            "EpochNumber",
            "EpochDuration",
            "BlockNumber",
            "EpochLength",
            "TimestampMillis",
            "ckb::since_decode(encoded)",
            "ckb::since_absolute_epoch(42, 3, 10)",
            "ckb::since_relative_timestamp(3600)",
            "ckb::epoch_add(epoch, duration)",
        ] {
            assert!(formatted.contains(token), "missing `{token}` in:\n{formatted}");
        }
    }

    #[test]
    fn format_preserves_full_width_u128_decimal_literals() {
        let source = r#"
module demo

const MAX: u128 = 340282366920938463463374607431768211455

fn max_value() -> u128 {
    return MAX
}
"#;
        let tokens = lexer::lex(source).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let formatted = format_default(&module).unwrap();

        assert!(formatted.contains("340282366920938463463374607431768211455"));
        let reparsed = parser::parse(&lexer::lex(&formatted).unwrap()).unwrap();
        let reformatted = format_default(&reparsed).unwrap();
        assert_eq!(formatted, reformatted);
    }

    #[test]
    fn format_preserves_bitwise_shift_precedence() {
        let source = r#"
module demo

fn mix(value: u64, mask: u64, count: u64) -> u64 {
    return ((value & mask) | (value ^ mask)) << count
}
"#;
        let formatted = verify_idempotent(source, FormatConfig::default()).and_then(|_| {
            let module = parser::parse(&lexer::lex(source)?)?;
            format_default(&module)
        });
        let formatted = formatted.unwrap();
        assert!(formatted.contains("return (value & mask | value ^ mask) << count"), "{formatted}");
    }

    #[test]
    fn format_preserves_cast_of_binary_expression() {
        for expression in ["(left - right) as u8", "(left & right) as u128", "(left << right) as u128", "(left == right) as u8"] {
            let source = format!("module cast_precedence\nfn value(left: u64, right: u64) -> u128 {{ return {expression} }}");
            let module = parser::parse(&lexer::lex(&source).unwrap()).unwrap();
            let formatted = format_default(&module).unwrap();
            assert!(formatted.contains(expression), "{formatted}");
            verify_idempotent(&formatted, FormatConfig::default()).unwrap();
        }
    }

    #[test]
    fn format_canonicalizes_typed_invariant_source_views() {
        let source = r#"
module demo

invariant token_conservation {
    trigger: type_group
    scope: group
    reads: group_input<Token>.amount, group_output<Token>.amount
    assert_sum(group_output<Token>.amount) == assert_sum(group_input<Token>.amount)
}

resource Token {
    amount: u128
}
"#;
        let tokens = lexer::lex(source).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let formatted = format_default(&module).unwrap();

        assert!(formatted.contains("reads: group_inputs<Token>.amount, group_outputs<Token>.amount"), "{formatted}");
        assert!(formatted.contains("assert_sum(group_outputs<Token>.amount) == assert_sum(group_inputs<Token>.amount)"));
        let reparsed = parser::parse(&lexer::lex(&formatted).unwrap()).unwrap();
        assert_eq!(format_default(&reparsed).unwrap(), formatted);
    }

    #[test]
    fn format_uses_field_shorthand_when_value_matches_name() {
        let source = r#"
module demo

resource Token has store {
    amount: u64
    symbol: [u8; 8]
}

action mint(amount: u64, symbol: [u8; 8]) -> token: Token {
    verification
        create token = Token { amount: amount, symbol: symbol }
}
"#;
        let tokens = lexer::lex(source).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let formatted = format_default(&module).unwrap();

        assert!(formatted.contains("create token = Token { amount, symbol }"), "unexpected formatted source:\n{}", formatted);
    }

    #[test]
    fn format_if_expression_branch_blocks_are_idempotent() {
        let source = r#"
module demo

action choose(flag: bool) -> u64 {
    verification
        let pair = if flag { (1, 2) } else { (3, 4) }
        return pair.0
}
"#;
        let tokens = lexer::lex(source).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let formatted = format_default(&module).unwrap();
        let tokens2 = lexer::lex(&formatted).unwrap();
        let module2 = parser::parse(&tokens2).unwrap();
        let formatted2 = format_default(&module2).unwrap();

        assert_eq!(formatted, formatted2);
        assert!(formatted.contains("let pair = if flag { (1, 2) } else { (3, 4) }"), "unexpected formatted source:\n{}", formatted);
        assert!(!formatted.contains("{{"), "unexpected formatted source:\n{}", formatted);
    }

    #[test]
    fn format_uses_canonical_require_and_no_const_semicolon() {
        let source = r#"
module demo

const LIMIT: u64 = 10;

action check(x: u64) -> bool {
    verification
        require x < LIMIT, "too large";
        require x > 0, "zero"
}
"#;
        let tokens = lexer::lex(source).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let formatted = format_default(&module).unwrap();

        assert!(formatted.contains("const LIMIT: u64 = 10\n"), "unexpected formatted source:\n{}", formatted);
        assert!(!formatted.contains("assert("), "unexpected formatted source:\n{}", formatted);
        assert!(formatted.contains("require x > 0, \"zero\""), "unexpected formatted source:\n{}", formatted);
        assert!(!formatted.contains("assert_invariant"), "unexpected formatted source:\n{}", formatted);
        assert!(!formatted.contains("const LIMIT: u64 = 10;"), "unexpected formatted source:\n{}", formatted);
    }

    #[test]
    fn format_round_trips_preserve_block() {
        let source = r#"
module demo

resource Offer has store {
    seller: u64
    price: u64
    state: u8
}

flow Offer.state {
    Live -> Filled;
}

action fill(input: Offer) -> (output: Offer) {
    transition input -> output
    verification
        preserve output from input {
            seller
            price
        }
}
"#;
        let tokens = lexer::lex(source).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let formatted = format_default(&module).unwrap();

        assert!(formatted.contains("preserve"), "formatted output should contain 'preserve':\n{}", formatted);
        assert!(formatted.contains("from input"), "formatted output should contain 'from input':\n{}", formatted);
        assert!(formatted.contains("seller"), "formatted output should contain 'seller':\n{}", formatted);

        // Round-trip: re-parse and re-format
        let tokens2 = lexer::lex(&formatted).unwrap();
        let module2 = parser::parse(&tokens2).unwrap();
        let formatted2 = format_default(&module2).unwrap();
        assert_eq!(formatted, formatted2, "formatter round-trip failed for preserve block");
    }

    #[test]
    fn format_action_multiple_transitions_without_block() {
        let source = r#"
module demo

action settle(input: Offer, receipt: Receipt) -> (output: Offer, next_receipt: Receipt) {
    transition input -> output
    transition receipt -> next_receipt
    verification
        require output.owner == input.owner
}
"#;
        let tokens = lexer::lex(source).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let formatted = format_default(&module).unwrap();

        assert!(!formatted.contains("transition {\n"), "formatted output must not use a transition block:\n{}", formatted);
        assert!(
            formatted.contains("transition input -> output"),
            "formatted output should contain the first transition edge:\n{}",
            formatted
        );
        assert!(
            formatted.contains("transition receipt -> next_receipt"),
            "formatted output should contain the second transition edge:\n{}",
            formatted
        );
    }

    #[test]
    fn format_round_trips_require_block() {
        let source = r#"
module demo

action check(x: u64, y: u64) -> u64 {
    verification
        require {
            x > 0
            y > 0
        }
        return x + y
}
"#;
        let tokens = lexer::lex(source).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let formatted = format_default(&module).unwrap();

        assert!(formatted.contains("require {"), "formatted output should contain 'require {{':\n{}", formatted);

        // Round-trip: re-parse and re-format
        let tokens2 = lexer::lex(&formatted).unwrap();
        let module2 = parser::parse(&tokens2).unwrap();
        let formatted2 = format_default(&module2).unwrap();
        assert_eq!(formatted, formatted2, "formatter round-trip failed for require block");
    }

    #[test]
    fn format_single_expr_require_block_uses_compact_form() {
        let source = r#"
module demo

action check(x: u64) -> u64 {
    verification
        require {
            x > 0
        }
        return x
}
"#;
        let tokens = lexer::lex(source).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let formatted = format_default(&module).unwrap();

        // Single-expression require block should format compactly
        assert!(formatted.contains("require {"), "formatted output should contain 'require {{':\n{}", formatted);
    }

    #[test]
    fn format_round_trips_stdlib_lifecycle_field_block() {
        let source = r#"
module demo

resource Coin has store, replace, relock, consume {
    amount: u64
    nonce: u64
}

action transfer_coin(coin: Coin, to: Address) -> next_coin: Coin {
    verification
        std::lifecycle::transfer(coin, next_coin, to) {
            amount
            nonce
        }
}
"#;

        let tokens = lexer::lex(source).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let formatted = format_default(&module).unwrap();
        let tokens2 = lexer::lex(&formatted).unwrap();
        let module2 = parser::parse(&tokens2).expect("formatted stdlib lifecycle block should parse");
        let formatted2 = format_default(&module2).unwrap();
        assert_eq!(formatted, formatted2, "formatter round-trip failed for stdlib lifecycle block");
        assert!(
            !formatted.contains("amount, nonce"),
            "stdlib field blocks use newline-separated field names, not comma-separated lists:\n{}",
            formatted
        );
        assert!(
            formatted
                .contains("        std::lifecycle::transfer(coin, next_coin, to) {\n            amount\n            nonce\n        }"),
            "stdlib field blocks should retain statement-relative indentation:\n{}",
            formatted
        );
    }

    #[test]
    fn format_preserves_type_policy_metadata() {
        let source = r#"
module fmt::identity

#[type_id("cellscript::fmt::Token:v1")]
resource Token has store
with_default_hash_type(Type)
with_capacity_floor(6100000000)
identity(field(token_id))
{
    token_id: u64,
    amount: u64
}

shared Config has store
identity(singleton_type)
{
    value: u64
}

receipt Burn -> Token has store
identity(script_args)
{
    amount: u64
}

#[type_id("cellscript::fmt::Snapshot:v1")]
struct Snapshot
with_default_hash_type(Data2)
with_capacity_floor(6100000000)
{
    amount: u64
}
"#;
        let tokens = lexer::lex(source).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let formatted = format_default(&module).unwrap();

        assert!(formatted.contains(r#"#[type_id("cellscript::fmt::Token:v1")]"#), "unexpected formatted source:\n{}", formatted);
        assert!(formatted.contains("with_default_hash_type(type)"), "unexpected formatted source:\n{}", formatted);
        assert!(formatted.contains("with_capacity_floor(6100000000)"), "unexpected formatted source:\n{}", formatted);
        assert!(formatted.contains("identity(field(token_id))"), "unexpected formatted source:\n{}", formatted);
        assert!(formatted.contains("identity(singleton_type)"), "unexpected formatted source:\n{}", formatted);
        assert!(formatted.contains("identity(script_args)"), "unexpected formatted source:\n{}", formatted);
        assert!(formatted.contains(r#"#[type_id("cellscript::fmt::Snapshot:v1")]"#), "unexpected formatted source:\n{}", formatted);
        assert!(formatted.contains("with_default_hash_type(data2)"), "unexpected formatted source:\n{}", formatted);

        let tokens = lexer::lex(&formatted).unwrap();
        let reparsed = parser::parse(&tokens).unwrap();
        let reformatted = format_default(&reparsed).unwrap();
        assert_eq!(formatted, reformatted);
    }

    #[test]
    fn format_round_trips_typed_transaction_view_calls() {
        let source = r#"
module fmt::views

resource Token has store {
    amount: u64
}

action inspect() -> u64 {
    verification
        let input = ckb::input<Token>(0)
        let output = ckb::group_output<Token>(0)
        return input.capacity + output.output_index
}
"#;
        let tokens = lexer::lex(source).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let formatted = format_default(&module).unwrap();
        assert!(formatted.contains("ckb::input<Token>(0)"), "unexpected formatted source:\n{}", formatted);
        assert!(formatted.contains("ckb::group_output<Token>(0)"), "unexpected formatted source:\n{}", formatted);

        let tokens = lexer::lex(&formatted).unwrap();
        let reparsed = parser::parse(&tokens).unwrap();
        assert_eq!(formatted, format_default(&reparsed).unwrap());
    }

    #[test]
    fn format_round_trips_bounded_invariant_quantifiers() {
        let source = r#"
module fmt::quantifiers

resource Token {
    amount: u64
}

invariant positive_outputs {
    trigger: type_group
    scope: group
    reads: group_outputs<Token>.amount
    forall output token in group_outputs<Token> {
        require token.amount > 0
    }
}

invariant one_claim {
    trigger: explicit_entry
    scope: transaction
    reads: outputs<Token>.amount
    count(outputs<Token> where amount == 7) == 1
}
"#;
        let tokens = lexer::lex(source).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let formatted = format_default(&module).unwrap();
        assert!(formatted.contains("forall output token in group_outputs<Token>"), "unexpected output:\n{}", formatted);
        assert!(formatted.contains("count(outputs<Token> where amount == 7) == 1"), "unexpected output:\n{}", formatted);
        let reparsed = parser::parse(&lexer::lex(&formatted).unwrap()).unwrap();
        assert_eq!(formatted, format_default(&reparsed).unwrap());
    }

    #[test]
    fn format_round_trips_bounded_collection_lifecycle_blocks() {
        let source = r#"
module fmt::bounded_collections

struct Plan {
    owner: Address
    amount: u64
}

resource Token has store, create, consume {
    owner: Address
    amount: u64
}

action batch(input inputs: BoundedCellSet<Token, 16>, witness plans: BoundedList<Plan, 16>) -> u64 {
    verification
        consume_each token in inputs {
            require token.amount > 0
        }
        create_each plan in plans {
            require plan.amount > 0
            create Token { owner: plan.owner, amount: plan.amount }
        }
        return 0
}
"#;
        let module = parser::parse(&lexer::lex(source).unwrap()).unwrap();
        let formatted = format_default(&module).unwrap();
        assert!(formatted.contains("input inputs: BoundedCellSet<Token, 16>"), "unexpected output:\n{formatted}");
        assert!(formatted.contains("witness plans: BoundedList<Plan, 16>"), "unexpected output:\n{formatted}");
        assert!(formatted.contains("consume_each token in inputs"), "unexpected output:\n{formatted}");
        assert!(formatted.contains("create_each plan in plans"), "unexpected output:\n{formatted}");
        let reparsed = parser::parse(&lexer::lex(&formatted).unwrap()).unwrap();
        assert_eq!(formatted, format_default(&reparsed).unwrap());
    }

    #[test]
    fn format_round_trips_type_validity_blocks() {
        let source = r#"
module fmt::validity

resource Token has store, create {
    amount: u64
    validity
        require amount > 0, "amount must be positive"
        require amount > env::block_number()
}

struct Legacy {
    validity: u64
}
"#;
        let module = parser::parse(&lexer::lex(source).unwrap()).unwrap();
        let formatted = format_default(&module).unwrap();
        assert!(formatted.contains("\n    validity\n        require amount > 0, \"amount must be positive\""));
        assert!(formatted.contains("require amount > env::block_number()"));
        assert!(formatted.contains("validity: u64,"), "contextual field was reformatted as a block:\n{formatted}");
        let reparsed = parser::parse(&lexer::lex(&formatted).unwrap()).unwrap();
        assert_eq!(formatted, format_default(&reparsed).unwrap());
    }

    #[test]
    fn format_round_trips_generic_parameters_abilities_and_calls() {
        let source = r#"
module fmt::generics

struct Tagged<phantom Tag, T: copy + fixed + serializable + non_linear> has copy, fixed, serializable, non_linear {
    value: T
}

fn identity<T: copy + drop>(value: T) -> T {
    return value
}

action verify() -> u64 {
    verification
        let tagged: Tagged<Hash, u64> = Tagged<Hash, u64> { value: identity<u64>(42) }
        return tagged.value
}
"#;
        let module = parser::parse(&lexer::lex(source).unwrap()).unwrap();
        let formatted = format_default(&module).unwrap();
        assert!(formatted.contains("struct Tagged<phantom Tag, T: copy + fixed + serializable + non_linear>"));
        assert!(formatted.contains("fn identity<T: copy + drop>(value: T) -> T"));
        assert!(formatted.contains("identity<u64>(42)"));
        let reparsed = parser::parse(&lexer::lex(&formatted).unwrap()).unwrap();
        assert_eq!(formatted, format_default(&reparsed).unwrap());
    }

    #[test]
    fn formatter_canonicalizes_the_fixed_value_profile_and_derived_abilities() {
        let source = r#"
module fmt::fixed_value

public struct Pair<T: non_linear + serializable + fixed + store + drop + copy>
    has copy, drop, store, fixed, serializable, non_linear {
    left: T,
    right: T,
}

public fn identity<T: copy + drop + store + fixed + serializable + non_linear>(value: T) -> T {
    value
}
"#;
        let module = parser::parse(&lexer::lex(source).unwrap()).unwrap();
        let formatted = format_default(&module).unwrap();
        assert!(formatted.contains("public struct Pair<T: fixed_value> {"), "unexpected format:\n{formatted}");
        assert!(!formatted.contains("Pair<T: fixed_value> has"), "derived abilities must not be repeated:\n{formatted}");
        assert!(formatted.contains("public fn identity<T: fixed_value>"));
        let reparsed = parser::parse(&lexer::lex(&formatted).unwrap()).unwrap();
        assert_eq!(formatted, format_default(&reparsed).unwrap());
    }
}
