//! Deterministic source-level monomorphization for the 0.25 value-generic
//! kernel.
//!
//! The backend intentionally remains concrete: templates are validated and
//! specialized before type checking and IR lowering. This keeps generic
//! substitution, value abilities, phantom identity, and recursion budgets out
//! of the trusted code-generation path.

use crate::ast::*;
use crate::error::{CompileError, Result, Span};
use std::collections::{BTreeMap, HashMap, HashSet};

const MONO_MARKER: &str = "__mono__";
pub(crate) const MAX_GENERIC_INSTANTIATIONS: usize = 256;
const MAX_GENERIC_NESTING: usize = 32;
const MAX_MONOMORPH_NAME_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TemplateKind {
    Struct,
    Enum,
    Function,
}

#[derive(Debug, Clone)]
struct Instantiation {
    kind: TemplateKind,
    base: String,
    args: Vec<Type>,
    span: Span,
}

#[derive(Debug, Clone)]
pub(crate) struct ExternalGenericItem {
    pub(crate) local_name: String,
    pub(crate) owner_module: String,
    pub(crate) source_name: String,
    pub(crate) item: Item,
}

#[derive(Debug, Clone)]
pub(crate) struct SeedInstantiation {
    pub(crate) base: String,
    pub(crate) args: Vec<Type>,
    pub(crate) span: Span,
}

#[derive(Debug, Clone)]
pub(crate) struct ExternalInstantiationRequest {
    pub(crate) owner_module: String,
    pub(crate) source_name: String,
    pub(crate) local_concrete_name: String,
    pub(crate) owner_concrete_name: String,
    pub(crate) seed: SeedInstantiation,
}

#[derive(Debug, Clone)]
pub(crate) struct MonomorphizeOutput {
    pub(crate) module: Module,
    pub(crate) external_requests: Vec<ExternalInstantiationRequest>,
}

#[derive(Debug, Clone)]
struct ExternalOrigin {
    owner_module: String,
    source_name: String,
    kind: TemplateKind,
}

#[derive(Default)]
struct RewriteContext {
    /// Generic base name to the only concrete instantiation seen in the
    /// current callable. Match patterns may omit their type arguments when
    /// this mapping is unambiguous.
    applied_types: HashMap<String, Option<String>>,
    bindings: HashMap<String, Type>,
}

impl RewriteContext {
    fn record_applied_type(&mut self, base: &str, concrete: &str) {
        self.applied_types
            .entry(base.to_string())
            .and_modify(|current| {
                if current.as_deref() != Some(concrete) {
                    *current = None;
                }
            })
            .or_insert_with(|| Some(concrete.to_string()));
    }

    fn concrete_type(&self, base: &str) -> Option<&str> {
        self.applied_types.get(base).and_then(Option::as_deref)
    }

    fn bind_pattern(&mut self, pattern: &BindingPattern, ty: &Type) {
        match (pattern, ty) {
            (BindingPattern::Name(name), ty) => {
                self.bindings.insert(name.clone(), ty.clone());
            }
            (BindingPattern::Tuple(patterns), Type::Tuple(items)) if patterns.len() == items.len() => {
                for (pattern, item) in patterns.iter().zip(items) {
                    self.bind_pattern(pattern, item);
                }
            }
            _ => {}
        }
    }
}

struct Monomorphizer {
    structs: HashMap<String, StructDef>,
    enums: HashMap<String, EnumDef>,
    functions: HashMap<String, FnDef>,
    concrete_struct_abilities: HashMap<String, Vec<ValueAbility>>,
    concrete_enum_abilities: HashMap<String, Vec<ValueAbility>>,
    concrete_struct_fields: HashMap<String, Vec<Type>>,
    concrete_enum_fields: HashMap<String, Vec<Type>>,
    cell_types: HashSet<String>,
    pending: BTreeMap<String, Instantiation>,
    emitted: HashSet<String>,
    external_origins: HashMap<String, ExternalOrigin>,
    external_requests: BTreeMap<String, ExternalInstantiationRequest>,
}

/// Replace every reachable generic template in one module with deterministic
/// concrete specializations.
pub fn monomorphize(module: &Module) -> Result<Module> {
    let mut monomorphizer = Monomorphizer::new(module)?;
    monomorphizer.run(module)
}

pub(crate) fn monomorphize_with_project_context(
    module: &Module,
    external_items: &[ExternalGenericItem],
    seeds: &[SeedInstantiation],
) -> Result<MonomorphizeOutput> {
    let mut monomorphizer = Monomorphizer::new(module)?;
    monomorphizer.register_external_items(external_items)?;
    monomorphizer.seed(seeds)?;
    let module = monomorphizer.run(module)?;
    Ok(MonomorphizeOutput { module, external_requests: monomorphizer.external_requests.into_values().collect() })
}

/// Decode the stable internal specialization name into its source template and
/// canonical type arguments for metadata, diagnostics, LSP, and docgen.
pub(crate) fn decode_monomorph_name(name: &str) -> Option<(String, Vec<String>)> {
    let (base, encoded) = name.split_once(MONO_MARKER)?;
    if encoded.len() % 2 != 0 || encoded.is_empty() {
        return None;
    }
    let mut bytes = Vec::with_capacity(encoded.len() / 2);
    for offset in (0..encoded.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&encoded[offset..offset + 2], 16).ok()?);
    }
    let canonical = String::from_utf8(bytes).ok()?;
    Some((base.to_string(), split_top_level(&canonical, ',')?))
}

/// Derive the abilities guaranteed by a generic value declaration's field
/// contract. Type parameters contribute only their declared constraints, so
/// the result is stable before any concrete monomorphization is selected.
pub(crate) fn derive_template_value_abilities<'a>(
    params: &[TypeParam],
    fields: impl IntoIterator<Item = &'a Type>,
) -> Vec<ValueAbility> {
    let constraints = params
        .iter()
        .map(|param| (param.name.as_str(), param.constraints.iter().copied().collect::<HashSet<_>>()))
        .collect::<HashMap<_, _>>();
    let mut fields = fields.into_iter().peekable();
    let Some(first) = fields.next() else {
        return ValueAbility::FIXED_VALUE_PROFILE.to_vec();
    };
    let mut derived = guaranteed_template_type_abilities(first, &constraints);
    for field in fields {
        let field_abilities = guaranteed_template_type_abilities(field, &constraints);
        derived.retain(|ability| field_abilities.contains(ability));
    }
    derived.remove(&ValueAbility::Cell);
    let mut derived = derived.into_iter().collect::<Vec<_>>();
    derived.sort_unstable();
    derived
}

fn guaranteed_template_type_abilities(ty: &Type, constraints: &HashMap<&str, HashSet<ValueAbility>>) -> HashSet<ValueAbility> {
    let fixed_value = || ValueAbility::FIXED_VALUE_PROFILE.into_iter().collect();
    match ty {
        Type::U8
        | Type::U16
        | Type::U32
        | Type::I32
        | Type::U64
        | Type::U128
        | Type::Bool
        | Type::Unit
        | Type::Address
        | Type::Hash => fixed_value(),
        Type::Array(item, _) => guaranteed_template_type_abilities(item, constraints),
        Type::Tuple(items) => {
            let mut items = items.iter();
            let Some(first) = items.next() else {
                return fixed_value();
            };
            let mut abilities = guaranteed_template_type_abilities(first, constraints);
            for item in items {
                let item_abilities = guaranteed_template_type_abilities(item, constraints);
                abilities.retain(|ability| item_abilities.contains(ability));
            }
            abilities
        }
        Type::Ref(_) | Type::MutRef(_) => [ValueAbility::Copy, ValueAbility::Drop, ValueAbility::NonLinear].into_iter().collect(),
        Type::Named(name) => constraints.get(name.as_str()).cloned().unwrap_or_else(|| match name.as_str() {
            "usize" | "isize" => fixed_value(),
            "String" | "Vec" => {
                [ValueAbility::Copy, ValueAbility::Drop, ValueAbility::Store, ValueAbility::Serializable, ValueAbility::NonLinear]
                    .into_iter()
                    .collect()
            }
            _ => HashSet::new(),
        }),
    }
}

impl Monomorphizer {
    fn new(module: &Module) -> Result<Self> {
        let mut this = Self {
            structs: HashMap::new(),
            enums: HashMap::new(),
            functions: HashMap::new(),
            concrete_struct_abilities: HashMap::new(),
            concrete_enum_abilities: HashMap::new(),
            concrete_struct_fields: HashMap::new(),
            concrete_enum_fields: HashMap::new(),
            cell_types: HashSet::new(),
            pending: BTreeMap::new(),
            emitted: HashSet::new(),
            external_origins: HashMap::new(),
            external_requests: BTreeMap::new(),
        };
        let option = builtin_option_template();
        this.enums.insert(option.name.clone(), option);

        for item in &module.items {
            if matches!(item, Item::Struct(def) if def.name == "Option") || matches!(item, Item::Enum(def) if def.name == "Option") {
                return Err(generic_declaration_error("type name 'Option' is reserved by the CellScript prelude", item_span(item)));
            }
            if let Some(name) = item_decl_name(item).filter(|name| name.contains(MONO_MARKER)) {
                return Err(generic_declaration_error(
                    format!("top-level name '{}' contains the compiler-reserved monomorphization marker", name),
                    item_span(item),
                ));
            }
            match item {
                Item::Resource(def) => {
                    this.cell_types.insert(def.name.clone());
                }
                Item::Shared(def) => {
                    this.cell_types.insert(def.name.clone());
                }
                Item::Receipt(def) => {
                    this.cell_types.insert(def.name.clone());
                }
                Item::Struct(def) if def.type_params.is_empty() => {
                    this.concrete_struct_abilities.insert(def.name.clone(), def.abilities.clone());
                    this.concrete_struct_fields.insert(def.name.clone(), def.fields.iter().map(|field| field.ty.clone()).collect());
                }
                Item::Struct(def) => {
                    let mut def = def.clone();
                    Self::validate_type_params("struct", &def.name, &def.type_params, def.span)?;
                    if module.visibility_of(&def.name).is_exported() {
                        Self::validate_public_layout_params("struct", &def.name, &def.type_params)?;
                    }
                    if def.abilities.is_empty() {
                        def.abilities = derive_template_value_abilities(&def.type_params, def.fields.iter().map(|field| &field.ty));
                    }
                    Self::validate_declared_abilities("struct", &def.name, &def.abilities, def.span)?;
                    Self::validate_phantom_layout_usage(&def.name, &def.type_params, def.fields.iter().map(|field| &field.ty))?;
                    this.structs.insert(def.name.clone(), def);
                }
                Item::Enum(def) if def.type_params.is_empty() => {
                    this.concrete_enum_abilities.insert(def.name.clone(), def.abilities.clone());
                    this.concrete_enum_fields
                        .insert(def.name.clone(), def.variants.iter().flat_map(|variant| variant.fields.iter().cloned()).collect());
                }
                Item::Enum(def) => {
                    let mut def = def.clone();
                    Self::validate_type_params("enum", &def.name, &def.type_params, def.span)?;
                    if module.visibility_of(&def.name).is_exported() {
                        Self::validate_public_layout_params("enum", &def.name, &def.type_params)?;
                    }
                    if def.abilities.is_empty() {
                        def.abilities = derive_template_value_abilities(
                            &def.type_params,
                            def.variants.iter().flat_map(|variant| variant.fields.iter()),
                        );
                    }
                    Self::validate_declared_abilities("enum", &def.name, &def.abilities, def.span)?;
                    Self::validate_phantom_layout_usage(
                        &def.name,
                        &def.type_params,
                        def.variants.iter().flat_map(|variant| variant.fields.iter()),
                    )?;
                    this.enums.insert(def.name.clone(), def);
                }
                Item::Function(def) if !def.type_params.is_empty() => {
                    Self::validate_type_params("function", &def.name, &def.type_params, def.span)?;
                    if def.type_params.iter().any(|param| param.phantom) {
                        return Err(generic_declaration_error(
                            "phantom parameters are only valid on struct and enum declarations",
                            def.span,
                        ));
                    }
                    this.functions.insert(def.name.clone(), def.clone());
                }
                _ => {}
            }
        }

        Ok(this)
    }

    fn register_external_items(&mut self, external_items: &[ExternalGenericItem]) -> Result<()> {
        for external in external_items {
            match &external.item {
                Item::Resource(_) | Item::Shared(_) | Item::Receipt(_) => {
                    self.cell_types.insert(external.local_name.clone());
                }
                Item::Struct(def) if def.type_params.is_empty() => {
                    self.concrete_struct_abilities.insert(external.local_name.clone(), def.abilities.clone());
                    self.concrete_struct_fields
                        .insert(external.local_name.clone(), def.fields.iter().map(|field| field.ty.clone()).collect());
                }
                Item::Struct(def) => {
                    self.structs.insert(external.local_name.clone(), def.clone());
                    self.external_origins.insert(
                        external.local_name.clone(),
                        ExternalOrigin {
                            owner_module: external.owner_module.clone(),
                            source_name: external.source_name.clone(),
                            kind: TemplateKind::Struct,
                        },
                    );
                }
                Item::Enum(def) if def.type_params.is_empty() => {
                    self.concrete_enum_abilities.insert(external.local_name.clone(), def.abilities.clone());
                    self.concrete_enum_fields.insert(
                        external.local_name.clone(),
                        def.variants.iter().flat_map(|variant| variant.fields.iter().cloned()).collect(),
                    );
                }
                Item::Enum(def) => {
                    self.enums.insert(external.local_name.clone(), def.clone());
                    self.external_origins.insert(
                        external.local_name.clone(),
                        ExternalOrigin {
                            owner_module: external.owner_module.clone(),
                            source_name: external.source_name.clone(),
                            kind: TemplateKind::Enum,
                        },
                    );
                }
                Item::Function(def) if !def.type_params.is_empty() => {
                    self.functions.insert(external.local_name.clone(), def.clone());
                    self.external_origins.insert(
                        external.local_name.clone(),
                        ExternalOrigin {
                            owner_module: external.owner_module.clone(),
                            source_name: external.source_name.clone(),
                            kind: TemplateKind::Function,
                        },
                    );
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn seed(&mut self, seeds: &[SeedInstantiation]) -> Result<()> {
        for seed in seeds {
            let kind = if self.structs.contains_key(&seed.base) {
                TemplateKind::Struct
            } else if self.enums.contains_key(&seed.base) {
                TemplateKind::Enum
            } else if self.functions.contains_key(&seed.base) {
                TemplateKind::Function
            } else {
                return Err(generic_instantiation_error(
                    format!("unknown generic template '{}' requested by another module", seed.base),
                    seed.span,
                ));
            };
            self.enqueue(kind, &seed.base, seed.args.clone(), seed.span)?;
        }
        Ok(())
    }

    fn run(&mut self, module: &Module) -> Result<Module> {
        let interface_templates = module
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Struct(def) if !def.type_params.is_empty() => self.structs.get(&def.name).cloned().map(Item::Struct),
                Item::Enum(def) if !def.type_params.is_empty() => self.enums.get(&def.name).cloned().map(Item::Enum),
                Item::Function(def) if !def.type_params.is_empty() => self.functions.get(&def.name).cloned().map(Item::Function),
                _ => None,
            })
            .collect::<Vec<_>>();
        let mut items = Vec::with_capacity(module.items.len());
        for item in &module.items {
            if matches!(item, Item::Struct(def) if !def.type_params.is_empty())
                || matches!(item, Item::Enum(def) if !def.type_params.is_empty())
                || matches!(item, Item::Function(def) if !def.type_params.is_empty())
            {
                continue;
            }
            items.push(self.rewrite_item(item.clone(), &HashMap::new())?);
        }

        while let Some(key) = self.pending.keys().next().cloned() {
            let request = self.pending.remove(&key).expect("pending generic request exists");
            if !self.emitted.insert(key) {
                continue;
            }
            if self.emitted.len() > MAX_GENERIC_INSTANTIATIONS {
                return Err(generic_budget_error(
                    format!("generic instantiation count exceeds the limit of {}", MAX_GENERIC_INSTANTIATIONS),
                    request.span,
                ));
            }
            let item = self.instantiate(request)?;
            items.push(item);
        }

        let mut visibilities = module.visibilities.clone();
        for item in &items {
            let Some(name) = item_decl_name(item) else { continue };
            let visibility = if decode_monomorph_name(name).is_some() { Visibility::Private } else { module.visibility_of(name) };
            visibilities.insert(name.to_string(), visibility);
        }
        Ok(Module { name: module.name.clone(), items, interface_templates, visibilities, span: module.span })
    }

    fn validate_type_params(kind: &str, name: &str, params: &[TypeParam], span: Span) -> Result<()> {
        let mut seen = HashSet::new();
        for param in params {
            if !seen.insert(param.name.clone()) {
                return Err(generic_declaration_error(
                    format!("duplicate type parameter '{}' on {} '{}'", param.name, kind, name),
                    param.span,
                ));
            }
            if primitive_type_name(&param.name).is_some() || param.name == "Self" {
                return Err(generic_declaration_error(
                    format!("type parameter '{}' on {} '{}' uses a reserved type name", param.name, kind, name),
                    param.span,
                ));
            }
            if param.constraints.contains(&ValueAbility::Cell) && param.constraints.contains(&ValueAbility::NonLinear) {
                return Err(generic_declaration_error(
                    format!("type parameter '{}' cannot require both cell and non_linear", param.name),
                    param.span,
                ));
            }
        }
        if params.is_empty() {
            return Err(generic_declaration_error(format!("{} '{}' has an empty generic parameter list", kind, name), span));
        }
        Ok(())
    }

    fn validate_declared_abilities(kind: &str, name: &str, abilities: &[ValueAbility], span: Span) -> Result<()> {
        if abilities.contains(&ValueAbility::Cell) {
            return Err(generic_declaration_error(
                format!(
                    "{} '{}' cannot declare the cell value ability; Cell lifecycle authority remains on resource/shared/receipt capabilities",
                    kind, name
                ),
                span,
            ));
        }
        Ok(())
    }

    fn validate_public_layout_params(kind: &str, name: &str, params: &[TypeParam]) -> Result<()> {
        for param in params.iter().filter(|param| !param.phantom) {
            let missing = [ValueAbility::Fixed, ValueAbility::Serializable, ValueAbility::NonLinear]
                .into_iter()
                .filter(|ability| !param.constraints.contains(ability))
                .map(ValueAbility::as_str)
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                return Err(generic_declaration_error(
                    format!(
                        "public generic {} '{}' parameter '{}' must preserve the fixed value layout boundary; add 'fixed_value' or the missing constraint(s): {}",
                        kind,
                        name,
                        param.name,
                        missing.join(", ")
                    ),
                    param.span,
                ));
            }
        }
        Ok(())
    }

    fn validate_phantom_layout_usage<'a>(
        owner: &str,
        params: &[TypeParam],
        field_types: impl Iterator<Item = &'a Type>,
    ) -> Result<()> {
        let fields = field_types.collect::<Vec<_>>();
        for param in params {
            let used = fields.iter().any(|ty| type_contains_param(ty, &param.name));
            if param.phantom && used {
                return Err(generic_declaration_error(
                    format!(
                        "phantom type parameter '{}' on '{}' appears in serialized layout; remove phantom or remove the field use",
                        param.name, owner
                    ),
                    param.span,
                ));
            }
            if !param.phantom && !used {
                return Err(generic_declaration_error(
                    format!(
                        "type parameter '{}' on '{}' does not affect layout; declare it as 'phantom {}' to make identity-only use explicit",
                        param.name, owner, param.name
                    ),
                    param.span,
                ));
            }
        }
        Ok(())
    }

    fn instantiate(&mut self, request: Instantiation) -> Result<Item> {
        match request.kind {
            TemplateKind::Struct => {
                let template =
                    self.structs.get(&request.base).cloned().ok_or_else(|| {
                        generic_instantiation_error(format!("unknown generic struct '{}'", request.base), request.span)
                    })?;
                let substitution =
                    self.validate_instantiation(&template.type_params, &request.args, TemplateKind::Struct, request.span)?;
                let mut concrete = template;
                concrete.name = monomorph_name(&request.base, &request.args, request.span)?;
                concrete.type_params.clear();
                let mut context = RewriteContext::default();
                for field in &mut concrete.fields {
                    field.ty = self.rewrite_type(&field.ty, &substitution, request.span, &mut context)?;
                }
                if let Some(validity) = &mut concrete.validity {
                    validity.predicates = validity
                        .predicates
                        .iter()
                        .cloned()
                        .map(|expr| self.rewrite_expr(expr, &substitution, &mut context))
                        .collect::<Result<Vec<_>>>()?;
                }
                self.validate_concrete_abilities(
                    &concrete.name,
                    &concrete.abilities,
                    concrete.fields.iter().map(|field| &field.ty),
                    concrete.span,
                )?;
                self.concrete_struct_abilities.insert(concrete.name.clone(), concrete.abilities.clone());
                self.concrete_struct_fields
                    .insert(concrete.name.clone(), concrete.fields.iter().map(|field| field.ty.clone()).collect());
                Ok(Item::Struct(concrete))
            }
            TemplateKind::Enum => {
                let template =
                    self.enums.get(&request.base).cloned().ok_or_else(|| {
                        generic_instantiation_error(format!("unknown generic enum '{}'", request.base), request.span)
                    })?;
                let substitution =
                    self.validate_instantiation(&template.type_params, &request.args, TemplateKind::Enum, request.span)?;
                let mut concrete = template;
                concrete.name = monomorph_name(&request.base, &request.args, request.span)?;
                concrete.type_params.clear();
                let mut context = RewriteContext::default();
                for variant in &mut concrete.variants {
                    for field in &mut variant.fields {
                        *field = self.rewrite_type(field, &substitution, request.span, &mut context)?;
                    }
                }
                self.validate_concrete_abilities(
                    &concrete.name,
                    &concrete.abilities,
                    concrete.variants.iter().flat_map(|variant| variant.fields.iter()),
                    concrete.span,
                )?;
                self.concrete_enum_abilities.insert(concrete.name.clone(), concrete.abilities.clone());
                self.concrete_enum_fields.insert(
                    concrete.name.clone(),
                    concrete.variants.iter().flat_map(|variant| variant.fields.iter().cloned()).collect(),
                );
                Ok(Item::Enum(concrete))
            }
            TemplateKind::Function => {
                let template = self.functions.get(&request.base).cloned().ok_or_else(|| {
                    generic_instantiation_error(format!("unknown generic function '{}'", request.base), request.span)
                })?;
                let substitution =
                    self.validate_instantiation(&template.type_params, &request.args, TemplateKind::Function, request.span)?;
                let mut concrete = template;
                concrete.name = monomorph_name(&request.base, &request.args, request.span)?;
                concrete.type_params.clear();
                let mut context = RewriteContext::default();
                for param in &mut concrete.params {
                    param.ty = self.rewrite_type(&param.ty, &substitution, request.span, &mut context)?;
                }
                concrete.return_type = concrete
                    .return_type
                    .as_ref()
                    .map(|ty| self.rewrite_type(ty, &substitution, request.span, &mut context))
                    .transpose()?;
                concrete.body = concrete
                    .body
                    .into_iter()
                    .map(|stmt| self.rewrite_stmt(stmt, &substitution, &mut context))
                    .collect::<Result<Vec<_>>>()?;
                Ok(Item::Function(concrete))
            }
        }
    }

    fn validate_instantiation(
        &self,
        params: &[TypeParam],
        args: &[Type],
        kind: TemplateKind,
        span: Span,
    ) -> Result<HashMap<String, Type>> {
        if params.len() != args.len() {
            return Err(generic_instantiation_error(
                format!("generic declaration expects {} type argument(s), got {}", params.len(), args.len()),
                span,
            ));
        }
        let mut substitution = HashMap::new();
        for (param, actual) in params.iter().zip(args) {
            if type_nesting(actual) > MAX_GENERIC_NESTING {
                return Err(generic_budget_error(
                    format!("type argument for '{}' exceeds generic nesting limit {}", param.name, MAX_GENERIC_NESTING),
                    span,
                ));
            }
            let actual_abilities = self.abilities_for_type(actual, &mut HashSet::new());
            let cell_backed = actual_abilities.contains(&ValueAbility::Cell);
            match kind {
                TemplateKind::Struct | TemplateKind::Enum if cell_backed && !param.phantom => {
                    return Err(generic_instantiation_error(
                        format!(
                            "Cell-backed type '{}' cannot be hidden in ordinary generic layout parameter '{}'; use an explicit Cell collection/flow primitive",
                            render_type(actual),
                            param.name
                        ),
                        span,
                    ));
                }
                TemplateKind::Function if cell_backed && !param.constraints.contains(&ValueAbility::Cell) => {
                    return Err(generic_instantiation_error(
                        format!(
                            "generic function parameter '{}' received Cell-backed type '{}' without an explicit 'cell' constraint",
                            param.name,
                            render_type(actual)
                        ),
                        span,
                    ));
                }
                _ => {}
            }
            for required in &param.constraints {
                if !actual_abilities.contains(required) {
                    return Err(generic_instantiation_error(
                        format!(
                            "type argument '{}' for '{}' does not satisfy '{}' (value-ability registry v{})",
                            render_type(actual),
                            param.name,
                            required.as_str(),
                            ValueAbility::REGISTRY_VERSION
                        ),
                        span,
                    ));
                }
            }

            match kind {
                TemplateKind::Struct | TemplateKind::Enum if !param.phantom => {
                    for required in [ValueAbility::Fixed, ValueAbility::Serializable, ValueAbility::NonLinear] {
                        if !actual_abilities.contains(&required) {
                            return Err(generic_instantiation_error(
                                format!(
                                    "layout type argument '{}' for '{}' must satisfy '{}' in the 0.25 fixed-value kernel",
                                    render_type(actual),
                                    param.name,
                                    required.as_str()
                                ),
                                span,
                            ));
                        }
                    }
                }
                _ => {}
            }
            substitution.insert(param.name.clone(), actual.clone());
        }
        Ok(substitution)
    }

    fn validate_concrete_abilities<'a>(
        &self,
        name: &str,
        declared: &[ValueAbility],
        fields: impl Iterator<Item = &'a Type>,
        span: Span,
    ) -> Result<()> {
        let field_types = fields.collect::<Vec<_>>();
        for ability in declared {
            if field_types.iter().any(|field| !self.abilities_for_type(field, &mut HashSet::new()).contains(ability)) {
                return Err(generic_instantiation_error(
                    format!("type '{}' declares '{}' but at least one field does not satisfy it", name, ability.as_str()),
                    span,
                ));
            }
        }
        Ok(())
    }

    fn abilities_for_type(&self, ty: &Type, visiting: &mut HashSet<String>) -> HashSet<ValueAbility> {
        let all_plain = || {
            [
                ValueAbility::Copy,
                ValueAbility::Drop,
                ValueAbility::Store,
                ValueAbility::Fixed,
                ValueAbility::Serializable,
                ValueAbility::NonLinear,
            ]
            .into_iter()
            .collect()
        };
        match ty {
            Type::U8
            | Type::U16
            | Type::U32
            | Type::I32
            | Type::U64
            | Type::U128
            | Type::Bool
            | Type::Unit
            | Type::Address
            | Type::Hash => all_plain(),
            Type::Array(inner, _) => self.abilities_for_type(inner, visiting),
            Type::Tuple(items) => intersect_abilities(items.iter().map(|item| self.abilities_for_type(item, visiting))),
            Type::Ref(_) | Type::MutRef(_) => [ValueAbility::Copy, ValueAbility::Drop, ValueAbility::NonLinear].into_iter().collect(),
            Type::Named(name) => {
                let decoded = decode_monomorph_name(name);
                let base = decoded
                    .as_ref()
                    .map(|(base, _)| base.as_str())
                    .or_else(|| applied_type(name).map(|(base, _)| base))
                    .unwrap_or(name.as_str());
                if self.cell_types.contains(base) {
                    return [ValueAbility::Cell, ValueAbility::Fixed, ValueAbility::Serializable].into_iter().collect();
                }
                if matches!(base, "usize" | "isize") {
                    return all_plain();
                }
                if base == "String" || base == "Vec" {
                    return [
                        ValueAbility::Copy,
                        ValueAbility::Drop,
                        ValueAbility::Store,
                        ValueAbility::Serializable,
                        ValueAbility::NonLinear,
                    ]
                    .into_iter()
                    .collect();
                }
                if let Some(abilities) = self
                    .concrete_struct_abilities
                    .get(name)
                    .or_else(|| self.concrete_enum_abilities.get(name))
                    .or_else(|| self.structs.get(base).map(|def| &def.abilities))
                    .or_else(|| self.enums.get(base).map(|def| &def.abilities))
                {
                    let mut result = abilities.iter().copied().collect::<HashSet<_>>();
                    if !visiting.insert(name.clone()) {
                        return HashSet::new();
                    }
                    let contains_cell = self
                        .structural_field_types(name, base)
                        .iter()
                        .any(|field| self.abilities_for_type(field, visiting).contains(&ValueAbility::Cell));
                    visiting.remove(name);
                    if contains_cell {
                        result.retain(|ability| matches!(ability, ValueAbility::Fixed | ValueAbility::Serializable));
                        result.insert(ValueAbility::Cell);
                    } else {
                        result.insert(ValueAbility::NonLinear);
                    }
                    return result;
                }
                if !visiting.insert(name.clone()) {
                    return HashSet::new();
                }
                visiting.remove(name);
                HashSet::new()
            }
        }
    }

    fn structural_field_types(&self, name: &str, base: &str) -> Vec<Type> {
        if let Some(fields) = self.concrete_struct_fields.get(name).or_else(|| self.concrete_struct_fields.get(base)) {
            return fields.clone();
        }
        if let Some(fields) = self.concrete_enum_fields.get(name).or_else(|| self.concrete_enum_fields.get(base)) {
            return fields.clone();
        }

        let arguments = decode_monomorph_name(name)
            .map(|(_, arguments)| arguments)
            .or_else(|| applied_type(name).map(|(_, arguments)| arguments))
            .unwrap_or_default();
        let arguments = arguments.iter().filter_map(|argument| parse_type_repr(argument)).collect::<Vec<_>>();

        if let Some(template) = self.structs.get(base).filter(|template| template.type_params.len() == arguments.len()) {
            let substitution = template
                .type_params
                .iter()
                .zip(arguments.iter().cloned())
                .map(|(parameter, argument)| (parameter.name.clone(), argument))
                .collect::<HashMap<_, _>>();
            return template.fields.iter().filter_map(|field| substitute_type_pure(&field.ty, &substitution)).collect();
        }
        if let Some(template) = self.enums.get(base).filter(|template| template.type_params.len() == arguments.len()) {
            let substitution = template
                .type_params
                .iter()
                .zip(arguments.iter().cloned())
                .map(|(parameter, argument)| (parameter.name.clone(), argument))
                .collect::<HashMap<_, _>>();
            return template
                .variants
                .iter()
                .flat_map(|variant| variant.fields.iter())
                .filter_map(|field| substitute_type_pure(field, &substitution))
                .collect();
        }
        Vec::new()
    }

    fn enqueue(&mut self, kind: TemplateKind, base: &str, args: Vec<Type>, span: Span) -> Result<String> {
        let name = monomorph_name(base, &args, span)?;
        if let Some(origin) = self.external_origins.get(base).filter(|origin| origin.kind == kind).cloned() {
            let params = match kind {
                TemplateKind::Struct => &self.structs.get(base).expect("registered external struct").type_params,
                TemplateKind::Enum => &self.enums.get(base).expect("registered external enum").type_params,
                TemplateKind::Function => &self.functions.get(base).expect("registered external function").type_params,
            };
            self.validate_instantiation(params, &args, kind, span)?;
            let owner_concrete_name = monomorph_name(&origin.source_name, &args, span)?;
            let key = format!("{}:{}:{}", origin.owner_module, kind_key(kind), owner_concrete_name);
            self.external_requests.entry(key).or_insert_with(|| ExternalInstantiationRequest {
                owner_module: origin.owner_module,
                source_name: origin.source_name.clone(),
                local_concrete_name: name.clone(),
                owner_concrete_name,
                seed: SeedInstantiation { base: origin.source_name, args, span },
            });
            if self.external_requests.len() + self.pending.len() + self.emitted.len() > MAX_GENERIC_INSTANTIATIONS {
                return Err(generic_budget_error(
                    format!("generic instantiation count exceeds the limit of {}", MAX_GENERIC_INSTANTIATIONS),
                    span,
                ));
            }
            return Ok(name);
        }
        let key = format!("{}:{}", kind_key(kind), name);
        if !self.emitted.contains(&key) && !self.pending.contains_key(&key) {
            self.pending.insert(key, Instantiation { kind, base: base.to_string(), args, span });
        }
        Ok(name)
    }

    fn rewrite_item(&mut self, item: Item, substitution: &HashMap<String, Type>) -> Result<Item> {
        let mut context = RewriteContext::default();
        match item {
            Item::Resource(mut def) => {
                self.rewrite_fields_and_validity(&mut def.fields, &mut def.validity, substitution, &mut context, def.span)?;
                Ok(Item::Resource(def))
            }
            Item::Shared(mut def) => {
                self.rewrite_fields_and_validity(&mut def.fields, &mut def.validity, substitution, &mut context, def.span)?;
                Ok(Item::Shared(def))
            }
            Item::Receipt(mut def) => {
                self.rewrite_fields_and_validity(&mut def.fields, &mut def.validity, substitution, &mut context, def.span)?;
                def.claim_output =
                    def.claim_output.as_ref().map(|ty| self.rewrite_type(ty, substitution, def.span, &mut context)).transpose()?;
                Ok(Item::Receipt(def))
            }
            Item::Struct(mut def) => {
                self.rewrite_fields_and_validity(&mut def.fields, &mut def.validity, substitution, &mut context, def.span)?;
                self.validate_concrete_abilities(&def.name, &def.abilities, def.fields.iter().map(|field| &field.ty), def.span)?;
                Ok(Item::Struct(def))
            }
            Item::Enum(mut def) => {
                for variant in &mut def.variants {
                    for ty in &mut variant.fields {
                        *ty = self.rewrite_type(ty, substitution, variant.span, &mut context)?;
                    }
                }
                self.validate_concrete_abilities(
                    &def.name,
                    &def.abilities,
                    def.variants.iter().flat_map(|variant| variant.fields.iter()),
                    def.span,
                )?;
                Ok(Item::Enum(def))
            }
            Item::Const(mut def) => {
                def.ty = self.rewrite_type(&def.ty, substitution, def.span, &mut context)?;
                def.value = self.rewrite_expr(def.value, substitution, &mut context)?;
                Ok(Item::Const(def))
            }
            Item::Action(mut def) => {
                self.rewrite_params(&mut def.params, substitution, &mut context)?;
                def.return_type =
                    def.return_type.as_ref().map(|ty| self.rewrite_type(ty, substitution, def.span, &mut context)).transpose()?;
                for output in &mut def.outputs {
                    output.ty = self.rewrite_type(&output.ty, substitution, output.span, &mut context)?;
                }
                def.body = def
                    .body
                    .into_iter()
                    .map(|stmt| self.rewrite_stmt(stmt, substitution, &mut context))
                    .collect::<Result<Vec<_>>>()?;
                Ok(Item::Action(def))
            }
            Item::Function(mut def) => {
                self.rewrite_params(&mut def.params, substitution, &mut context)?;
                def.return_type =
                    def.return_type.as_ref().map(|ty| self.rewrite_type(ty, substitution, def.span, &mut context)).transpose()?;
                def.body = def
                    .body
                    .into_iter()
                    .map(|stmt| self.rewrite_stmt(stmt, substitution, &mut context))
                    .collect::<Result<Vec<_>>>()?;
                Ok(Item::Function(def))
            }
            Item::Lock(mut def) => {
                self.rewrite_params(&mut def.params, substitution, &mut context)?;
                def.return_type = self.rewrite_type(&def.return_type, substitution, def.span, &mut context)?;
                def.body = def
                    .body
                    .into_iter()
                    .map(|stmt| self.rewrite_stmt(stmt, substitution, &mut context))
                    .collect::<Result<Vec<_>>>()?;
                Ok(Item::Lock(def))
            }
            Item::Invariant(mut def) => {
                for target in &mut def.reads {
                    self.rewrite_aggregate_target(target, substitution, &mut context)?;
                }
                for aggregate in &mut def.aggregates {
                    self.rewrite_aggregate_target(&mut aggregate.target, substitution, &mut context)?;
                    if let Some(rhs) = &mut aggregate.rhs {
                        self.rewrite_aggregate_target(rhs, substitution, &mut context)?;
                    }
                }
                for quantifier in &mut def.quantifiers {
                    self.rewrite_aggregate_target(&mut quantifier.range, substitution, &mut context)?;
                    quantifier.predicates = quantifier
                        .predicates
                        .iter()
                        .cloned()
                        .map(|expr| self.rewrite_expr(expr, substitution, &mut context))
                        .collect::<Result<Vec<_>>>()?;
                    quantifier.expected =
                        quantifier.expected.take().map(|expr| self.rewrite_expr(expr, substitution, &mut context)).transpose()?;
                }
                def.asserts = def
                    .asserts
                    .into_iter()
                    .map(|expr| self.rewrite_expr(expr, substitution, &mut context))
                    .collect::<Result<Vec<_>>>()?;
                Ok(Item::Invariant(def))
            }
            Item::Flow(def) => Ok(Item::Flow(def)),
            Item::Use(def) => Ok(Item::Use(def)),
        }
    }

    fn rewrite_fields_and_validity(
        &mut self,
        fields: &mut [Field],
        validity: &mut Option<ValidityBlock>,
        substitution: &HashMap<String, Type>,
        context: &mut RewriteContext,
        span: Span,
    ) -> Result<()> {
        for field in fields {
            field.ty = self.rewrite_type(&field.ty, substitution, field.span, context)?;
        }
        if let Some(validity) = validity {
            validity.predicates = validity
                .predicates
                .iter()
                .cloned()
                .map(|expr| self.rewrite_expr(expr, substitution, context))
                .collect::<Result<Vec<_>>>()?;
        }
        let _ = span;
        Ok(())
    }

    fn rewrite_params(
        &mut self,
        params: &mut [Param],
        substitution: &HashMap<String, Type>,
        context: &mut RewriteContext,
    ) -> Result<()> {
        for param in params {
            param.ty = self.rewrite_type(&param.ty, substitution, param.span, context)?;
            context.bindings.insert(param.name.clone(), param.ty.clone());
        }
        Ok(())
    }

    fn rewrite_aggregate_target(
        &mut self,
        target: &mut AggregateTarget,
        substitution: &HashMap<String, Type>,
        context: &mut RewriteContext,
    ) -> Result<()> {
        if let Some(name) = target.type_name.take() {
            target.type_name = Some(self.rewrite_type_name(&name, substitution, Span::default(), context)?);
        }
        Ok(())
    }

    fn rewrite_type(
        &mut self,
        ty: &Type,
        substitution: &HashMap<String, Type>,
        span: Span,
        context: &mut RewriteContext,
    ) -> Result<Type> {
        match ty {
            Type::Named(name) if substitution.contains_key(name) => {
                let substituted = substitution.get(name).expect("checked substitution").clone();
                self.rewrite_type(&substituted, &HashMap::new(), span, context)
            }
            Type::Named(name) => Ok(Type::Named(self.rewrite_type_name(name, substitution, span, context)?)),
            Type::Array(inner, len) => Ok(Type::Array(Box::new(self.rewrite_type(inner, substitution, span, context)?), *len)),
            Type::Tuple(items) => Ok(Type::Tuple(
                items.iter().map(|item| self.rewrite_type(item, substitution, span, context)).collect::<Result<Vec<_>>>()?,
            )),
            Type::Ref(inner) => Ok(Type::Ref(Box::new(self.rewrite_type(inner, substitution, span, context)?))),
            Type::MutRef(inner) => Ok(Type::MutRef(Box::new(self.rewrite_type(inner, substitution, span, context)?))),
            primitive => Ok(primitive.clone()),
        }
    }

    fn rewrite_type_name(
        &mut self,
        name: &str,
        substitution: &HashMap<String, Type>,
        span: Span,
        context: &mut RewriteContext,
    ) -> Result<String> {
        if let Some(actual) = substitution.get(name) {
            return match self.rewrite_type(actual, &HashMap::new(), span, context)? {
                Type::Named(name) => Ok(name),
                other => Ok(render_type(&other)),
            };
        }
        let Some((base, arg_texts)) = applied_type(name) else {
            return Ok(name.to_string());
        };
        let mut args = Vec::with_capacity(arg_texts.len());
        for text in arg_texts {
            let parsed = parse_type_repr(&text).ok_or_else(|| {
                generic_instantiation_error(format!("cannot parse generic type argument '{}' in '{}'", text, name), span)
            })?;
            args.push(self.rewrite_type(&parsed, substitution, span, context)?);
        }
        let concrete = if self.structs.contains_key(base) {
            self.enqueue(TemplateKind::Struct, base, args.clone(), span)?
        } else if self.enums.contains_key(base) {
            self.enqueue(TemplateKind::Enum, base, args.clone(), span)?
        } else {
            format!("{}<{}>", base, args.iter().map(render_type).collect::<Vec<_>>().join(", "))
        };
        if self.structs.contains_key(base) || self.enums.contains_key(base) {
            context.record_applied_type(base, &concrete);
        }
        Ok(concrete)
    }

    fn rewrite_stmt(&mut self, stmt: Stmt, substitution: &HashMap<String, Type>, context: &mut RewriteContext) -> Result<Stmt> {
        match stmt {
            Stmt::Let(mut stmt) => {
                stmt.ty = stmt.ty.as_ref().map(|ty| self.rewrite_type(ty, substitution, stmt.span, context)).transpose()?;
                stmt.value = self.rewrite_expr(stmt.value, substitution, context)?;
                if let Some(ty) = stmt.ty.clone().or_else(|| self.infer_rewrite_expr_type(&stmt.value, context)) {
                    context.bind_pattern(&stmt.pattern, &ty);
                }
                Ok(Stmt::Let(stmt))
            }
            Stmt::Expr(expr) => Ok(Stmt::Expr(self.rewrite_expr(expr, substitution, context)?)),
            Stmt::Return(mut stmt) => {
                stmt.value = stmt.value.map(|expr| self.rewrite_expr(expr, substitution, context)).transpose()?;
                Ok(Stmt::Return(stmt))
            }
            Stmt::Break(_) | Stmt::Continue(_) => Ok(stmt),
            Stmt::If(mut stmt) => {
                stmt.condition = self.rewrite_expr(stmt.condition, substitution, context)?;
                stmt.then_branch = stmt
                    .then_branch
                    .into_iter()
                    .map(|stmt| self.rewrite_stmt(stmt, substitution, context))
                    .collect::<Result<Vec<_>>>()?;
                stmt.else_branch = stmt
                    .else_branch
                    .map(|branch| {
                        branch.into_iter().map(|stmt| self.rewrite_stmt(stmt, substitution, context)).collect::<Result<Vec<_>>>()
                    })
                    .transpose()?;
                Ok(Stmt::If(stmt))
            }
            Stmt::For(mut stmt) => {
                stmt.iterable = self.rewrite_expr(stmt.iterable, substitution, context)?;
                stmt.body =
                    stmt.body.into_iter().map(|stmt| self.rewrite_stmt(stmt, substitution, context)).collect::<Result<Vec<_>>>()?;
                Ok(Stmt::For(stmt))
            }
            Stmt::While(mut stmt) => {
                stmt.condition = self.rewrite_expr(stmt.condition, substitution, context)?;
                stmt.body =
                    stmt.body.into_iter().map(|stmt| self.rewrite_stmt(stmt, substitution, context)).collect::<Result<Vec<_>>>()?;
                Ok(Stmt::While(stmt))
            }
            Stmt::Borrow(mut stmt) => {
                stmt.body =
                    stmt.body.into_iter().map(|stmt| self.rewrite_stmt(stmt, substitution, context)).collect::<Result<Vec<_>>>()?;
                Ok(Stmt::Borrow(stmt))
            }
        }
    }

    fn rewrite_expr(&mut self, expr: Expr, substitution: &HashMap<String, Type>, context: &mut RewriteContext) -> Result<Expr> {
        match expr {
            Expr::Integer(_) | Expr::Bool(_) | Expr::String(_) | Expr::ByteString(_) | Expr::Identifier(_) => Ok(expr),
            Expr::Assign(mut value) => {
                value.target = Box::new(self.rewrite_expr(*value.target, substitution, context)?);
                value.value = Box::new(self.rewrite_expr(*value.value, substitution, context)?);
                Ok(Expr::Assign(value))
            }
            Expr::Binary(mut value) => {
                value.left = Box::new(self.rewrite_expr(*value.left, substitution, context)?);
                value.right = Box::new(self.rewrite_expr(*value.right, substitution, context)?);
                Ok(Expr::Binary(value))
            }
            Expr::Unary(mut value) => {
                value.expr = Box::new(self.rewrite_expr(*value.expr, substitution, context)?);
                Ok(Expr::Unary(value))
            }
            Expr::Call(mut call) => {
                call.func = Box::new(self.rewrite_expr(*call.func, substitution, context)?);
                call.args =
                    call.args.into_iter().map(|arg| self.rewrite_expr(arg, substitution, context)).collect::<Result<Vec<_>>>()?;
                call.type_args = call
                    .type_args
                    .iter()
                    .map(|ty| self.rewrite_type(ty, substitution, call.span, context))
                    .collect::<Result<Vec<_>>>()?;

                let Expr::Identifier(path) = call.func.as_ref() else {
                    return Ok(Expr::Call(call));
                };
                let path = path.clone();
                if matches!(path.as_str(), "Option::unwrap" | "Option::expect" | "Option::unwrap_or") {
                    let helper = path.rsplit_once("::").map_or(path.as_str(), |(_, helper)| helper);
                    return Err(CompileError::new(
                        format!("{helper} is forbidden; use explicit match-based error handling"),
                        call.span,
                    ));
                }
                if self.functions.contains_key(&path) {
                    let type_args = if call.type_args.is_empty() {
                        let template = self.functions.get(&path).cloned().expect("known generic function");
                        self.infer_function_type_args(&template, &call.args, context, call.span)?
                    } else {
                        call.type_args.clone()
                    };
                    let concrete = self.enqueue(TemplateKind::Function, &path, type_args, call.span)?;
                    call.func = Box::new(Expr::Identifier(concrete));
                    call.type_args.clear();
                    return Ok(Expr::Call(call));
                }

                if let Some((enum_name, variant)) = path.rsplit_once("::")
                    && self.enums.contains_key(enum_name)
                {
                    if call.type_args.is_empty() {
                        return Err(generic_instantiation_error(
                            format!("generic enum constructor '{}::{}' requires explicit type arguments", enum_name, variant),
                            call.span,
                        ));
                    }
                    let concrete = self.enqueue(TemplateKind::Enum, enum_name, call.type_args.clone(), call.span)?;
                    context.record_applied_type(enum_name, &concrete);
                    let no_payload = self
                        .enums
                        .get(enum_name)
                        .and_then(|def| def.variants.iter().find(|candidate| candidate.name == variant))
                        .is_some_and(|variant| variant.fields.is_empty());
                    if no_payload && call.args.is_empty() {
                        return Ok(Expr::Identifier(format!("{}::{}", concrete, variant)));
                    }
                    call.func = Box::new(Expr::Identifier(format!("{}::{}", concrete, variant)));
                    call.type_args.clear();
                }
                Ok(Expr::Call(call))
            }
            Expr::FieldAccess(mut value) => {
                value.expr = Box::new(self.rewrite_expr(*value.expr, substitution, context)?);
                Ok(Expr::FieldAccess(value))
            }
            Expr::Index(mut value) => {
                value.expr = Box::new(self.rewrite_expr(*value.expr, substitution, context)?);
                value.index = Box::new(self.rewrite_expr(*value.index, substitution, context)?);
                Ok(Expr::Index(value))
            }
            Expr::Create(mut value) => {
                value.ty = self.rewrite_type_name(&value.ty, substitution, value.span, context)?;
                value.fields = self.rewrite_field_values(value.fields, substitution, context)?;
                value.lock = value.lock.map(|lock| self.rewrite_expr(*lock, substitution, context).map(Box::new)).transpose()?;
                Ok(Expr::Create(value))
            }
            Expr::Consume(mut value) => {
                value.expr = Box::new(self.rewrite_expr(*value.expr, substitution, context)?);
                Ok(Expr::Consume(value))
            }
            Expr::Destroy(mut value) => {
                value.expr = Box::new(self.rewrite_expr(*value.expr, substitution, context)?);
                Ok(Expr::Destroy(value))
            }
            Expr::ReadRef(mut value) => {
                value.ty = self.rewrite_type_name(&value.ty, substitution, value.span, context)?;
                Ok(Expr::ReadRef(value))
            }
            Expr::Claim(mut value) => {
                value.receipt = Box::new(self.rewrite_expr(*value.receipt, substitution, context)?);
                Ok(Expr::Claim(value))
            }
            Expr::Settle(mut value) => {
                value.expr = Box::new(self.rewrite_expr(*value.expr, substitution, context)?);
                Ok(Expr::Settle(value))
            }
            Expr::CreateUnique(mut value) => {
                value.ty = self.rewrite_type_name(&value.ty, substitution, value.span, context)?;
                value.fields = self.rewrite_field_values(value.fields, substitution, context)?;
                value.lock = value.lock.map(|lock| self.rewrite_expr(*lock, substitution, context).map(Box::new)).transpose()?;
                Ok(Expr::CreateUnique(value))
            }
            Expr::ReplaceUnique(mut value) => {
                value.expr = Box::new(self.rewrite_expr(*value.expr, substitution, context)?);
                value.ty = self.rewrite_type_name(&value.ty, substitution, value.span, context)?;
                value.fields = self.rewrite_field_values(value.fields, substitution, context)?;
                Ok(Expr::ReplaceUnique(value))
            }
            Expr::Assert(mut value) => {
                value.condition = Box::new(self.rewrite_expr(*value.condition, substitution, context)?);
                value.message = Box::new(self.rewrite_expr(*value.message, substitution, context)?);
                Ok(Expr::Assert(value))
            }
            Expr::Require(mut value) => {
                value.condition = Box::new(self.rewrite_expr(*value.condition, substitution, context)?);
                value.message =
                    value.message.map(|message| self.rewrite_expr(*message, substitution, context).map(Box::new)).transpose()?;
                Ok(Expr::Require(value))
            }
            Expr::RequireBlock(mut value) => {
                value.expressions = value
                    .expressions
                    .into_iter()
                    .map(|expr| self.rewrite_expr(expr, substitution, context))
                    .collect::<Result<Vec<_>>>()?;
                Ok(Expr::RequireBlock(value))
            }
            Expr::Preserve(_) => Ok(expr),
            Expr::ReplaceRelation(_) => Ok(expr),
            Expr::Block(stmts) => Ok(Expr::Block(
                stmts.into_iter().map(|stmt| self.rewrite_stmt(stmt, substitution, context)).collect::<Result<Vec<_>>>()?,
            )),
            Expr::Tuple(items) => Ok(Expr::Tuple(
                items.into_iter().map(|expr| self.rewrite_expr(expr, substitution, context)).collect::<Result<Vec<_>>>()?,
            )),
            Expr::Array(items) => Ok(Expr::Array(
                items.into_iter().map(|expr| self.rewrite_expr(expr, substitution, context)).collect::<Result<Vec<_>>>()?,
            )),
            Expr::If(mut value) => {
                value.condition = Box::new(self.rewrite_expr(*value.condition, substitution, context)?);
                value.then_branch = Box::new(self.rewrite_expr(*value.then_branch, substitution, context)?);
                value.else_branch = Box::new(self.rewrite_expr(*value.else_branch, substitution, context)?);
                Ok(Expr::If(value))
            }
            Expr::Cast(mut value) => {
                value.expr = Box::new(self.rewrite_expr(*value.expr, substitution, context)?);
                value.ty = self.rewrite_type(&value.ty, substitution, value.span, context)?;
                Ok(Expr::Cast(value))
            }
            Expr::Range(mut value) => {
                value.start = Box::new(self.rewrite_expr(*value.start, substitution, context)?);
                value.end = Box::new(self.rewrite_expr(*value.end, substitution, context)?);
                Ok(Expr::Range(value))
            }
            Expr::StructInit(mut value) => {
                value.ty = self.rewrite_type_name(&value.ty, substitution, value.span, context)?;
                value.fields = self.rewrite_field_values(value.fields, substitution, context)?;
                Ok(Expr::StructInit(value))
            }
            Expr::Match(mut value) => {
                value.expr = Box::new(self.rewrite_expr(*value.expr, substitution, context)?);
                for arm in &mut value.arms {
                    self.rewrite_match_pattern(&mut arm.pattern, context, arm.span)?;
                    arm.value = self.rewrite_expr(arm.value.clone(), substitution, context)?;
                }
                Ok(Expr::Match(value))
            }
            Expr::StdlibCall(mut value) => {
                value.args =
                    value.args.into_iter().map(|arg| self.rewrite_expr(arg, substitution, context)).collect::<Result<Vec<_>>>()?;
                Ok(Expr::StdlibCall(value))
            }
        }
    }

    fn rewrite_match_pattern(&self, pattern: &mut MatchPattern, context: &RewriteContext, span: Span) -> Result<()> {
        match pattern {
            MatchPattern::Wildcard | MatchPattern::Binding(_) => Ok(()),
            MatchPattern::Tuple(items) | MatchPattern::Or(items) => {
                for item in items {
                    self.rewrite_match_pattern(item, context, span)?;
                }
                Ok(())
            }
            MatchPattern::Struct { path, fields } => {
                if self.structs.contains_key(path.as_str()) {
                    *path = context
                        .concrete_type(path)
                        .ok_or_else(|| {
                            generic_instantiation_error(
                                format!("struct pattern '{}' is ambiguous; the callable must contain exactly one instantiation", path),
                                span,
                            )
                        })?
                        .to_string();
                }
                for (_, pattern) in fields {
                    self.rewrite_match_pattern(pattern, context, span)?;
                }
                Ok(())
            }
            MatchPattern::Variant { path, fields } => {
                if let Some((enum_name, variant)) = path.rsplit_once("::")
                    && self.enums.contains_key(enum_name)
                {
                    let concrete = context.concrete_type(enum_name).ok_or_else(|| {
                        generic_instantiation_error(
                            format!(
                                "match pattern '{}' is ambiguous; the callable must contain exactly one '{}' instantiation",
                                path, enum_name
                            ),
                            span,
                        )
                    })?;
                    *path = format!("{}::{}", concrete, variant);
                }
                for field in fields {
                    self.rewrite_match_pattern(field, context, span)?;
                }
                Ok(())
            }
        }
    }

    fn rewrite_field_values(
        &mut self,
        fields: Vec<(String, Expr)>,
        substitution: &HashMap<String, Type>,
        context: &mut RewriteContext,
    ) -> Result<Vec<(String, Expr)>> {
        fields.into_iter().map(|(name, value)| Ok((name, self.rewrite_expr(value, substitution, context)?))).collect()
    }

    fn infer_function_type_args(&self, template: &FnDef, args: &[Expr], context: &RewriteContext, span: Span) -> Result<Vec<Type>> {
        if template.params.len() != args.len() {
            return Err(generic_instantiation_error(
                format!(
                    "generic function '{}' expects {} value argument(s), got {}",
                    template.name,
                    template.params.len(),
                    args.len()
                ),
                span,
            ));
        }
        let param_names = template.type_params.iter().map(|param| param.name.as_str()).collect::<HashSet<_>>();
        let mut inferred = HashMap::<String, Type>::new();
        for (formal, expr) in template.params.iter().zip(args) {
            let Some(actual) = self.infer_rewrite_expr_type(expr, context) else {
                continue;
            };
            unify_generic_type(&formal.ty, &actual, &param_names, &mut inferred, span)?;
        }
        template
            .type_params
            .iter()
            .map(|param| {
                inferred.get(&param.name).cloned().ok_or_else(|| {
                    generic_instantiation_error(
                        format!(
                            "cannot infer type parameter '{}' for generic function '{}'; supply explicit type arguments",
                            param.name, template.name
                        ),
                        span,
                    )
                })
            })
            .collect()
    }

    fn infer_rewrite_expr_type(&self, expr: &Expr, context: &RewriteContext) -> Option<Type> {
        match expr {
            Expr::Integer(value) if *value <= u64::MAX as u128 => Some(Type::U64),
            Expr::Integer(_) => Some(Type::U128),
            Expr::Bool(_) => Some(Type::Bool),
            Expr::ByteString(bytes) => Some(Type::Array(Box::new(Type::U8), bytes.len())),
            Expr::Identifier(name) => context.bindings.get(name).cloned(),
            Expr::StructInit(value) => Some(Type::Named(value.ty.clone())),
            Expr::Array(items) if !items.is_empty() => {
                let first = self.infer_rewrite_expr_type(&items[0], context)?;
                items
                    .iter()
                    .skip(1)
                    .all(|item| self.infer_rewrite_expr_type(item, context).as_ref() == Some(&first))
                    .then(|| Type::Array(Box::new(first), items.len()))
            }
            Expr::Tuple(items) => {
                Some(Type::Tuple(items.iter().map(|item| self.infer_rewrite_expr_type(item, context)).collect::<Option<Vec<_>>>()?))
            }
            Expr::Cast(value) => Some(value.ty.clone()),
            Expr::FieldAccess(value) => {
                let owner = self.infer_rewrite_expr_type(&value.expr, context)?;
                let Type::Named(name) = owner else {
                    return None;
                };
                let base = generics_source_base(&name);
                let template = self.structs.get(base)?;
                let (_, args) = crate::generics::decode_monomorph_name(&name)?;
                let substitution = template
                    .type_params
                    .iter()
                    .zip(args.iter().filter_map(|arg| parse_type_repr(arg)))
                    .map(|(param, arg)| (param.name.clone(), arg))
                    .collect::<HashMap<_, _>>();
                let field = template.fields.iter().find(|field| field.name == value.field)?;
                substitute_type_pure(&field.ty, &substitution)
            }
            Expr::Call(call) => match call.func.as_ref() {
                Expr::Identifier(name) => {
                    let (base, args) = crate::generics::decode_monomorph_name(name)?;
                    let template = self.functions.get(&base)?;
                    let substitution = template
                        .type_params
                        .iter()
                        .zip(args.iter().filter_map(|arg| parse_type_repr(arg)))
                        .map(|(param, arg)| (param.name.clone(), arg))
                        .collect::<HashMap<_, _>>();
                    template.return_type.as_ref().and_then(|ty| substitute_type_pure(ty, &substitution))
                }
                _ => None,
            },
            _ => None,
        }
    }
}

fn intersect_abilities(sets: impl Iterator<Item = HashSet<ValueAbility>>) -> HashSet<ValueAbility> {
    let mut sets = sets.peekable();
    let Some(mut result) = sets.next() else {
        return ValueAbility::ALL.into_iter().filter(|ability| *ability != ValueAbility::Cell).collect();
    };
    for set in sets {
        result.retain(|ability| set.contains(ability));
    }
    result
}

fn generics_source_base(name: &str) -> &str {
    name.split_once(MONO_MARKER).map_or(name, |(base, _)| base)
}

fn unify_generic_type(
    formal: &Type,
    actual: &Type,
    params: &HashSet<&str>,
    inferred: &mut HashMap<String, Type>,
    span: Span,
) -> Result<()> {
    if let Type::Named(name) = formal
        && params.contains(name.as_str())
    {
        if let Some(previous) = inferred.get(name) {
            if previous != actual {
                return Err(generic_instantiation_error(
                    format!(
                        "generic type inference for '{}' is inconsistent: '{}' versus '{}'",
                        name,
                        render_type(previous),
                        render_type(actual)
                    ),
                    span,
                ));
            }
        } else {
            inferred.insert(name.clone(), actual.clone());
        }
        return Ok(());
    }
    match (formal, actual) {
        (Type::Array(formal, formal_len), Type::Array(actual, actual_len)) if formal_len == actual_len => {
            unify_generic_type(formal, actual, params, inferred, span)
        }
        (Type::Tuple(formal), Type::Tuple(actual)) if formal.len() == actual.len() => {
            for (formal, actual) in formal.iter().zip(actual) {
                unify_generic_type(formal, actual, params, inferred, span)?;
            }
            Ok(())
        }
        (Type::Ref(formal), Type::Ref(actual)) | (Type::MutRef(formal), Type::MutRef(actual)) => {
            unify_generic_type(formal, actual, params, inferred, span)
        }
        (Type::Named(formal), Type::Named(actual)) => {
            let formal_applied = applied_type(formal);
            let actual_applied =
                decode_monomorph_name(actual).or_else(|| applied_type(actual).map(|(base, args)| (base.to_string(), args)));
            match (formal_applied, actual_applied) {
                (Some((formal_base, formal_args)), Some((actual_base, actual_args)))
                    if formal_base == actual_base && formal_args.len() == actual_args.len() =>
                {
                    for (formal, actual) in formal_args.iter().zip(&actual_args) {
                        unify_generic_type(
                            &parse_type_repr(formal)
                                .ok_or_else(|| generic_instantiation_error("invalid formal generic type", span))?,
                            &parse_type_repr(actual)
                                .ok_or_else(|| generic_instantiation_error("invalid actual generic type", span))?,
                            params,
                            inferred,
                            span,
                        )?;
                    }
                    Ok(())
                }
                _ if formal == actual => Ok(()),
                _ => Ok(()),
            }
        }
        _ => Ok(()),
    }
}

fn substitute_type_pure(ty: &Type, substitution: &HashMap<String, Type>) -> Option<Type> {
    match ty {
        Type::Named(name) if substitution.contains_key(name) => substitution.get(name).cloned(),
        Type::Array(inner, len) => Some(Type::Array(Box::new(substitute_type_pure(inner, substitution)?), *len)),
        Type::Tuple(items) => {
            Some(Type::Tuple(items.iter().map(|item| substitute_type_pure(item, substitution)).collect::<Option<Vec<_>>>()?))
        }
        Type::Ref(inner) => Some(Type::Ref(Box::new(substitute_type_pure(inner, substitution)?))),
        Type::MutRef(inner) => Some(Type::MutRef(Box::new(substitute_type_pure(inner, substitution)?))),
        other => Some(other.clone()),
    }
}

fn item_decl_name(item: &Item) -> Option<&str> {
    match item {
        Item::Resource(def) => Some(&def.name),
        Item::Shared(def) => Some(&def.name),
        Item::Receipt(def) => Some(&def.name),
        Item::Struct(def) => Some(&def.name),
        Item::Invariant(def) => Some(&def.name),
        Item::Const(def) => Some(&def.name),
        Item::Enum(def) => Some(&def.name),
        Item::Action(def) => Some(&def.name),
        Item::Function(def) => Some(&def.name),
        Item::Lock(def) => Some(&def.name),
        Item::Flow(_) | Item::Use(_) => None,
    }
}

fn item_span(item: &Item) -> Span {
    match item {
        Item::Resource(def) => def.span,
        Item::Shared(def) => def.span,
        Item::Receipt(def) => def.span,
        Item::Struct(def) => def.span,
        Item::Flow(def) => def.span,
        Item::Invariant(def) => def.span,
        Item::Const(def) => def.span,
        Item::Enum(def) => def.span,
        Item::Action(def) => def.span,
        Item::Function(def) => def.span,
        Item::Lock(def) => def.span,
        Item::Use(def) => def.span,
    }
}

fn kind_key(kind: TemplateKind) -> &'static str {
    match kind {
        TemplateKind::Struct => "struct",
        TemplateKind::Enum => "enum",
        TemplateKind::Function => "fn",
    }
}

fn generic_declaration_error(message: impl Into<String>, span: Span) -> CompileError {
    CompileError::new(message, span).with_code("E2110")
}

fn generic_instantiation_error(message: impl Into<String>, span: Span) -> CompileError {
    CompileError::new(message, span).with_code("E2111")
}

fn generic_budget_error(message: impl Into<String>, span: Span) -> CompileError {
    CompileError::new(message, span).with_code("E2112")
}

fn monomorph_name(base: &str, args: &[Type], span: Span) -> Result<String> {
    let canonical = args.iter().map(render_type_identity).collect::<Vec<_>>().join(",");
    let encoded = canonical.as_bytes().iter().map(|byte| format!("{:02x}", byte)).collect::<String>();
    let name = format!("{}{}{}", base, MONO_MARKER, encoded);
    if name.len() > MAX_MONOMORPH_NAME_BYTES {
        return Err(generic_budget_error(
            format!("monomorphized identity for '{}' exceeds {} bytes", base, MAX_MONOMORPH_NAME_BYTES),
            span,
        ));
    }
    Ok(name)
}

pub(crate) fn render_type(ty: &Type) -> String {
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
        Type::Array(inner, len) => format!("[{}; {}]", render_type(inner), len),
        Type::Tuple(items) => format!("({})", items.iter().map(render_type).collect::<Vec<_>>().join(", ")),
        Type::Named(name) => name.clone(),
        Type::Ref(inner) => format!("&{}", render_type(inner)),
        Type::MutRef(inner) => format!("&mut {}", render_type(inner)),
    }
}

pub(crate) fn render_source_type(ty: &Type) -> String {
    match ty {
        Type::Array(inner, len) => format!("[{}; {}]", render_source_type(inner), len),
        Type::Tuple(items) => format!("({})", items.iter().map(render_source_type).collect::<Vec<_>>().join(", ")),
        Type::Named(name) => source_type_name(name),
        Type::Ref(inner) => format!("&{}", render_source_type(inner)),
        Type::MutRef(inner) => format!("&mut {}", render_source_type(inner)),
        primitive => render_type(primitive),
    }
}

fn render_type_identity(ty: &Type) -> String {
    match ty {
        Type::Array(inner, len) => format!("[{};{}]", render_type_identity(inner), len),
        Type::Tuple(items) => format!("({})", items.iter().map(render_type_identity).collect::<Vec<_>>().join(",")),
        Type::Ref(inner) => format!("&{}", render_type_identity(inner)),
        Type::MutRef(inner) => format!("&mut {}", render_type_identity(inner)),
        Type::Named(name) => source_type_name(name),
        primitive => render_type(primitive),
    }
}

fn source_type_name(name: &str) -> String {
    if let Some((base, args)) = decode_monomorph_name(name) {
        let args = args
            .iter()
            .map(|arg| parse_type_repr(arg).map_or_else(|| arg.clone(), |ty| render_type_identity(&ty)))
            .collect::<Vec<_>>()
            .join(",");
        return format!("{}<{}>", base, args);
    }
    name.chars().filter(|ch| !ch.is_whitespace()).collect()
}

fn primitive_type_name(name: &str) -> Option<Type> {
    Some(match name {
        "u8" => Type::U8,
        "u16" => Type::U16,
        "u32" => Type::U32,
        "i32" => Type::I32,
        "u64" => Type::U64,
        "u128" => Type::U128,
        "bool" => Type::Bool,
        "Address" => Type::Address,
        "Hash" => Type::Hash,
        "()" => Type::Unit,
        _ => return None,
    })
}

fn applied_type(name: &str) -> Option<(&str, Vec<String>)> {
    let start = name.find('<')?;
    if !name.ends_with('>') {
        return None;
    }
    let base = name[..start].trim();
    let inner = &name[start + 1..name.len() - 1];
    Some((base, split_top_level(inner, ',')?))
}

fn split_top_level(input: &str, separator: char) -> Option<Vec<String>> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut angle = 0usize;
    let mut square = 0usize;
    let mut paren = 0usize;
    for (index, ch) in input.char_indices() {
        match ch {
            '<' => angle = angle.checked_add(1)?,
            '>' => angle = angle.checked_sub(1)?,
            '[' => square = square.checked_add(1)?,
            ']' => square = square.checked_sub(1)?,
            '(' => paren = paren.checked_add(1)?,
            ')' => paren = paren.checked_sub(1)?,
            _ => {}
        }
        if ch == separator && angle == 0 && square == 0 && paren == 0 {
            let part = input[start..index].trim();
            if part.is_empty() {
                return None;
            }
            parts.push(part.to_string());
            start = index + ch.len_utf8();
        }
    }
    if angle != 0 || square != 0 || paren != 0 {
        return None;
    }
    let tail = input[start..].trim();
    if tail.is_empty() {
        return None;
    }
    parts.push(tail.to_string());
    Some(parts)
}

fn parse_type_repr(input: &str) -> Option<Type> {
    let input = input.trim();
    if let Some(primitive) = primitive_type_name(input) {
        return Some(primitive);
    }
    if let Some(inner) = input.strip_prefix("&mut ") {
        return Some(Type::MutRef(Box::new(parse_type_repr(inner)?)));
    }
    if let Some(inner) = input.strip_prefix('&') {
        return Some(Type::Ref(Box::new(parse_type_repr(inner)?)));
    }
    if input.starts_with('[') && input.ends_with(']') {
        let body = &input[1..input.len() - 1];
        let parts = split_top_level(body, ';')?;
        if parts.len() != 2 {
            return None;
        }
        return Some(Type::Array(Box::new(parse_type_repr(&parts[0])?), parts[1].parse().ok()?));
    }
    if input.starts_with('(') && input.ends_with(')') {
        let body = &input[1..input.len() - 1];
        if body.trim().is_empty() {
            return Some(Type::Unit);
        }
        return Some(Type::Tuple(split_top_level(body, ',')?.iter().map(|part| parse_type_repr(part)).collect::<Option<Vec<_>>>()?));
    }
    Some(Type::Named(input.to_string()))
}

fn type_contains_param(ty: &Type, param: &str) -> bool {
    match ty {
        Type::Named(name) if name == param => true,
        Type::Named(name) => applied_type(name)
            .is_some_and(|(_, args)| args.iter().filter_map(|arg| parse_type_repr(arg)).any(|arg| type_contains_param(&arg, param))),
        Type::Array(inner, _) | Type::Ref(inner) | Type::MutRef(inner) => type_contains_param(inner, param),
        Type::Tuple(items) => items.iter().any(|item| type_contains_param(item, param)),
        _ => false,
    }
}

fn type_nesting(ty: &Type) -> usize {
    match ty {
        Type::Array(inner, _) | Type::Ref(inner) | Type::MutRef(inner) => 1 + type_nesting(inner),
        Type::Tuple(items) => 1 + items.iter().map(type_nesting).max().unwrap_or(0),
        Type::Named(name) => applied_type(name)
            .map(|(_, args)| 1 + args.iter().filter_map(|arg| parse_type_repr(arg)).map(|arg| type_nesting(&arg)).max().unwrap_or(0))
            .unwrap_or(1),
        _ => 1,
    }
}

fn builtin_option_template() -> EnumDef {
    let span = Span::default();
    EnumDef {
        name: "Option".to_string(),
        type_params: vec![TypeParam {
            name: "T".to_string(),
            constraints: vec![
                ValueAbility::Copy,
                ValueAbility::Drop,
                ValueAbility::Store,
                ValueAbility::Fixed,
                ValueAbility::Serializable,
                ValueAbility::NonLinear,
            ],
            phantom: false,
            span,
        }],
        abilities: vec![
            ValueAbility::Copy,
            ValueAbility::Drop,
            ValueAbility::Store,
            ValueAbility::Fixed,
            ValueAbility::Serializable,
            ValueAbility::NonLinear,
        ],
        variants: vec![
            EnumVariant { name: "None".to_string(), fields: Vec::new(), span },
            EnumVariant { name: "Some".to_string(), fields: vec![Type::Named("T".to_string())], span },
        ],
        span,
    }
}
