//! Entry points sharing the checked IR policy resolver across input transports.

use super::ArtifactDeclaration;
use crate::error::{CompileError, DiagnosticSeverity, Result};
use crate::{CompileEntryScope, CompileMetadata, CompileOptions, InMemorySource};
#[cfg(not(feature = "wasm"))]
use crate::{CompileResult, ExecutableSurfacePolicy};

/// Compile one explicitly declared persistent policy from in-memory source.
/// The declaration is not inferred from names, module order, or transaction shape.
/// ELF generation is a native feature; browser builds expose metadata only.
#[cfg(not(feature = "wasm"))]
pub fn compile_artifact(
    source: &str,
    options: CompileOptions,
    declaration: ArtifactDeclaration,
    policy: ExecutableSurfacePolicy,
) -> Result<CompileResult> {
    let ast = crate::generics::monomorphize(&crate::frontend::parse(source, options.edition)?)?;
    let scope = CompileEntryScope::Artifact(declaration);
    let mut result = crate::compile_ast_with_build(&ast, &options, None, None, None, Some(&scope), policy)?;
    crate::bind_compile_result_source_metadata(
        &mut result,
        vec![crate::source_unit_from_bytes("<memory>", "memory", source.as_bytes())],
    )?;
    result.validate()?;
    Ok(result)
}

/// Inspect exactly the same resolved policy without generating machine code.
/// Reserved executable operations remain visible to diagnostic consumers.
pub fn compile_artifact_metadata(source: &str, options: CompileOptions, declaration: ArtifactDeclaration) -> Result<CompileMetadata> {
    let ast = crate::generics::monomorphize(&crate::frontend::parse(source, options.edition)?)?;
    let scope = CompileEntryScope::Artifact(declaration);
    let mut metadata = metadata_from_ast(&ast, &options, None, None, None, Some(&scope))?;
    crate::bind_source_metadata(&mut metadata, vec![crate::source_unit_from_bytes("<memory>", "memory", source.as_bytes())]);
    crate::validate_compile_metadata(&metadata, crate::ArtifactFormat::from_target(crate::resolve_target(&options, None))?)?;
    Ok(metadata)
}

/// Virtual-source counterpart of `compile_artifact`, including imported modules.
#[cfg(not(feature = "wasm"))]
pub fn compile_sources_artifact(
    sources: &[InMemorySource],
    entry_path: &str,
    options: CompileOptions,
    declaration: ArtifactDeclaration,
    policy: ExecutableSurfacePolicy,
) -> Result<CompileResult> {
    let project = crate::load_virtual_project_for_entry_diagnostics(sources, entry_path, options.edition)
        .map_err(crate::diagnostics_to_compile_error)?;
    validate_project(&project, &options)?;
    let entry = project.entry();
    let scope = CompileEntryScope::Artifact(declaration);
    let mut result = crate::compile_ast_with_build(
        &entry.ast,
        &options,
        Some((&project.resolver, &entry.ast.name)),
        None,
        None,
        Some(&scope),
        policy,
    )?;
    crate::bind_compile_result_source_metadata(&mut result, source_units(sources, entry_path))?;
    result.validate()?;
    Ok(result)
}

/// Virtual-source metadata uses the same source resolver and selected policy.
pub fn compile_sources_artifact_metadata(
    sources: &[InMemorySource],
    entry_path: &str,
    options: CompileOptions,
    declaration: ArtifactDeclaration,
) -> Result<CompileMetadata> {
    let project = crate::load_virtual_project_for_entry_diagnostics(sources, entry_path, options.edition)
        .map_err(crate::diagnostics_to_compile_error)?;
    validate_project(&project, &options)?;
    let entry = project.entry();
    let scope = CompileEntryScope::Artifact(declaration);
    let mut metadata = metadata_from_ast(&entry.ast, &options, Some((&project.resolver, &entry.ast.name)), None, None, Some(&scope))?;
    crate::bind_source_metadata(&mut metadata, source_units(sources, entry_path));
    crate::validate_compile_metadata(&metadata, crate::ArtifactFormat::from_target(crate::resolve_target(&options, None))?)?;
    Ok(metadata)
}

/// Resolve an explicit package artifact without generating machine code or
/// reading/writing the default artifact cache. Package edition, build profile,
/// source closure and deployment declarations match executable compilation.
pub fn compile_path_artifact_metadata<P: AsRef<camino::Utf8Path>>(
    path: P,
    mut options: CompileOptions,
    name: &str,
) -> Result<CompileMetadata> {
    let path = crate::canonical_utf8_path(&crate::resolve_input_path(path)?)?;
    let declaration = crate::resolve_named_artifact(&path, name)?;
    let package_root = crate::find_package_root(&path)?
        .ok_or_else(|| CompileError::without_span("--artifact requires a package Cell.toml declaration"))?;
    let manifest = crate::load_manifest(&package_root)?;
    options.edition = manifest.package.edition;
    let source_units = crate::collect_source_units_for_compile_file(&path)?;
    let project = crate::load_project_for_entry(&path, None)?;
    validate_project(&project, &options)?;
    let entry = project.entry();
    let scope = CompileEntryScope::Artifact(declaration);
    let mut metadata = metadata_from_ast(
        &entry.ast,
        &options,
        Some((&project.resolver, &entry.ast.name)),
        Some(&manifest.build),
        manifest.deploy.ckb.as_ref().map(|ckb| ckb.trusted_external_verifiers.as_slice()),
        Some(&scope),
    )?;
    crate::bind_source_metadata(&mut metadata, source_units);
    crate::apply_manifest_deploy_metadata(&mut metadata, &manifest)?;
    crate::validate_compile_metadata(
        &metadata,
        crate::ArtifactFormat::from_target(crate::resolve_target(&options, Some(&manifest.build)))?,
    )?;
    Ok(metadata)
}

fn validate_project(project: &crate::LoadedProject, options: &CompileOptions) -> Result<()> {
    let diagnostics = crate::project_frontend_diagnostics(project, options, true);
    if diagnostics.iter().any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error) {
        return Err(crate::diagnostics_to_compile_error(diagnostics));
    }
    Ok(())
}

fn source_units(sources: &[InMemorySource], entry_path: &str) -> Vec<crate::SourceUnitMetadata> {
    sources
        .iter()
        .map(|source| {
            crate::source_unit_from_bytes(
                source.path.clone(),
                source.role.clone().unwrap_or_else(|| if source.path == entry_path { "entry".into() } else { "memory".into() }),
                source.source.as_bytes(),
            )
        })
        .collect()
}

fn metadata_from_ast(
    ast: &crate::ast::Module,
    options: &CompileOptions,
    resolver: Option<(&crate::ModuleResolver, &str)>,
    build: Option<&crate::package::BuildConfig>,
    trusted_external_verifiers: Option<&[crate::package::CkbTrustedExternalVerifierConfig]>,
    scope: Option<&CompileEntryScope>,
) -> Result<CompileMetadata> {
    crate::validate_compile_options(options)?;
    let target_profile = crate::TargetProfile::from_options(options, build)?;
    target_profile.ensure_compile_supported()?;
    let artifact_format = crate::ArtifactFormat::from_target(crate::resolve_target(options, build))?;
    let (optimized_ast, ir) = crate::prepare_compile_ir(ast, options, resolver, scope)?;
    let lowering_ast = optimized_ast.as_ref().unwrap_or(ast);
    let mut metadata =
        crate::compile_metadata_from_ir(&ir, artifact_format, target_profile, options.edition, options.primitive_compat.as_deref());
    crate::bind_public_interface(&mut metadata, lowering_ast);
    crate::apply_trusted_external_verifiers(&mut metadata, &ir, trusted_external_verifiers.unwrap_or_default())?;
    crate::bind_typed_semantics(&mut metadata, &ir);
    // Executable-surface policy intentionally does not reject metadata-only
    // inspection. Target/profile shape checks still apply to the requested view.
    let violations = crate::target_profile_artifact_policy_violations(&metadata, target_profile);
    if !violations.is_empty() {
        return Err(CompileError::without_span(format!("target profile policy failed: {}", violations.join("; "))));
    }
    Ok(metadata)
}

#[cfg(all(test, not(feature = "wasm")))]
mod tests {
    use super::*;
    use crate::artifact::{ArtifactAction, ArtifactContext, ArtifactDispatch};

    const SOURCE: &str = r#"
module policy_transport
resource Token has store, consume { amount: u64 }
action common() { require true }
action mint(witness amount: u64, witness recipient: Address) {
    require amount > 0
    create Token { amount: amount } with_lock(recipient)
}

action burn(input token: Token) { consume token }
"#;

    fn declaration() -> ArtifactDeclaration {
        ArtifactDeclaration {
            name: "TokenPolicy".into(),
            context: ArtifactContext::TypeGroup { resource: "Token".into() },
            dispatch: ArtifactDispatch::PolicyWitnessV1,
            actions: vec![ArtifactAction { tag: 41, action: "burn".into() }, ArtifactAction { tag: 3, action: "mint".into() }],
            common_checks: vec!["common".into()],
        }
    }

    fn options() -> CompileOptions {
        CompileOptions { edition: crate::NEXT_EDITION, target: Some("riscv64-elf".into()), ..Default::default() }
    }

    fn sources(source: &str) -> Vec<InMemorySource> {
        vec![InMemorySource { path: "src/main.cell".into(), source: source.into(), role: None }]
    }

    fn assert_same_policy(left: &CompileMetadata, right: &CompileMetadata) {
        assert_eq!(left.typed_semantics, right.typed_semantics);
        assert_eq!(left.typed_semantics_hash, right.typed_semantics_hash);
        assert_eq!(left.runtime.policy_artifact, right.runtime.policy_artifact);
        assert_eq!(left.compatibility_profile, right.compatibility_profile);
        assert_eq!(serde_json::to_value(&left.actions).unwrap(), serde_json::to_value(&right.actions).unwrap());
    }

    #[test]
    fn policy_transport_full_and_metadata_share_one_resolved_contract() {
        for opt_level in [0, 1, 2, 3] {
            let options = CompileOptions { opt_level, ..options() };
            let full = compile_artifact(SOURCE, options.clone(), declaration(), ExecutableSurfacePolicy::DenyFailClosed).unwrap();
            let metadata = compile_artifact_metadata(SOURCE, options.clone(), declaration()).unwrap();
            let virtual_full = compile_sources_artifact(
                &sources(SOURCE),
                "src/main.cell",
                options.clone(),
                declaration(),
                ExecutableSurfacePolicy::DenyFailClosed,
            )
            .unwrap();
            let virtual_metadata =
                compile_sources_artifact_metadata(&sources(SOURCE), "src/main.cell", options, declaration()).unwrap();
            assert_same_policy(&full.metadata, &metadata);
            assert_same_policy(&full.metadata, &virtual_full.metadata);
            assert_same_policy(&full.metadata, &virtual_metadata);
            assert_eq!(crate::strip_vm_abi_trailer(&full.artifact_bytes), crate::strip_vm_abi_trailer(&virtual_full.artifact_bytes));
        }
    }

    #[test]
    fn policy_transport_metadata_does_not_skip_binding_or_declaration_rejection() {
        for declaration in [
            ArtifactDeclaration { actions: vec![ArtifactAction { tag: 3, action: "absent".into() }], ..declaration() },
            ArtifactDeclaration { context: ArtifactContext::TypeGroup { resource: "Unknown".into() }, ..declaration() },
            ArtifactDeclaration { actions: vec![ArtifactAction { tag: 3, action: "mint".into() }; 2], ..declaration() },
        ] {
            let full = compile_artifact(SOURCE, options(), declaration.clone(), ExecutableSurfacePolicy::DenyFailClosed).unwrap_err();
            let metadata = compile_artifact_metadata(SOURCE, options(), declaration.clone()).unwrap_err();
            let virtual_full = compile_sources_artifact(
                &sources(SOURCE),
                "src/main.cell",
                options(),
                declaration.clone(),
                ExecutableSurfacePolicy::DenyFailClosed,
            )
            .unwrap_err();
            let virtual_metadata =
                compile_sources_artifact_metadata(&sources(SOURCE), "src/main.cell", options(), declaration).unwrap_err();
            assert_eq!(full.message, metadata.message);
            assert_eq!(full.message, virtual_full.message);
            assert_eq!(full.message, virtual_metadata.message);
        }
    }

    #[test]
    fn policy_transport_preserves_supported_positional_payload_families() {
        let source = r#"
module policy_payload_families
struct Point { x: u64, y: u64 }
enum Choice { None, Some((u64, u64)) }
resource Token has store, consume { amount: u64 }
action mint(
    witness flag: bool, witness small: u8, witness medium: u16,
    witness word: u32, witness signed: i32, witness amount: u64,
    witness wide: u128, witness recipient: Address, witness hash: Hash,
    witness bytes: [u8; 4], witness large_bytes: [u8; 12],
    witness tuple: (u64, u64), witness array: [[u16; 3]; 2],
    witness point: Point, witness choice: Choice, witness unit: ()
) {
    require amount > 0
    create Token { amount: amount } with_lock(recipient)
}
action burn(input token: Token) { consume token }
"#;
        let declaration = ArtifactDeclaration { common_checks: Vec::new(), ..declaration() };
        let full = compile_artifact(source, options(), declaration.clone(), ExecutableSurfacePolicy::DenyFailClosed).unwrap();
        let metadata = compile_artifact_metadata(source, options(), declaration).unwrap();
        assert_same_policy(&full.metadata, &metadata);
        let action = metadata.actions.iter().find(|action| action.name == "mint").unwrap();
        assert_eq!(action.params.len(), 16);
        assert!(action.params.iter().all(|param| !param.cell_bound_abi));
        assert_eq!(action.params.iter().find(|param| param.name == "wide").unwrap().fixed_byte_len, Some(16));
        assert_eq!(action.params.iter().find(|param| param.name == "tuple").unwrap().fixed_byte_len, Some(16));
        assert_eq!(action.params.iter().find(|param| param.name == "array").unwrap().fixed_byte_len, Some(12));
        assert!(action.params.iter().find(|param| param.name == "point").unwrap().schema_pointer_abi);
        assert!(action.params.iter().find(|param| param.name == "choice").unwrap().fixed_byte_pointer_abi);
    }
}

#[cfg(all(test, feature = "wasm"))]
mod wasm_tests {
    use super::*;
    use crate::artifact::{ArtifactAction, ArtifactContext, ArtifactDispatch};

    #[test]
    fn policy_transport_wasm_metadata_keeps_checked_policy_without_machine_claims() {
        let source = "module browser_policy\nresource Token has store, consume { amount: u64 }\naction burn(input token: Token) { consume token }";
        let options = CompileOptions { edition: crate::NEXT_EDITION, ..Default::default() };
        let declaration = ArtifactDeclaration {
            name: "TokenPolicy".into(),
            context: ArtifactContext::TypeGroup { resource: "Token".into() },
            dispatch: ArtifactDispatch::PolicyWitnessV1,
            actions: vec![ArtifactAction { tag: 40, action: "burn".into() }],
            common_checks: Vec::new(),
        };
        let metadata = compile_artifact_metadata(source, options.clone(), declaration.clone()).unwrap();
        let virtual_metadata = compile_sources_artifact_metadata(
            &[InMemorySource { path: "main.cell".into(), source: source.into(), role: None }],
            "main.cell",
            options.clone(),
            declaration.clone(),
        )
        .unwrap();
        assert_eq!(metadata.runtime.policy_artifact, virtual_metadata.runtime.policy_artifact);
        let encoded = serde_json::to_value(&metadata).unwrap();
        assert!(encoded.get("typed_semantics").is_none());
        assert!(encoded.get("artifact_hash").is_none());
        assert_eq!(encoded["runtime"]["policy_artifact"]["declaration"]["actions"][0]["tag"], 40);
        let mut wrong = declaration;
        wrong.context = ArtifactContext::TypeGroup { resource: "Foreign".into() };
        assert!(compile_artifact_metadata(source, options, wrong).is_err());
    }
}
