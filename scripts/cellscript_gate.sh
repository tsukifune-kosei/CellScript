#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-dev}"
if [[ $# -gt 0 ]]; then
    shift
fi

export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CELLSCRIPT_BACKEND_SHAPE_REPORT="${CELLSCRIPT_BACKEND_SHAPE_REPORT:-$ROOT_DIR/target/cellscript-backend-shape/backend-shape-report-$MODE.json}"
export CELLSCRIPT_MOLECULE_SCHEMA_MANIFEST_REPORT="${CELLSCRIPT_MOLECULE_SCHEMA_MANIFEST_REPORT:-$ROOT_DIR/target/cellscript-schema-manifest/schema-manifest-report-$MODE.json}"

cd "$ROOT_DIR"
mkdir -p "$(dirname "$CELLSCRIPT_BACKEND_SHAPE_REPORT")"
mkdir -p "$(dirname "$CELLSCRIPT_MOLECULE_SCHEMA_MANIFEST_REPORT")"

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'missing required command: %s\n' "$1" >&2
        exit 127
    fi
}

require_node_22() {
    require_cmd node
    local node_major
    node_major="$(node --version | sed -n 's/^v\([0-9][0-9]*\).*/\1/p')"
    if [[ "$node_major" != "22" ]]; then
        printf 'Node.js 22 is required by the CellScript website and Registry toolchain; found %s\n' "$(node --version)" >&2
        exit 1
    fi
}

run() {
    printf '\n==> %s\n' "$*"
    "$@"
}

run_in_dir() {
    local dir="$1"
    shift
    printf '\n==> (cd %s && %s)\n' "$dir" "$*"
    (cd "$dir" && "$@")
}

cargo_fmt_workspace() {
    run cargo fmt \
        --manifest-path "$ROOT_DIR/Cargo.toml" \
        --package cellscript \
        --package cellscript-artifact-checker \
        --package cellscript-ckb-adapter \
        --package cellscript-fiber-adapter \
        --package cellscript-tools \
        --package cellscript-wasm \
        --package cellscript-ckb-sdk-builder-example \
        "$@"
}

check_canonical_cellscript_format() {
    run cargo run --quiet --locked -p cellscript --bin cellc -- \
        fmt --check "$ROOT_DIR/examples/language/core/canonical_style.cell"
}

check_example_u64_boundaries() {
    local example_files=(
        "examples/atomic_swap.cell"
        "examples/atomic_swap/src/main.cell"
        "examples/multi_phase_dao.cell"
        "examples/multi_phase_dao/src/main.cell"
        "examples/nft.cell"
        "examples/nft/src/main.cell"
        "examples/timelock.cell"
        "examples/timelock/src/main.cell"
    )

    if rg -n '18446744073709551615' "${example_files[@]}" | rg -v 'const U64_MAX: u64 = 18446744073709551615'; then
        printf '\nRaw u64 maximum found outside a U64_MAX declaration.\n' >&2
        exit 1
    fi
    if rg -n '18446744073709551515|18446744073706923615' "${example_files[@]}"; then
        printf '\nRaw MAX-delta boundary found in a checked CellScript example.\n' >&2
        exit 1
    fi
}

check_trailing_whitespace() {
    local tracked_rust_files=()
    local tracked_rust_file
    while IFS= read -r tracked_rust_file; do
        if [[ -f "$tracked_rust_file" ]]; then
            tracked_rust_files+=("$tracked_rust_file")
        fi
    done < <(git ls-files '*.rs')

    local tracked_website_files=()
    local tracked_website_file
    while IFS= read -r tracked_website_file; do
        case "$tracked_website_file" in
            website/*.json|website/*.mjs|website/**/*.astro|website/**/*.css|website/**/*.js|website/**/*.json|website/**/*.mjs|website/**/*.ts)
                if [[ -f "$tracked_website_file" ]]; then
                    tracked_website_files+=("$tracked_website_file")
                fi
                ;;
        esac
    done < <(git ls-files website)

    local files=(
        ".github/workflows/ci.yml"
        ".github/workflows/release.yml"
        ".github/workflows/website-build.yml"
        "Cargo.toml"
        "CODING_STYLE.md"
        "README.md"
        "CHANGELOG.md"
        "docs/README.md"
        "docs/releases/CELLSCRIPT_0_13_RELEASE_SCOPE.md"
        "docs/releases/CELLSCRIPT_0_13_2_RELEASE_NOTES.md"
        "docs/releases/CELLSCRIPT_0_13_2_ACCEPTANCE_COMMUNITY_POST.md"
        "docs/releases/CELLSCRIPT_0_14_RELEASE_NOTES.md"
        "docs/CELLSCRIPT_CKB_DEPLOYMENT_MANIFEST.md"
        "docs/CELLSCRIPT_CAPACITY_AND_BUILDER_CONTRACT.md"
        "docs/CELLSCRIPT_ENTRY_WITNESS_ABI.md"
        "docs/CELLSCRIPT_COLLECTIONS_SUPPORT_MATRIX.md"
        "docs/CELLSCRIPT_GATE_POLICY.md"
        "docs/wiki/Home.md"
        "docs/wiki/Tutorial-05-CKB-Target-Profiles.md"
        "docs/wiki/Tutorial-06-Metadata-Verification-and-Production-Gates.md"
        "docs/wiki/Tutorial-08-Bundled-Example-Contracts.md"
        "editors/vscode-cellscript/extension.js"
        "editors/vscode-cellscript/package-lock.json"
        "editors/vscode-cellscript/package.json"
        "editors/vscode-cellscript/scripts/validate.mjs"
        "scripts/cellscript_gate.sh"
        "scripts/cellscript_ckb_release_gate.sh"
        "scripts/cellscript_0_14_scope_audit.sh"
        "scripts/cellscript_syntax_combo_audit.sh"
        "scripts/cellscript_strict_backend_audit.sh"
        "scripts/ckb_cellscript_acceptance.sh"
        "tests/syntax_combo/matrix.toml"
        "tests/syntax_combo/seeds/require-block-lifecycle.cell"
        "docs/releases/CELLSCRIPT_0_20_RELEASE_NOTES.md"
        "docs/releases/CELLSCRIPT_0_21_RELEASE_NOTES.md"
        "docs/releases/CELLSCRIPT_0_22_RELEASE_NOTES.md"
        "docs/releases/CELLSCRIPT_0_16_TO_0_20_RELEASE_NOTES.md"
        "examples/atomic_swap.cell"
        "examples/multi_phase_dao.cell"
    )
    if ((${#tracked_rust_files[@]} > 0)); then
        files+=("${tracked_rust_files[@]}")
    fi
    if ((${#tracked_website_files[@]} > 0)); then
        files+=("${tracked_website_files[@]}")
    fi
    if ((${#files[@]} > 0)) && rg -n '[ \t]+$' "${files[@]}"; then
        printf '\nTrailing whitespace found in tracked CellScript files.\n' >&2
        exit 1
    fi
}

check_novaseal_verifier_pinning() {
    run cargo run --quiet --locked -p cellscript-tools --bin cellscript-tools -- \
        --root "$ROOT_DIR" check-novaseal-verifier-pinning
}

check_release_docs() {
    local required=(
        'docs/releases/CELLSCRIPT_0_13_RELEASE_SCOPE.md::Stdlib lifecycle and Cell metadata patterns'
        'docs/releases/CELLSCRIPT_0_13_RELEASE_SCOPE.md::./scripts/cellscript_gate.sh release'
        'docs/releases/CELLSCRIPT_0_13_RELEASE_SCOPE.md::./scripts/cellscript_gate.sh ci'
        'docs/releases/CELLSCRIPT_0_13_2_RELEASE_NOTES.md::Syntax Governance And Standard Library'
        'docs/releases/CELLSCRIPT_0_13_2_RELEASE_NOTES.md::Release tag'
        'docs/README.md::CellScript Documentation Map'
    )
    local item file pattern
    for item in "${required[@]}"; do
        file="${item%%::*}"
        pattern="${item#*::}"
        if ! rg --quiet --fixed-strings "$pattern" "$file"; then
            printf 'release docs are missing required boundary in %s: %s\n' "$file" "$pattern" >&2
            exit 1
        fi
    done
}

check_ckb_release_docs() {
    local release_doc="docs/wiki/Tutorial-06-Metadata-Verification-and-Production-Gates.md"
    local required=(
        "CKB Release Evidence Gate"
        "Syntax-Combination Preflight"
        "Unified Gate Entry Points"
        "syntax-combination audit is a release acceptance preflight"
        "before builder-backed CKB acceptance"
        "./scripts/cellscript_gate.sh release"
        "primitive-strict original bundled-example coverage"
        "builder-backed action runs"
        "source-bound acceptance provenance"
        "exact-artifact build reports"
        "occupied-capacity evidence"
        "passed final production hardening gate"
    )
    local pattern
    for pattern in "${required[@]}"; do
        if ! rg --quiet --fixed-strings "$pattern" "$release_doc"; then
            printf 'CKB production-gate docs are missing required boundary: %s\n' "$pattern" >&2
            exit 1
        fi
    done
}

check_cellscript_doc_status_freshness() {
    run cargo run --quiet --locked -p cellscript-tools --bin cellscript-tools -- \
        --root "$ROOT_DIR" check-doc-status
}

check_business_corpus() {
    run cargo run --quiet --locked -p cellscript-tools --bin cellscript-tools -- \
        --root "$ROOT_DIR" check-business-corpus
}

check_executable_surface_freshness() {
    run cargo run --quiet --locked -p cellscript-tools --bin cellscript-tools -- \
        --root "$ROOT_DIR" check-executable-surface
}

check_markdown_local_links() {
    run cargo run --quiet --locked -p cellscript-tools --bin cellscript-tools -- \
        --root "$ROOT_DIR" check-markdown-links
}

check_source_policy() {
    run cargo run --quiet --locked -p cellscript-tools --bin cellscript-tools -- \
        --root "$ROOT_DIR" check-source-policy
}

check_ckb_acceptance_boundaries() {
    local required=(
        'scripts/ckb_cellscript_acceptance.sh::Usage: scripts/ckb_cellscript_acceptance.sh'
        'scripts/ckb_cellscript_acceptance.sh::ckb-acceptance'
        'crates/cellscript-tools/src/ckb_acceptance.rs::requires_all_bundled_examples_strict_original_ckb'
        'crates/cellscript-tools/src/ckb_acceptance.rs::bundled_examples_exact_order'
        'crates/cellscript-tools/src/ckb_acceptance.rs::language_examples_exact_order'
        'crates/cellscript-tools/src/ckb_acceptance.rs::strict_original_ckb_compile_policy_fail_closed'
        'crates/cellscript-tools/src/ckb_acceptance.rs::strict_original_ckb_compile_unexpected_failures'
        'crates/cellscript-tools/src/ckb_acceptance.rs::SOURCE_PROVENANCE_SCHEMA'
        'crates/cellscript-tools/src/ckb_acceptance.rs::BUILD_REPORT_SCHEMA'
        'crates/cellscript-tools/src/ckb_acceptance.rs::"source_provenance":source_provenance(root)?'
        'crates/cellscript-tools/src/ckb_acceptance_live.rs::ckb_acceptance_pin.json'
        'crates/cellscript-tools/src/ckb_acceptance_live.rs::cellscript-ckb-runtime-provenance-v0.22'
        'crates/cellscript-tools/src/ckb_acceptance_live.rs::fresh-dedicated-cargo-target'
        'crates/cellscript-tools/src/ckb_acceptance_live.rs::ckb-librocksdb-sys-8.5.4-explicit-cstdint-v1'
        'crates/cellscript-tools/src/ckb_acceptance_live.rs::binary_archived_with_report'
        'crates/cellscript-tools/src/ckb_acceptance.rs::cellscript-public-builder-contract-gate-v0.22'
        'crates/cellscript-tools/src/ckb_acceptance.rs::cellscript_build_reports'
        'crates/cellscript-tools/src/ckb_acceptance_live.rs::live_code_cell_data_hash_matches_artifact'
        'crates/cellscript-tools/src/ckb_acceptance_live.rs::public_builder_contract_action_count'
        'crates/cellscript-tools/src/ckb_acceptance_live.rs::final_production_hardening_gate'
        'crates/cellscript-tools/src/production_evidence.rs::validate_source_provenance'
        'crates/cellscript-tools/src/production_evidence.rs::validate_public_builder_contracts'
        'crates/cellscript-tools/src/production_evidence.rs::validate_ckb_runtime_provenance'
        'crates/cellscript-tools/src/production_evidence.rs::fresh-dedicated-cargo-target'
        'crates/cellscript-tools/src/production_evidence.rs::ckb-librocksdb-sys-8.5.4-explicit-cstdint-v1'
        'crates/cellscript-tools/src/production_evidence.rs::stateful branch scenarios must cover every action absent from end-to-end flows exactly once'
        'crates/cellscript-tools/src/production_evidence.rs::validate_build_reports'
        'crates/cellscript-tools/src/production_evidence.rs::tracked_source_sha256'
        'crates/cellscript-tools/src/production_evidence.rs::valid CKB CellScript'
        'crates/cellscript-tools/src/tooling_release.rs::valid CellScript tooling release boundary'
        'src/lib.rs::cellscript-template-layout-v0.21'
        'src/cli/commands.rs::cellscript-protocol-graph-v0.22'
        'src/cli/commands.rs::cellscript-action-scan-selectors-v0.21'
    )
    local item file pattern
    for item in "${required[@]}"; do
        file="${item%%::*}"
        pattern="${item#*::}"
        if ! rg --quiet --fixed-strings "$pattern" "$file"; then
            printf 'CKB acceptance boundary is missing required pattern in %s: %s\n' "$file" "$pattern" >&2
            exit 1
        fi
    done
}

check_novaseal_acceptance_boundaries() {
    local required=(
        'src/cli/novaseal_certification.rs::stateful_live_acceptance_blockers'
        'src/cli/novaseal_certification.rs::stateful_acceptance_status'
        'src/cli/novaseal_certification.rs::local_devnet_passed_external_endpoint_required'
        'src/cli/novaseal_certification.rs::acceptance_blocker_count'
        'src/cli/novaseal_certification.rs::local_blocker_count'
        'src/cli/novaseal_certification.rs::external_endpoint_coverage'
        'src/cli/novaseal_certification.rs::real BTC SPV and Fiber endpoint production acceptance'
        'src/cli/novaseal_certification.rs::current_source_valid'
        'src/cli/novaseal_certification.rs::source_tree_invalid_paths_empty'
        'crates/cellscript-tools/src/bip340_tcb.rs::invalid_paths'
        'crates/cellscript-tools/src/ckb_devnet.rs::invalid_paths'
        'crates/cellscript-tools/src/external_handoff.rs::source tree path must not be a symlink'
        'crates/cellscript-tools/src/verifier_pinning.rs::is a symlink inside the NovaSeal'
        'scripts/novaseal_devnet_stateful_acceptance.sh::novaseal-acceptance-summary'
        'scripts/novaseal_devnet_stateful_acceptance.sh::local_blockers acceptance_blockers blockers external_endpoint_status'
        'scripts/novaseal_devnet_stateful_acceptance.sh::$acceptance_blockers" == "1"'
        'scripts/novaseal_devnet_stateful_acceptance.sh::acceptance_blockers=%s'
        'scripts/novaseal_devnet_stateful_acceptance.sh::external_endpoint_status=%s'
        'scripts/novaseal_devnet_stateful_acceptance.sh::certifier_status=%s'
        'scripts/novaseal_devnet_stateful_acceptance.sh::certifier_status=not_run'
        'scripts/novaseal_devnet_stateful_acceptance.sh::local_devnet_passed_external_endpoint_required'
        'scripts/novaseal_devnet_stateful_acceptance.sh::cert_status=$?'
        'proposals/novaseal/DEVNET_FULL_ACCEPTANCE_RUNBOOK.md::external_endpoint_status=external_required'
        'proposals/novaseal/DEVNET_FULL_ACCEPTANCE_RUNBOOK.md::acceptance_blockers=0'
        'proposals/novaseal/DEVNET_FULL_ACCEPTANCE_RUNBOOK.md::Missing public BTC SPV evidence'
        'proposals/novaseal/v0-mvp-skeleton/docs/AUDIT_STATUS.md::external_endpoint_status=external_required'
        'proposals/novaseal/v0-mvp-skeleton/docs/AUDIT_STATUS.md::acceptance_blockers=0'
        'src/cli/novaseal_certification.rs::source_tree_expected_files_and_provenance_reject_symlink_escape'
        'src/cli/novaseal_certification.rs::source_tree_invalid_paths_empty'
    )
    local item file pattern
    for item in "${required[@]}"; do
        file="${item%%::*}"
        pattern="${item#*::}"
        if ! rg --quiet --fixed-strings "$pattern" "$file"; then
            printf 'NovaSeal acceptance boundary is missing required pattern in %s: %s\n' "$file" "$pattern" >&2
            exit 1
        fi
    done
}

check_package_contents() {
    local package_files
    package_files="$(mktemp)"
    printf '\n==> cargo package --list --locked --allow-dirty --offline\n'
    cargo package --list --locked --allow-dirty --offline | tee "$package_files"
    if ! cargo run --quiet --locked -p cellscript-tools --bin cellscript-tools -- \
        --root "$ROOT_DIR" check-package-contents "$package_files"; then
        printf 'crates.io package includes repository-only files or unpublished helper binaries\n' >&2
        exit 1
    fi
    rm -f "$package_files"
}

check_script_syntax() {
    local shell_scripts=()
    local shell_script
    while IFS= read -r shell_script; do
        shell_scripts+=("$shell_script")
    done < <(git ls-files '*.sh')
    for shell_script in "${shell_scripts[@]}"; do
        if [[ -f "$shell_script" ]]; then
            run bash -n "$shell_script"
        fi
    done

}

check_release_source_identity() {
    require_cmd git

    local dirty version expected_tag exact_tags
    dirty="$(git status --porcelain --untracked-files=all)"
    if [[ -n "$dirty" ]]; then
        printf 'release gates require a clean source tree; commit or remove every tracked and untracked change first:\n%s\n' "$dirty" >&2
        exit 1
    fi

    version="$(cargo run --quiet --locked -p cellscript-tools --bin cellscript-tools -- \
        --root "$ROOT_DIR" workspace-version)"
    if [[ -n "${CELLSCRIPT_RELEASE_VERSION:-}" && "$CELLSCRIPT_RELEASE_VERSION" != "$version" ]]; then
        printf 'release version mismatch: requested %s, Cargo workspace declares %s\n' "$CELLSCRIPT_RELEASE_VERSION" "$version" >&2
        exit 1
    fi

    if [[ "${CELLSCRIPT_RELEASE_REQUIRE_TAG:-0}" == "1" ]]; then
        expected_tag="v$version"
        exact_tags="$(git tag --points-at HEAD)"
        if ! grep -Fxq "$expected_tag" <<<"$exact_tags"; then
            printf 'release tag mismatch: HEAD must carry exact tag %s (tags at HEAD: %s)\n' "$expected_tag" "${exact_tags:-none}" >&2
            exit 1
        fi
        if [[ -n "${GITHUB_REF_NAME:-}" && "$GITHUB_REF_NAME" != "$expected_tag" ]]; then
            printf 'release ref mismatch: GITHUB_REF_NAME=%s, expected %s\n' "$GITHUB_REF_NAME" "$expected_tag" >&2
            exit 1
        fi
    fi
}

run_website_build_check() {
    require_cmd npm

    if [[ ! -d website/node_modules ]]; then
        run npm --prefix website ci
    fi
    run npm --prefix website run prepare:registry

    local registry_status
    registry_status="$(git -C website status --porcelain -- src/data/registry-packages.json)"
    if [[ -n "$registry_status" ]]; then
        printf '\nwebsite registry data is stale. Run `npm --prefix website run prepare:registry` and commit the generated data.\n' >&2
        printf '%s\n' "$registry_status" >&2
        exit 1
    fi

    run npm --prefix website run build:ci
}

run_registry_api_check() {
    local registry_verifier_target_dir="${CARGO_TARGET_DIR:-$ROOT_DIR/services/registry-verifier/target}"
    if [[ "$registry_verifier_target_dir" != /* ]]; then
        registry_verifier_target_dir="$ROOT_DIR/$registry_verifier_target_dir"
    fi
    local registry_artifact_verifier_target_dir="$ROOT_DIR/services/registry-artifact-verifier/target"

    if [[ ! -d services/registry-api/node_modules ]]; then
        run npm --prefix services/registry-api ci
    fi
    run npm --prefix services/registry-api run check
    run cargo build --locked --manifest-path services/registry-verifier/Cargo.toml \
        --target-dir "$registry_verifier_target_dir"
    run cargo build --locked --manifest-path services/registry-artifact-verifier/Cargo.toml \
        --target-dir "$registry_artifact_verifier_target_dir"
    run env CELLSCRIPT_REGISTRY_VERIFIER_TEST_BINARY="$registry_verifier_target_dir/debug/cellscript-registry-verify" \
        CELLSCRIPT_REGISTRY_ARTIFACT_VERIFIER_TEST_BINARY="$registry_artifact_verifier_target_dir/debug/cellscript-registry-artifact-verify" \
        npm --prefix services/registry-api test
    run npm --prefix services/registry-api run build
    run npm --prefix services/registry-api run build:node
    run cargo fmt --manifest-path services/registry-verifier/Cargo.toml -- --check
    run cargo fmt --manifest-path services/registry-artifact-verifier/Cargo.toml -- --check
    run cargo test --locked --manifest-path services/registry-verifier/Cargo.toml
    run cargo test --locked --manifest-path services/registry-artifact-verifier/Cargo.toml
    run cargo clippy --locked --manifest-path services/registry-verifier/Cargo.toml --all-targets -- -D warnings
    run cargo clippy --locked --manifest-path services/registry-artifact-verifier/Cargo.toml --all-targets -- -D warnings
}

check_registry_artifact_verifier_dependency_boundary() {
    if cargo tree --locked --manifest-path services/registry-artifact-verifier/Cargo.toml --edges normal --prefix none \
        | rg --quiet '^cellscript v'; then
        printf 'Registry artifact verifier production dependency graph must not contain the CellScript compiler\n' >&2
        return 1
    fi
}

check_artifact_checker_dependency_boundary() {
    if cargo tree --locked --manifest-path Cargo.toml -p cellscript-artifact-checker --edges normal --prefix none \
        | rg --quiet '^cellscript v'; then
        printf 'Artifact checker production dependency graph must not contain the CellScript compiler\n' >&2
        return 1
    fi
}

run_executable_package_scenarios() {
    local backend="$1"
    run cargo run --quiet --locked -p cellscript --bin cellc -- test scenarios --backend "$backend"
}

check_workspace_graph_example() {
    run_in_dir "$ROOT_DIR/examples/workspace_graph" \
        cargo run --quiet --locked --manifest-path "$ROOT_DIR/Cargo.toml" \
        -p cellscript --bin cellc -- check --workspace --frozen --offline --json
}

check_package_inspection_schemas() {
    run cargo run --quiet --locked -p cellscript --bin cellc -- \
        resolve-graph examples/package_graph --environment mainnet --offline --schema-version 1 --json
    run cargo run --quiet --locked -p cellscript --bin cellc -- \
        build-plan examples/workspace_graph --package app --offline --schema-version 1 --json
    local update_plan="$ROOT_DIR/target/cellscript-upgrade-plan-gate.json"
    local lock_snapshot="$ROOT_DIR/target/cellscript-upgrade-plan-gate.Cell.lock"
    run cp examples/package_graph/Cell.lock "$lock_snapshot"
    run cargo run --quiet --locked -p cellscript --bin cellc -- \
        update-plan examples/package_graph --offline --schema-version 1 --output "$update_plan"
    run cmp examples/package_graph/Cell.lock "$lock_snapshot"
    if ! rg --quiet '"schema": "cellscript-upgrade-plan-v1"' "$update_plan"; then
        printf 'Transactional update plan gate did not emit schema v1\n' >&2
        return 1
    fi
    if ! rg --quiet '"apply_status": "ready"' "$update_plan"; then
        printf 'Transactional update plan gate did not produce a ready no-change plan\n' >&2
        return 1
    fi
    if ! rg --quiet '"old_build_unit_id": "build-unit:' "$update_plan"; then
        printf 'Transactional update plan gate did not retain canonical reverse-dependent build units\n' >&2
        return 1
    fi
}

run_registry_type_script_check() {
    run cargo fmt --manifest-path contracts/registry-type-script/Cargo.toml -- --check
    run contracts/registry-type-script/build_reproducible_release.sh
    run cargo test --locked --manifest-path contracts/registry-type-script/Cargo.toml
    local registry_type_script_hash
    registry_type_script_hash="$(sed -n 's/.*"ckb_data_hash": "\(0x[0-9a-f]*\)".*/\1/p' \
        contracts/registry-type-script/release-manifest.json)"
    if [[ ! "$registry_type_script_hash" =~ ^0x[0-9a-f]{64}$ ]]; then
        printf 'Registry Type Script release manifest has no canonical CKB data hash\n' >&2
        return 1
    fi
    if ! rg --fixed-strings --quiet "$registry_type_script_hash" services/registry-api/src/index.ts; then
        printf 'Registry API canonical Type Script identity is stale: expected %s\n' "$registry_type_script_hash" >&2
        return 1
    fi
}

check_wasm_release_bundle() {
    require_cmd docker
    run website/scripts/build-wasm.sh
    if ! git -C website diff --quiet -- public/wasm; then
        printf 'website WASM bundle is stale; rebuild and commit website/public/wasm before release\n' >&2
        git -C website status --short -- public/wasm >&2
        exit 1
    fi
}

release_ckb_repo_from_args() {
    local ckb_repo="$ROOT_DIR/../ckb"
    while (($# > 0)); do
        case "$1" in
            --ckb-repo)
                if (($# < 2)); then
                    printf 'missing value for --ckb-repo\n' >&2
                    return 2
                fi
                ckb_repo="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done
    printf '%s\n' "$ckb_repo"
}

check_ckb_tx_measure_tool() {
    local ckb_repo="$1"
    local default_ckb_repo="$ROOT_DIR/../ckb"
    if [[ ! -d "$ckb_repo" ]]; then
        printf 'CKB checkout does not exist: %s\n' "$ckb_repo" >&2
        return 1
    fi
    ckb_repo="$(cd "$ckb_repo" && pwd -P)"
    if [[ -d "$default_ckb_repo" ]]; then
        default_ckb_repo="$(cd "$default_ckb_repo" && pwd -P)"
        if [[ "$ckb_repo" == "$default_ckb_repo" ]]; then
            run cargo test --manifest-path tools/ckb-tx-measure/Cargo.toml --locked
            return
        fi
    fi

    local staging_dir
    staging_dir="$(mktemp -d "$ROOT_DIR/target/cellscript-ckb-tx-measure.XXXXXX")"
    mkdir -p "$staging_dir/cellscript/tools/ckb-tx-measure" "$staging_dir/cellscript/src/bin"
    cp tools/ckb-tx-measure/Cargo.toml tools/ckb-tx-measure/Cargo.lock \
        "$staging_dir/cellscript/tools/ckb-tx-measure/"
    cp src/bin/ckb_tx_measure.rs "$staging_dir/cellscript/src/bin/"
    ln -s "$ckb_repo" "$staging_dir/ckb"
    run cargo test --manifest-path "$staging_dir/cellscript/tools/ckb-tx-measure/Cargo.toml" --locked
}

check_novaseal_rust_tooling() {
    run cargo test --locked --manifest-path proposals/novaseal/v0-mvp-skeleton/verifier/novaseal_btc_verifier_core/Cargo.toml
    run cargo test --locked --manifest-path proposals/novaseal/v0-mvp-skeleton/verifier/novaseal_btc_verifier/Cargo.toml
    run cargo test --locked --manifest-path proposals/novaseal/v0-mvp-skeleton/verifier/novaseal_btc_verifier_riscv/Cargo.toml --lib
    run cargo check --locked --manifest-path proposals/novaseal/v0-mvp-skeleton/verifier/novaseal_btc_verifier_core/Cargo.toml --target riscv64imac-unknown-none-elf
    run cargo build --locked --manifest-path proposals/novaseal/v0-mvp-skeleton/verifier/novaseal_btc_verifier_riscv/Cargo.toml --target riscv64imac-unknown-none-elf --bin novaseal_btc_verifier_riscv
    run proposals/novaseal/v0-mvp-skeleton/verifier/novaseal_btc_verifier_riscv/build_reproducible_release.sh
    run cargo check --locked --manifest-path proposals/novaseal/v0-mvp-skeleton/harness/ckb_vm/Cargo.toml --all-targets
    run cargo check --locked --manifest-path proposals/novaseal/agreement-profile-v0/harness/ckb_vm/Cargo.toml --all-targets
}

run_dev_gate() {
    if (($# != 0)); then
        printf 'usage: %s dev\n' "$0" >&2
        exit 2
    fi
    require_cmd cargo
    require_cmd rg

    cargo_fmt_workspace
    run cargo fmt --manifest-path services/registry-verifier/Cargo.toml
    run cargo fmt --manifest-path services/registry-artifact-verifier/Cargo.toml
    run cargo check --locked -p cellscript --all-targets
    run cargo check --locked -p cellscript-artifact-checker --all-targets
    run cargo test --locked -p cellscript-artifact-checker
    run cargo test --locked -p cellscript --test artifact_checker --test myelin_handoff
    run cargo test --locked -p cellscript deployment_line_handle --lib
    run cargo test --locked -p cellscript --test exact_script_handles
    run cargo check --locked -p cellscript-fiber-adapter --all-targets
    run cargo check --locked -p cellscript-ckb-adapter --all-targets
    run cargo check --locked -p cellscript-wasm --all-targets --features wasm
    run cargo check --locked -p cellscript-ckb-sdk-builder-example --all-targets
    run cargo check --locked -p cellscript-tools --all-targets
    run cargo check --locked --manifest-path services/registry-verifier/Cargo.toml --all-targets
    run cargo check --locked --manifest-path services/registry-artifact-verifier/Cargo.toml --all-targets
    check_registry_artifact_verifier_dependency_boundary
    check_artifact_checker_dependency_boundary
    run_registry_type_script_check
    check_canonical_cellscript_format
    check_example_u64_boundaries
    run ./scripts/cellscript_strict_backend_audit.sh quick
    run ./scripts/cellscript_syntax_combo_audit.sh quick
    run_executable_package_scenarios simulator
    check_workspace_graph_example
    check_package_inspection_schemas
    run cargo run --quiet --locked -p cellscript-tools --bin cellscript-tools -- \
        --root "$ROOT_DIR" check-skill-pack
    check_cellscript_doc_status_freshness
    check_business_corpus
    check_executable_surface_freshness
    check_markdown_local_links
    check_source_policy
    run git diff --check
}

run_ci_gate() {
    if (($# != 0)); then
        printf 'usage: %s ci\n' "$0" >&2
        exit 2
    fi
    require_cmd cargo
    require_cmd rg
    require_cmd npm
    require_node_22

    printf '{"status":"not-generated","reason":"test suite did not reach backend shape report generation"}\n' >"$CELLSCRIPT_BACKEND_SHAPE_REPORT"
    cargo_fmt_workspace --check
    check_canonical_cellscript_format
    check_example_u64_boundaries
    run cargo test --locked -p cellscript -- --test-threads=1
    run cargo test --locked -p cellscript-artifact-checker -- --test-threads=1
    check_artifact_checker_dependency_boundary
    run cargo test --locked -p cellscript-fiber-adapter -- --test-threads=1
    run cargo test --locked -p cellscript-ckb-adapter -- --test-threads=1
    run cargo test --locked -p cellscript-wasm --features wasm -- --test-threads=1
    run cargo test --locked -p cellscript-ckb-sdk-builder-example -- --test-threads=1
    run cargo test --locked -p cellscript-tools -- --test-threads=1
    run_executable_package_scenarios all
    check_workspace_graph_example
    check_package_inspection_schemas
    run cargo clippy --locked -p cellscript --all-targets -- -D warnings
    run cargo clippy --locked -p cellscript-artifact-checker --all-targets -- -D warnings
    run cargo clippy --locked -p cellscript-fiber-adapter --all-targets -- -D warnings
    run cargo clippy --locked -p cellscript-ckb-adapter --all-targets -- -D warnings
    run cargo clippy --locked -p cellscript-wasm --all-targets --features wasm -- -D warnings
    run cargo clippy --locked -p cellscript-ckb-sdk-builder-example --all-targets -- -D warnings
    run cargo clippy --locked -p cellscript-tools --all-targets -- -D warnings
    run_registry_type_script_check
    run cargo clippy --locked --manifest-path contracts/registry-type-script/Cargo.toml --tests -- -D warnings
    run ./scripts/cellscript_strict_backend_audit.sh ci
    run cargo run --quiet --locked -p cellscript-tools --bin cellscript-tools -- \
        --root "$ROOT_DIR" check-skill-pack
    check_cellscript_doc_status_freshness
    check_business_corpus
    check_executable_surface_freshness
    check_markdown_local_links
    check_package_contents
    run cargo package --manifest-path crates/cellscript-artifact-checker/Cargo.toml --locked --offline --allow-dirty
    run cargo --config "patch.crates-io.cellscript-artifact-checker.path=\"$ROOT_DIR/crates/cellscript-artifact-checker\"" \
        package --locked --offline --allow-dirty
    run_registry_api_check
    check_registry_artifact_verifier_dependency_boundary
    run_website_build_check
    check_script_syntax
    run git diff --check
    check_source_policy
    check_trailing_whitespace
}

run_backend_gate() {
    if (($# != 0)); then
        printf 'usage: %s backend\n' "$0" >&2
        exit 2
    fi
    require_cmd cargo
    require_cmd rg

    check_source_policy
    check_business_corpus

    cargo_fmt_workspace --check
    run cargo check --locked -p cellscript --all-targets
    run cargo check --locked -p cellscript-artifact-checker --all-targets
    run cargo check --locked -p cellscript-fiber-adapter --all-targets
    run cargo test --locked -p cellscript
    run cargo test --locked -p cellscript-artifact-checker
    run cargo test --locked -p cellscript-fiber-adapter -- --test-threads=1
    run cargo clippy --locked -p cellscript --all-targets -- -D warnings
    run cargo clippy --locked -p cellscript-artifact-checker --all-targets -- -D warnings
    run cargo clippy --locked -p cellscript-fiber-adapter --all-targets -- -D warnings
    check_registry_artifact_verifier_dependency_boundary
    check_artifact_checker_dependency_boundary
    run_executable_package_scenarios all
    run ./scripts/cellscript_strict_backend_audit.sh full
    run git diff --check
}

run_release_auxiliary_checks() {
    local ckb_repo="$1"
    require_cmd npm

    run cargo run --quiet --locked -p cellscript-tools --bin cellscript-tools -- \
        --root "$ROOT_DIR" validate-tooling-release
    check_release_docs
    check_ckb_release_docs
    check_ckb_acceptance_boundaries
    check_novaseal_acceptance_boundaries
    check_ckb_tx_measure_tool "$ckb_repo"
    check_novaseal_rust_tooling
    check_novaseal_verifier_pinning
    check_wasm_release_bundle
    if [[ ! -d editors/vscode-cellscript/node_modules ]]; then
        run npm --prefix editors/vscode-cellscript ci
    fi
    run_in_dir editors/vscode-cellscript npm exec -- vsce package --no-dependencies --out /tmp/cellscript-vscode-dry-run.vsix
    run node editors/vscode-cellscript/scripts/validate.mjs
}

run_release_quick_gate() {
    local ckb_repo
    ckb_repo="$(release_ckb_repo_from_args "$@")"
    check_release_source_identity
    run_ci_gate
    run_release_auxiliary_checks "$ckb_repo"
    run ./scripts/ckb_cellscript_acceptance.sh --compile-only --production "$@"
    printf '\nCellScript backend shape report: %s\n' "$CELLSCRIPT_BACKEND_SHAPE_REPORT"
    printf 'CellScript Molecule schema manifest report: %s\n' "$CELLSCRIPT_MOLECULE_SCHEMA_MANIFEST_REPORT"
}

run_release_gate() {
    local ckb_repo
    ckb_repo="$(release_ckb_repo_from_args "$@")"
    check_release_source_identity
    run_ci_gate
    run_release_auxiliary_checks "$ckb_repo"
    run ./scripts/ckb_cellscript_acceptance.sh --production --stateful-scenarios "$@"
    printf '\nCellScript backend shape report: %s\n' "$CELLSCRIPT_BACKEND_SHAPE_REPORT"
    printf 'CellScript Molecule schema manifest report: %s\n' "$CELLSCRIPT_MOLECULE_SCHEMA_MANIFEST_REPORT"
}

case "$MODE" in
    dev)
        run_dev_gate "$@"
        ;;
    ci)
        run_ci_gate "$@"
        ;;
    backend)
        run_backend_gate "$@"
        ;;
    release)
        run_release_gate "$@"
        ;;
    release-quick)
        run_release_quick_gate "$@"
        ;;
    *)
        printf 'usage: %s [dev|ci|backend|release|release-quick]\n' "$0" >&2
        exit 2
        ;;
esac

printf '\nCellScript %s gate passed.\n' "$MODE"
