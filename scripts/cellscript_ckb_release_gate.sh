#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-quick}"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/cellscript-ckb-release-gate-target}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
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

run() {
    printf '\n==> %s\n' "$*"
    "$@"
}

check_trailing_whitespace() {
    local files=(
        ".github/workflows/ci.yml"
        "Cargo.toml"
        "README.md"
        "README_CH.md"
        "CHANGELOG.md"
        "docs/CELLSCRIPT_0_12_RELEASE_EVIDENCE.md"
        "docs/CELLSCRIPT_CKB_PROFILE_AUTHORING.md"
        "docs/CELLSCRIPT_CKB_DEPLOYMENT_MANIFEST.md"
        "docs/CELLSCRIPT_CAPACITY_AND_BUILDER_CONTRACT.md"
        "docs/CELLSCRIPT_ENTRY_WITNESS_ABI.md"
        "docs/CELLSCRIPT_COLLECTIONS_SUPPORT_MATRIX.md"
        "docs/wiki/Home.md"
        "docs/wiki/Tutorial-06-Metadata-Verification-and-Production-Gates.md"
        "docs/wiki/Tutorial-08-Bundled-Example-Contracts.md"
        "editors/vscode-cellscript/extension.js"
        "editors/vscode-cellscript/package.json"
        "editors/vscode-cellscript/scripts/validate.mjs"
        "scripts/cellscript_ckb_release_gate.sh"
        "scripts/ckb_cellscript_acceptance.sh"
        "scripts/validate_cellscript_tooling_release.py"
        "scripts/validate_ckb_cellscript_production_evidence.py"
        "src/lib.rs"
        "src/lsp/mod.rs"
        "src/package/mod.rs"
        "tests/cli.rs"
        "tests/examples.rs"
    )

    if rg -n '[ \t]+$' "${files[@]}"; then
        printf '\nTrailing whitespace found in CellScript CKB release-gate files.\n' >&2
        exit 1
    fi
}

check_ckb_release_docs() {
    local release_doc="docs/CELLSCRIPT_0_12_RELEASE_EVIDENCE.md"
    local required=(
        "CKB Acceptance Evidence"
        "scripts/ckb_cellscript_acceptance.sh --production"
        "scripts/validate_ckb_cellscript_production_evidence.py"
        "strict original policy status for all bundled examples"
        "builder-backed action count"
        "occupied capacity"
        "final hardening gate"
    )
    local pattern
    for pattern in "${required[@]}"; do
        if ! rg --quiet --fixed-strings "$pattern" "$release_doc"; then
            printf '0.12 release evidence doc is missing required CKB boundary: %s\n' "$pattern" >&2
            exit 1
        fi
    done
}

check_ckb_acceptance_boundaries() {
    local required=(
        'scripts/ckb_cellscript_acceptance.sh::Usage: scripts/ckb_cellscript_acceptance.sh'
        'scripts/ckb_cellscript_acceptance.sh::strict-original-ckb'
        'scripts/ckb_cellscript_acceptance.sh::bundled_examples_exact_order'
        'scripts/ckb_cellscript_acceptance.sh::strict_original_ckb_compile_policy_fail_closed'
        'scripts/ckb_cellscript_acceptance.sh::strict_original_ckb_compile_unexpected_failures'
        'scripts/ckb_cellscript_acceptance.sh::builder_backed_action_count'
        'scripts/ckb_cellscript_acceptance.sh::final_production_hardening_gate'
        'scripts/validate_ckb_cellscript_production_evidence.py::valid CKB CellScript'
        'scripts/validate_cellscript_tooling_release.py::valid CellScript tooling release boundary'
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

run_common_gate() {
    require_cmd cargo
    require_cmd python3
    require_cmd rg
    require_cmd npm

    run cargo fmt --all --check
    run cargo check --locked --all-targets
    run cargo test --locked -- --test-threads=1
    run python3 scripts/validate_cellscript_tooling_release.py
    run bash -n scripts/ckb_cellscript_acceptance.sh
    run bash -n scripts/cellscript_ckb_release_gate.sh
    run npm --prefix editors/vscode-cellscript run validate
    run git diff --check
    check_trailing_whitespace
    check_ckb_release_docs
    check_ckb_acceptance_boundaries
}

run_quick_gate() {
    run_common_gate
    run ./scripts/ckb_cellscript_acceptance.sh --compile-only --production
    printf '\nCellScript backend shape report: %s\n' "$CELLSCRIPT_BACKEND_SHAPE_REPORT"
    printf 'CellScript Molecule schema manifest report: %s\n' "$CELLSCRIPT_MOLECULE_SCHEMA_MANIFEST_REPORT"
}

run_production_gate() {
    run_common_gate
    run ./scripts/ckb_cellscript_acceptance.sh --production
    printf '\nCellScript backend shape report: %s\n' "$CELLSCRIPT_BACKEND_SHAPE_REPORT"
    printf 'CellScript Molecule schema manifest report: %s\n' "$CELLSCRIPT_MOLECULE_SCHEMA_MANIFEST_REPORT"
}

case "$MODE" in
    quick)
        run_quick_gate
        ;;
    production|full)
        run_production_gate
        ;;
    *)
        printf 'usage: %s [quick|production|full]\n' "$0" >&2
        exit 2
        ;;
esac

printf '\nCellScript CKB %s release gate passed.\n' "$MODE"
