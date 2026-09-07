#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FIBER_REPO="${FIBER_REPO:-$REPO_ROOT/../fiber}"
FIBER_REVISION="${FIBER_REVISION:-f9232d52254a5aa52195ecae296c896de7078887}"
MODE="static"
ACCEPTANCE_REPORT=""
COMPATIBILITY_REPORT=""
REGISTRATION_REPORT=""
TOPOLOGY_REPORT=""
EVIDENCE_ROOT=""

usage() {
  cat <<'USAGE'
Usage: scripts/cellscript_fiber_acceptance.sh [--static] [--full <report options>] [options]

Runs the non-gating CellScript 0.22 Fiber acceptance boundary.

  --static                       Run compiler CKB-VM scenarios plus adapter tests.
  --full                         Also validate a concrete, complete lifecycle matrix.
  --acceptance-report <path>     Generated acceptance.json containing every required row.
  --compatibility-report <path>  Generated compatibility.json bound to the same environment.
  --registration-report <path>   LocalNodeAdvertised registration.json for the same binding.
  --topology-report <path>       TopologyCertified topology.json for the same binding.
  --evidence-root <path>         Root containing content-addressed evidence files.
  --fiber-repo <path>            Fiber checkout used by the topology (default: ../fiber).
  --fiber-revision <commit>      Exact accepted Fiber commit.
  -h, --help                     Show this help.

The full mode validates externally produced lifecycle evidence. It does not
start, configure, sign for, or stop user-owned Fiber/CKB nodes.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --static)
      MODE="static"
      shift
      ;;
    --full)
      MODE="full"
      shift
      ;;
    --acceptance-report)
      ACCEPTANCE_REPORT="${2:?missing value for --acceptance-report}"
      shift 2
      ;;
    --compatibility-report)
      COMPATIBILITY_REPORT="${2:?missing value for --compatibility-report}"
      shift 2
      ;;
    --registration-report)
      REGISTRATION_REPORT="${2:?missing value for --registration-report}"
      shift 2
      ;;
    --topology-report)
      TOPOLOGY_REPORT="${2:?missing value for --topology-report}"
      shift 2
      ;;
    --evidence-root)
      EVIDENCE_ROOT="${2:?missing value for --evidence-root}"
      shift 2
      ;;
    --fiber-repo)
      FIBER_REPO="${2:?missing value for --fiber-repo}"
      shift 2
      ;;
    --fiber-revision)
      FIBER_REVISION="${2:?missing value for --fiber-revision}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

cd "$REPO_ROOT"

cargo test --locked -p cellscript --test fiber_compatibility -- --test-threads=1
cargo test --locked -p cellscript-fiber-adapter -- --test-threads=1
cargo clippy --locked -p cellscript-fiber-adapter --all-targets -- -D warnings

if [[ "$MODE" == "static" ]]; then
  echo "CellScript Fiber static and CKB-VM acceptance passed; no Fiber topology claim was made."
  exit 0
fi

if [[ -z "$ACCEPTANCE_REPORT" || -z "$COMPATIBILITY_REPORT" || -z "$REGISTRATION_REPORT" || -z "$TOPOLOGY_REPORT" || -z "$EVIDENCE_ROOT" ]]; then
  echo "--full requires acceptance, compatibility, registration, topology, and evidence-root arguments" >&2
  exit 2
fi
if [[ ! -d "$FIBER_REPO/.git" && ! -f "$FIBER_REPO/.git" ]]; then
  echo "Fiber checkout not found at $FIBER_REPO" >&2
  exit 1
fi

actual_revision="$(git -C "$FIBER_REPO" rev-parse HEAD)"
if [[ "$actual_revision" != "$FIBER_REVISION" ]]; then
  echo "Fiber revision mismatch: expected $FIBER_REVISION, got $actual_revision" >&2
  exit 1
fi

cargo run --quiet --locked -p cellscript-tools --bin cellscript-tools -- \
  --root "$REPO_ROOT" fiber-report-binding \
  "$COMPATIBILITY_REPORT" "$ACCEPTANCE_REPORT" "$FIBER_REVISION"

cargo run --locked -p cellscript-fiber-adapter --bin cellscript-fiber -- accept "$ACCEPTANCE_REPORT" \
  --compatibility-report "$COMPATIBILITY_REPORT" \
  --registration-report "$REGISTRATION_REPORT" \
  --topology-report "$TOPOLOGY_REPORT" \
  --evidence-root "$EVIDENCE_ROOT"
echo "CellScript Fiber full evidence-bundle integrity passed for $FIBER_REVISION; operator identity and binary provenance remain external."
