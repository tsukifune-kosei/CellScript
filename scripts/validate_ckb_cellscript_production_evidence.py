#!/usr/bin/env python3
"""Validate CKB CellScript production acceptance evidence before release."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


EXPECTED_EXAMPLES = [
    "amm_pool.cell",
    "launch.cell",
    "multisig.cell",
    "nft.cell",
    "timelock.cell",
    "token.cell",
    "vesting.cell",
]
EXPECTED_NON_PRODUCTION_EXAMPLES = ["registry.cell"]
EXPECTED_ACTION_COUNT = 43
EXPECTED_LOCK_COUNT = 16
EXPECTED_STATUS = "passed"
EXPECTED_MODE = "production"
EXPECTED_LOCK_SPEND_MATRIX = {
    "multisig.cell": ["is_signer_lock", "can_execute", "can_cancel", "has_enough_signatures", "not_expired"],
    "nft.cell": ["nft_ownership", "listing_seller", "offer_buyer", "valid_royalty", "collection_creator"],
    "timelock.cell": ["can_unlock_lock", "is_owner", "asset_matches", "not_expired", "emergency_approved"],
    "vesting.cell": ["vesting_admin"],
}
EXPECTED_LOCK_NAMES = [
    f"{example}:{lock}"
    for example in EXPECTED_EXAMPLES
    for lock in EXPECTED_LOCK_SPEND_MATRIX.get(example, [])
]

ACTION_RUN_KEYS = [
    "token_action_runs",
    "nft_action_runs",
    "timelock_action_runs",
    "multisig_action_runs",
    "vesting_action_runs",
    "amm_action_runs",
    "launch_action_runs",
]

EXPECTED_ACTIONS_BY_RUN_KEY = {
    "token_action_runs": ["mint", "transfer_token", "burn", "merge"],
    "nft_action_runs": [
        "mint",
        "transfer",
        "create_listing",
        "cancel_listing",
        "buy_from_listing",
        "create_offer",
        "accept_offer",
        "burn",
        "batch_mint",
    ],
    "timelock_action_runs": [
        "create_absolute_lock",
        "create_relative_lock",
        "lock_asset",
        "request_release",
        "request_emergency_release",
        "approve_emergency_release",
        "extend_lock",
        "execute_release",
        "execute_emergency_release",
        "batch_create_locks",
    ],
    "multisig_action_runs": [
        "create_wallet",
        "propose_transfer",
        "add_signature",
        "execute_proposal",
        "cancel_proposal",
        "propose_add_signer",
        "propose_remove_signer",
        "propose_change_threshold",
    ],
    "vesting_action_runs": ["create_vesting_config", "grant_vesting", "claim_vested", "revoke_grant"],
    "amm_action_runs": ["seed_pool", "swap_a_for_b", "add_liquidity", "remove_liquidity", "isqrt", "min"],
    "launch_action_runs": ["launch_token", "simple_launch"],
}


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            value = json.load(fh)
    except FileNotFoundError as exc:
        raise SystemExit(f"missing CKB production evidence: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain a JSON object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"invalid CKB CellScript production evidence: {message}")


def require_field(mapping: dict[str, Any], key: str, expected: Any, context: str = "") -> None:
    actual = mapping.get(key)
    prefix = f"{context}." if context else ""
    require(actual == expected, f"{prefix}{key} must be {expected!r}, got {actual!r}")


def require_empty(mapping: dict[str, Any], key: str, context: str = "") -> None:
    value = mapping.get(key)
    prefix = f"{context}." if context else ""
    require(value == [], f"{prefix}{key} must be empty, got {value!r}")


def require_positive_int(value: Any, context: str) -> int:
    require(isinstance(value, int) and value > 0, f"{context} must be a positive integer, got {value!r}")
    return value


def require_bool(value: Any, context: str) -> bool:
    require(isinstance(value, bool), f"{context} must be a boolean, got {value!r}")
    return value


def all_action_runs(report: dict[str, Any]) -> list[dict[str, Any]]:
    onchain = report.get("onchain")
    require(isinstance(onchain, dict), "onchain section must be present")
    runs: list[dict[str, Any]] = []
    for key in ACTION_RUN_KEYS:
        value = onchain.get(key)
        require(isinstance(value, list), f"onchain.{key} must be a list")
        expected_actions = EXPECTED_ACTIONS_BY_RUN_KEY[key]
        actual_actions = [row.get("action") for row in value if isinstance(row, dict)]
        require(
            sorted(actual_actions) == sorted(expected_actions) and len(actual_actions) == len(expected_actions),
            f"onchain.{key} actions must be {expected_actions!r}, got {actual_actions!r}",
        )
        require(
            len(set(actual_actions)) == len(actual_actions),
            f"onchain.{key} must not contain duplicate actions, got {actual_actions!r}",
        )
        for row in value:
            require(isinstance(row, dict), f"onchain.{key} entries must be objects")
            runs.append(row)
    return runs


def validate_compile_gate(report: dict[str, Any], *, compile_only: bool = False) -> None:
    require_field(report, "acceptance_mode", EXPECTED_MODE)
    require_field(report, "status", EXPECTED_STATUS)
    if compile_only:
        require_field(report, "production_ready", False)
    else:
        require_field(report, "production_ready", True)
    require_field(report, "bundled_examples_count", len(EXPECTED_EXAMPLES))
    require_field(report, "bundled_examples_exact_order", EXPECTED_EXAMPLES)
    require_field(report, "non_production_examples", EXPECTED_NON_PRODUCTION_EXAMPLES)
    require_field(report, "original_scoped_action_count", EXPECTED_ACTION_COUNT)
    require_field(report, "original_scoped_lock_count", EXPECTED_LOCK_COUNT)
    require_field(report, "original_scoped_action_fail_closed_count", 0)
    require_field(report, "original_scoped_lock_fail_closed_count", 0)
    require_empty(report, "strict_original_ckb_compile_policy_fail_closed")
    require_empty(report, "strict_original_ckb_compile_unexpected_failures")
    require_empty(report, "original_scoped_action_fail_closed")
    require_empty(report, "original_scoped_lock_fail_closed")

    gate = report.get("production_gate")
    require(isinstance(gate, dict), "production_gate must be an object")
    require_field(gate, "status", EXPECTED_STATUS, "production_gate")
    require_empty(gate, "failures", "production_gate")
    require_field(gate, "requires_original_scoped_harnesses", True, "production_gate")
    require_field(gate, "requires_no_expected_fail_closed_entries", True, "production_gate")
    require_field(gate, "requires_all_bundled_examples_strict_original_ckb", True, "production_gate")

    coverage = report.get("ckb_business_coverage")
    require(isinstance(coverage, dict), "ckb_business_coverage must be an object")
    require_field(coverage, "strict_compile_coverage_complete", True, "ckb_business_coverage")
    require_field(coverage, "expected_fail_closed_action_count", 0, "ckb_business_coverage")
    require_field(coverage, "expected_fail_closed_lock_count", 0, "ckb_business_coverage")
    if compile_only:
        require_field(coverage, "status", "incomplete", "ckb_business_coverage")
        require_field(coverage, "onchain_action_coverage_complete", False, "ckb_business_coverage")
        require_field(coverage, "ckb_onchain_action_count", 0, "ckb_business_coverage")
        onchain = report.get("onchain")
        require(isinstance(onchain, dict), "onchain section must be present")
        require_field(onchain, "status", "skipped", "onchain")
        require_field(onchain, "reason", "compile-only", "onchain")
    else:
        require_field(coverage, "status", "complete", "ckb_business_coverage")
        require_field(coverage, "onchain_action_coverage_complete", True, "ckb_business_coverage")
        require_field(coverage, "ckb_onchain_action_count", EXPECTED_ACTION_COUNT, "ckb_business_coverage")
        missing = coverage.get("missing_ckb_onchain_actions")
        require(missing in ({}, None), f"ckb_business_coverage.missing_ckb_onchain_actions must be empty, got {missing!r}")

    example_scope = report.get("example_scope")
    require(isinstance(example_scope, dict), "example_scope must be an object")
    require_field(example_scope, "production_bundled_examples", EXPECTED_EXAMPLES, "example_scope")
    require_field(example_scope, "non_production_language_examples", EXPECTED_NON_PRODUCTION_EXAMPLES, "example_scope")
    scope_note = example_scope.get("production_scope_note")
    require(
        isinstance(scope_note, str)
        and "Only production_bundled_examples" in scope_note
        and "non_production_language_examples" in scope_note,
        "example_scope.production_scope_note must state the production/non-production example boundary",
    )

    lock_scope = report.get("lock_acceptance_scope")
    require(isinstance(lock_scope, dict), "lock_acceptance_scope must be an object")
    if lock_scope.get("onchain_lock_spend_matrix") is True:
        require_field(lock_scope, "strict_compile_only", False, "lock_acceptance_scope")
        require_field(lock_scope, "onchain_lock_spend_matrix_scope", EXPECTED_LOCK_SPEND_MATRIX, "lock_acceptance_scope")
        require_field(lock_scope, "required_cases_per_lock", ["valid_spend", "invalid_spend"], "lock_acceptance_scope")
    else:
        require_field(lock_scope, "strict_compile_only", True, "lock_acceptance_scope")
        require_field(lock_scope, "onchain_lock_spend_matrix", False, "lock_acceptance_scope")
        require_field(lock_scope, "pending_onchain_lock_spend_matrix", EXPECTED_LOCK_SPEND_MATRIX, "lock_acceptance_scope")
        require_field(
            lock_scope,
            "required_cases_per_lock_when_promoted",
            ["valid_spend", "invalid_spend"],
            "lock_acceptance_scope",
        )
    lock_scope_note = lock_scope.get("scope_note")
    require(isinstance(lock_scope_note, str) and "strict-compiled" in lock_scope_note, "lock_acceptance_scope.scope_note must mention strict compilation")


def validate_onchain_gate(report: dict[str, Any]) -> None:
    onchain = report.get("onchain")
    require(isinstance(onchain, dict), "onchain section must be present")
    require_field(onchain, "status", EXPECTED_STATUS, "onchain")
    require_field(onchain, "all_artifacts_deployed_and_spent", True, "onchain")
    require_field(onchain, "all_bundled_examples_deployed", True, "onchain")
    require_field(onchain, "bundled_examples_deployed", EXPECTED_EXAMPLES, "onchain")
    require_field(onchain, "all_token_actions_exercised", True, "onchain")
    require_field(onchain, "all_nft_actions_exercised", True, "onchain")
    require_field(onchain, "all_timelock_actions_exercised", True, "onchain")
    require_field(onchain, "all_multisig_actions_exercised", True, "onchain")
    require_field(onchain, "all_vesting_actions_exercised", True, "onchain")
    require_field(onchain, "all_amm_actions_exercised", True, "onchain")
    require_field(onchain, "all_launch_actions_exercised", True, "onchain")
    require_field(onchain, "builder_backed_action_count", EXPECTED_ACTION_COUNT, "onchain")
    require_field(onchain, "handwritten_harness_action_count", 0, "onchain")
    require_field(onchain, "measured_cycles_action_count", EXPECTED_ACTION_COUNT, "onchain")
    require_field(onchain, "tx_size_measured_action_count", EXPECTED_ACTION_COUNT, "onchain")
    require_field(onchain, "occupied_capacity_measured_action_count", EXPECTED_ACTION_COUNT, "onchain")
    require_field(onchain, "lock_spend_matrix_count", EXPECTED_LOCK_COUNT, "onchain")
    require_field(onchain, "builder_backed_lock_spend_matrix_count", EXPECTED_LOCK_COUNT, "onchain")
    require_field(onchain, "lock_valid_spend_count", EXPECTED_LOCK_COUNT, "onchain")
    require_field(onchain, "lock_invalid_spend_count", EXPECTED_LOCK_COUNT, "onchain")
    require_field(onchain, "measured_cycles_lock_count", EXPECTED_LOCK_COUNT, "onchain")
    require_field(onchain, "tx_size_measured_lock_count", EXPECTED_LOCK_COUNT, "onchain")
    require_field(onchain, "occupied_capacity_measured_lock_count", EXPECTED_LOCK_COUNT, "onchain")
    require_field(onchain, "all_locks_behavior_exercised", True, "onchain")

    deployment_runs = onchain.get("bundled_example_deployment_runs")
    require(isinstance(deployment_runs, list), "onchain.bundled_example_deployment_runs must be a list")
    require(
        len(deployment_runs) == len(EXPECTED_EXAMPLES),
        f"expected {len(EXPECTED_EXAMPLES)} bundled example deployment runs, got {len(deployment_runs)}",
    )
    deployment_names = [run.get("name") for run in deployment_runs if isinstance(run, dict)]
    require(
        deployment_names == EXPECTED_EXAMPLES,
        f"bundled example deployment order must be {EXPECTED_EXAMPLES!r}, got {deployment_names!r}",
    )
    for run in deployment_runs:
        require(isinstance(run, dict), "bundled example deployment run entries must be objects")
        name = run.get("name")
        require(isinstance(name, str) and name, "bundled example deployment run is missing name")
        require_field(run, "status", EXPECTED_STATUS, name)
        require_field(run, "kind", "bundled-example-strict-original", name)
        require_bool(run.get("code_cell_live"), f"{name}.code_cell_live")
        require_positive_int(run.get("artifact_size_bytes"), f"{name}.artifact_size_bytes")
        valid_deploy_dry_run = run.get("valid_deploy_dry_run")
        require(isinstance(valid_deploy_dry_run, dict), f"{name} missing valid_deploy_dry_run")
        require(
            isinstance(valid_deploy_dry_run.get("cycles"), str) and valid_deploy_dry_run["cycles"].startswith("0x"),
            f"{name} missing hex deploy dry-run cycles",
        )

    final_gate = report.get("final_production_hardening_gate")
    require(isinstance(final_gate, dict), "final_production_hardening_gate must be an object")
    require_field(final_gate, "status", EXPECTED_STATUS, "final_production_hardening_gate")
    require_field(final_gate, "ready", True, "final_production_hardening_gate")
    require_field(final_gate, "requires_builder_generated_transactions", True, "final_production_hardening_gate")
    require_field(final_gate, "requires_measured_cycles", True, "final_production_hardening_gate")
    require_field(final_gate, "requires_consensus_serialized_tx_size", True, "final_production_hardening_gate")
    require_field(final_gate, "requires_exact_occupied_capacity", True, "final_production_hardening_gate")
    require_empty(final_gate, "failures", "final_production_hardening_gate")

    runs = all_action_runs(report)
    require(len(runs) == EXPECTED_ACTION_COUNT, f"expected {EXPECTED_ACTION_COUNT} action runs, got {len(runs)}")
    seen_names: set[str] = set()
    for run in runs:
        name = run.get("name")
        require(isinstance(name, str) and name, "action run is missing name")
        require(name not in seen_names, f"duplicate action run name: {name}")
        seen_names.add(name)
        action = run.get("action")
        require(isinstance(action, str) and action, f"{name} is missing action")
        require(name.endswith(f":{action}"), f"{name} must end with action suffix :{action}")
        require_field(run, "status", EXPECTED_STATUS, name)
        require(run.get("builder_backed") is True, f"{name} is not builder-backed")
        require(isinstance(run.get("builder_name"), str) and run["builder_name"], f"{name} missing builder_name")
        require(isinstance(run.get("harness_origin"), str) and run["harness_origin"], f"{name} missing harness_origin")

        code = run.get("code")
        require(isinstance(code, dict), f"{name} missing code section")
        require_bool(code.get("code_cell_live"), f"{name}.code.code_cell_live")
        require_positive_int(code.get("artifact_size_bytes"), f"{name}.code.artifact_size_bytes")

        valid_dry_run = run.get("valid_dry_run")
        require(isinstance(valid_dry_run, dict), f"{name} missing valid_dry_run")
        require(isinstance(valid_dry_run.get("cycles"), str) and valid_dry_run["cycles"].startswith("0x"), f"{name} missing hex dry-run cycles")
        require(isinstance(run.get("valid_commit"), dict), f"{name} missing valid_commit")

        malformed = run.get("malformed_transaction")
        require(isinstance(malformed, dict), f"{name} missing malformed_transaction evidence")
        require_field(malformed, "status", "rejected", f"{name}.malformed_transaction")
        require_field(malformed, "expected_reason_matched", True, f"{name}.malformed_transaction")
        require_field(malformed, "policy_or_capacity_reason", False, f"{name}.malformed_transaction")

        measured = run.get("measured_constraints")
        require(isinstance(measured, dict), f"{name} missing measured_constraints")
        require_field(measured, "cycles_status", "dry-run-measured", f"{name}.measured_constraints")
        require_field(measured, "tx_size_status", "measured-by-cellscript-ckb-tx-measure", f"{name}.measured_constraints")
        require_field(
            measured,
            "occupied_capacity_status",
            "derived-by-cellscript-ckb-tx-measure",
            f"{name}.measured_constraints",
        )
        require_positive_int(measured.get("measured_cycles"), f"{name}.measured_constraints.measured_cycles")
        require_positive_int(
            measured.get("consensus_serialized_tx_size_bytes"),
            f"{name}.measured_constraints.consensus_serialized_tx_size_bytes",
        )
        occupied = require_positive_int(
            measured.get("occupied_capacity_shannons"),
            f"{name}.measured_constraints.occupied_capacity_shannons",
        )
        output_capacity = require_positive_int(
            measured.get("output_capacity_shannons"),
            f"{name}.measured_constraints.output_capacity_shannons",
        )
        require(output_capacity >= occupied, f"{name} output capacity is below occupied capacity")
        output_count = require_positive_int(measured.get("output_count"), f"{name}.measured_constraints.output_count")
        output_caps = measured.get("measured_output_capacity_shannons")
        output_occupied = measured.get("output_occupied_capacity_shannons")
        require(isinstance(output_caps, list), f"{name}.measured_constraints.measured_output_capacity_shannons must be a list")
        require(isinstance(output_occupied, list), f"{name}.measured_constraints.output_occupied_capacity_shannons must be a list")
        require(len(output_caps) == output_count, f"{name} measured output capacity count does not match output_count")
        require(len(output_occupied) == output_count, f"{name} occupied output capacity count does not match output_count")
        for index, (cap, occ) in enumerate(zip(output_caps, output_occupied)):
            cap_int = require_positive_int(cap, f"{name}.measured_constraints.measured_output_capacity_shannons[{index}]")
            occ_int = require_positive_int(occ, f"{name}.measured_constraints.output_occupied_capacity_shannons[{index}]")
            require(cap_int >= occ_int, f"{name} output {index} capacity is below occupied capacity")
        require(measured.get("capacity_is_sufficient") is True, f"{name} has insufficient capacity")
        require(measured.get("under_capacity_output_indexes") == [], f"{name} has under-capacity outputs")

    lock_runs = onchain.get("lock_spend_matrix_runs")
    require(isinstance(lock_runs, list), "onchain.lock_spend_matrix_runs must be a list")
    lock_names = [run.get("name") for run in lock_runs if isinstance(run, dict)]
    require(
        sorted(lock_names) == sorted(EXPECTED_LOCK_NAMES) and len(lock_names) == EXPECTED_LOCK_COUNT,
        f"lock spend matrix must cover {EXPECTED_LOCK_NAMES!r}, got {lock_names!r}",
    )
    require(len(set(lock_names)) == len(lock_names), f"lock spend matrix must not contain duplicates, got {lock_names!r}")
    for run in lock_runs:
        require(isinstance(run, dict), "lock spend matrix entries must be objects")
        name = run.get("name")
        require(isinstance(name, str) and name, "lock run is missing name")
        lock = run.get("lock")
        require(isinstance(lock, str) and lock, f"{name} is missing lock")
        require(name.endswith(f":{lock}"), f"{name} must end with lock suffix :{lock}")
        require_field(run, "status", EXPECTED_STATUS, name)
        require(run.get("builder_backed") is True, f"{name} lock run is not builder-backed")
        require(isinstance(run.get("builder_name"), str) and run["builder_name"], f"{name} missing builder_name")
        require(isinstance(run.get("harness_origin"), str) and run["harness_origin"], f"{name} missing harness_origin")

        code = run.get("code")
        require(isinstance(code, dict), f"{name} missing code section")
        require_bool(code.get("code_cell_live"), f"{name}.code.code_cell_live")
        require_positive_int(code.get("artifact_size_bytes"), f"{name}.code.artifact_size_bytes")

        valid_spend = run.get("valid_spend")
        require(isinstance(valid_spend, dict), f"{name} missing valid_spend evidence")
        require_field(valid_spend, "status", EXPECTED_STATUS, f"{name}.valid_spend")
        require_field(valid_spend, "output_live", True, f"{name}.valid_spend")
        valid_dry_run = valid_spend.get("dry_run")
        require(isinstance(valid_dry_run, dict), f"{name}.valid_spend missing dry_run")
        require(
            isinstance(valid_dry_run.get("cycles"), str) and valid_dry_run["cycles"].startswith("0x"),
            f"{name}.valid_spend missing hex dry-run cycles",
        )
        require(isinstance(valid_spend.get("commit"), dict), f"{name}.valid_spend missing commit")

        invalid_spend = run.get("invalid_spend")
        require(isinstance(invalid_spend, dict), f"{name} missing invalid_spend evidence")
        require_field(invalid_spend, "status", "rejected", f"{name}.invalid_spend")
        rejection = invalid_spend.get("rejection")
        require(isinstance(rejection, dict), f"{name}.invalid_spend missing rejection")
        require_field(rejection, "status", "rejected", f"{name}.invalid_spend.rejection")
        require_field(rejection, "expected_reason_matched", True, f"{name}.invalid_spend.rejection")
        require_field(rejection, "policy_or_capacity_reason", False, f"{name}.invalid_spend.rejection")
        reason = rejection.get("reason")
        require(isinstance(reason, str) and reason, f"{name}.invalid_spend.rejection missing reason")
        for fragment in ("source: Inputs[0].Lock", "ValidationFailure", "error code 5"):
            require(fragment in reason, f"{name}.invalid_spend.rejection must show lock predicate error fragment {fragment!r}")
        live_after_rejection = invalid_spend.get("input_cells_live_after_rejection")
        require(
            isinstance(live_after_rejection, list) and live_after_rejection and all(value is True for value in live_after_rejection),
            f"{name}.invalid_spend must keep rejected input cells live",
        )

        measured = run.get("measured_constraints")
        require(isinstance(measured, dict), f"{name} missing measured_constraints")
        require_field(measured, "cycles_status", "dry-run-measured", f"{name}.measured_constraints")
        require_field(measured, "tx_size_status", "measured-by-cellscript-ckb-tx-measure", f"{name}.measured_constraints")
        require_field(
            measured,
            "occupied_capacity_status",
            "derived-by-cellscript-ckb-tx-measure",
            f"{name}.measured_constraints",
        )
        require_positive_int(measured.get("measured_cycles"), f"{name}.measured_constraints.measured_cycles")
        require_positive_int(
            measured.get("consensus_serialized_tx_size_bytes"),
            f"{name}.measured_constraints.consensus_serialized_tx_size_bytes",
        )
        occupied = require_positive_int(
            measured.get("occupied_capacity_shannons"),
            f"{name}.measured_constraints.occupied_capacity_shannons",
        )
        output_capacity = require_positive_int(
            measured.get("output_capacity_shannons"),
            f"{name}.measured_constraints.output_capacity_shannons",
        )
        require(output_capacity >= occupied, f"{name} output capacity is below occupied capacity")
        require(measured.get("capacity_is_sufficient") is True, f"{name} has insufficient capacity")
        require(measured.get("under_capacity_output_indexes") == [], f"{name} has under-capacity outputs")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate production CKB CellScript acceptance evidence emitted by CellScript scripts/ckb_cellscript_acceptance.sh.",
    )
    parser.add_argument("report", type=Path, help="Path to ckb-cellscript-acceptance-report.json")
    parser.add_argument(
        "--compile-only",
        action="store_true",
        help="Only validate strict compile and scoped-entry production gates. This is not sufficient for external release.",
    )
    args = parser.parse_args()

    report_path = args.report.resolve()
    report = load_json(report_path)
    validate_compile_gate(report, compile_only=args.compile_only)
    if not args.compile_only:
        validate_onchain_gate(report)

    mode = "compile-only " if args.compile_only else ""
    print(f"valid CKB CellScript {mode}production evidence: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
