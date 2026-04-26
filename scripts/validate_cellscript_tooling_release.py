#!/usr/bin/env python3
"""Validate CellScript package/LSP/tooling release boundaries."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"invalid CellScript tooling release boundary: {message}")


def require_contains(path: str, tokens: list[str]) -> None:
    text = read(path)
    for token in tokens:
        require(token in text, f"{path} is missing {token!r}")


def main() -> int:
    package_json = json.loads(read("editors/vscode-cellscript/package.json"))

    require(package_json["name"] == "cellscript-vscode", "VS Code extension package name changed")
    require(package_json["main"] == "./dist/extension.js", "VS Code extension entrypoint changed")
    require("vscode-languageclient" in package_json.get("devDependencies", {}), "VS Code extension must build with vscode-languageclient")
    require("esbuild" in package_json.get("devDependencies", {}), "VS Code extension must bundle with esbuild")
    require("build" in package_json.get("scripts", {}), "VS Code extension must expose a build script")
    require("vscode:prepublish" in package_json.get("scripts", {}), "VS Code extension must build before publish")
    require("package" in package_json.get("scripts", {}), "VS Code extension must expose a package script")
    require("publish:dry-run" in package_json.get("scripts", {}), "VS Code extension must expose a publish dry-run script")

    require_contains(
        "src/main.rs",
        [
            "Start the language server (JSON-RPC over stdio).",
            "cellscript::lsp::server::run_lsp_server_blocking();",
        ],
    )
    require_contains(
        "src/lsp/server.rs",
        [
            "tower_lsp::LanguageServer",
            "JSON-RPC",
            "completion_provider",
            "hover_provider",
            "definition_provider",
            "references_provider",
            "rename_provider",
            "document_formatting_provider",
            "signature_help_provider",
            "folding_range_provider",
            "selection_range_provider",
        ],
    )
    require_contains(
        "editors/vscode-cellscript/extension.js",
        [
            "LanguageClient",
            "TransportKind.stdio",
            "--lsp",
            "cellscript.showConstraints",
            "cellscript.showProductionReport",
        ],
    )
    require_contains(
        "editors/vscode-cellscript/scripts/validate.mjs",
        [
            "LanguageClient",
            "TransportKind.stdio",
            "extension README must describe the production local tooling surface",
        ],
    )
    require_contains(
        "src/package/mod.rs",
        [
            "registry dependency '{}' with version '{}' is not supported yet; use a local path dependency",
            "Git { url: String, revision: String }",
            "pub fn consistency_issues(&self, manifest: &PackageManifest) -> Vec<String>",
            "pub fn replace_with_resolved(&mut self, resolved: &HashMap<String, ResolvedPackage>)",
        ],
    )
    require_contains(
        "tests/cli.rs",
        [
            "cellc_rejects_registry_package_dependencies_fail_closed",
            "cellc_install_path_updates_lockfile_and_remove_prunes_it",
            "cellc_fmt_subcommand_formats_sources",
            "cellc_run_subcommand_executes_pure_elf_package",
        ],
    )

    cargo_toml = read("Cargo.toml")
    for excluded in [
        '".github/"',
        '"docs/"',
        '"docs/wiki/"',
        '"editors/"',
    ]:
        require(excluded in cargo_toml, f"Cargo.toml package exclude is missing {excluded}")

    print("valid CellScript tooling release boundary")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
