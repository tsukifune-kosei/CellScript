import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");

const requiredFiles = [
  "package.json",
  "extension.js",
  "README.md",
  "CHANGELOG.md",
  "language-configuration.json",
  "syntaxes/cellscript.tmLanguage.json",
  "snippets/cellscript.json"
];

for (const relative of requiredFiles) {
  const file = path.join(root, relative);
  if (!fs.existsSync(file)) {
    throw new Error(`missing required file: ${relative}`);
  }
}

const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
const grammar = JSON.parse(fs.readFileSync(path.join(root, "syntaxes/cellscript.tmLanguage.json"), "utf8"));
const languageConfig = JSON.parse(fs.readFileSync(path.join(root, "language-configuration.json"), "utf8"));
const snippets = JSON.parse(fs.readFileSync(path.join(root, "snippets/cellscript.json"), "utf8"));

if (pkg.name !== "cellscript-vscode") {
  throw new Error(`unexpected package name: ${pkg.name}`);
}

if (pkg.version !== "0.12.0") {
  throw new Error(`unexpected extension version: ${pkg.version}`);
}

if (!pkg.repository?.url?.includes("tsukifune-kosei/CellScript")) {
  throw new Error(`extension repository must point at standalone CellScript repo: ${pkg.repository?.url}`);
}

if (!Array.isArray(pkg.contributes?.languages) || pkg.contributes.languages.length === 0) {
  throw new Error("package.json must contribute at least one language");
}

if (pkg.main !== "./extension.js") {
  throw new Error(`unexpected extension entrypoint: ${pkg.main}`);
}

const commands = new Set((pkg.contributes?.commands || []).map((command) => command.command));
for (const command of [
  "cellscript.compileCurrentFile",
  "cellscript.showMetadata",
  "cellscript.showConstraints",
  "cellscript.showProductionReport",
  "cellscript.selectTargetProfile"
]) {
  if (!commands.has(command)) {
    throw new Error(`missing command contribution: ${command}`);
  }
}

const properties = pkg.contributes?.configuration?.properties || {};
for (const setting of [
  "cellscript.compilerPath",
  "cellscript.useCargoRunFallback",
  "cellscript.commandTimeoutMs",
  "cellscript.maxOutputBytes",
  "cellscript.target",
  "cellscript.targetProfile"
]) {
  if (!properties[setting]) {
    throw new Error(`missing configuration setting: ${setting}`);
  }
}

if (!Array.isArray(grammar.patterns) || grammar.patterns.length === 0) {
  throw new Error("grammar must contain top-level patterns");
}

if (grammar.scopeName !== "source.cellscript") {
  throw new Error(`unexpected grammar scope: ${grammar.scopeName}`);
}

if (!languageConfig.comments?.lineComment) {
  throw new Error("language configuration must declare line comments");
}

if (typeof snippets !== "object" || snippets === null || Object.keys(snippets).length === 0) {
  throw new Error("snippets file must contain at least one snippet");
}

const extensionSource = fs.readFileSync(path.join(root, "extension.js"), "utf8");
for (const token of [
  "LanguageClient",
  "vscode-languageclient",
  "cellscript.compileCurrentFile",
  "cellscript.showMetadata",
  "cellscript.showConstraints",
  "cellscript.showProductionReport",
  "cellscript.selectTargetProfile",
  "cellc",
  "--lsp",
  "TransportKind.stdio"
]) {
  if (!extensionSource.includes(token)) {
    throw new Error(`extension runtime is missing expected wiring: ${token}`);
  }
}

const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");
if (/\bbeta\b|\bthin\b|placeholder|metadata-only/i.test(readme)) {
  throw new Error("extension README must describe the production local tooling surface, not beta/thin placeholder scope");
}

console.log("CellScript VS Code extension manifest is valid.");
