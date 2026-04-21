import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");

const requiredFiles = [
  "package.json",
  "extension.js",
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

if (!Array.isArray(pkg.contributes?.languages) || pkg.contributes.languages.length === 0) {
  throw new Error("package.json must contribute at least one language");
}

if (pkg.main !== "./extension.js") {
  throw new Error(`unexpected extension entrypoint: ${pkg.main}`);
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
if (!extensionSource.includes("cellscript.validateCurrentFile")) {
  throw new Error("extension runtime must register the validateCurrentFile command");
}

console.log("CellScript VS Code extension manifest is valid.");
