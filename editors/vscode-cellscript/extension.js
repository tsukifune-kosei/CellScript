const vscode = require("vscode");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const cp = require("node:child_process");

const LANGUAGE_ID = "cellscript";
const OUTPUT_NAME = "CellScript";
const SCRATCH_DIR = ".cellscript-vscode";

function activate(context) {
  const diagnostics = vscode.languages.createDiagnosticCollection(LANGUAGE_ID);
  const output = vscode.window.createOutputChannel(OUTPUT_NAME);
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  const pending = new Map();

  status.name = "CellScript";
  status.command = "cellscript.validateCurrentFile";
  status.text = "$(check) CellScript";
  status.tooltip = "Validate the active CellScript file";

  context.subscriptions.push(diagnostics, output, status);

  context.subscriptions.push(
    vscode.commands.registerCommand("cellscript.validateCurrentFile", async () => {
      const document = activeCellScriptDocument();
      if (document) {
        await validateDocument(document, diagnostics, output, status);
      }
    }),
    vscode.commands.registerCommand("cellscript.compileCurrentFile", async () => {
      const document = activeCellScriptDocument();
      if (document) {
        await runCompilerReport(document, output, status, "compile");
      }
    }),
    vscode.commands.registerCommand("cellscript.showMetadata", async () => {
      const document = activeCellScriptDocument();
      if (document) {
        await runCompilerReport(document, output, status, "metadata");
      }
    }),
    vscode.commands.registerCommand("cellscript.showConstraints", async () => {
      const document = activeCellScriptDocument();
      if (document) {
        await runCompilerReport(document, output, status, "constraints");
      }
    }),
    vscode.commands.registerCommand("cellscript.showProductionReport", async () => {
      const document = activeCellScriptDocument();
      if (document) {
        await runProductionReport(document, output, status);
      }
    }),
    vscode.commands.registerCommand("cellscript.formatCurrentFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor || editor.document.languageId !== LANGUAGE_ID) {
        return;
      }
      const edits = await buildFormatEdits(editor.document, output, status);
      if (edits.length > 0) {
        await editor.edit((builder) => {
          for (const edit of edits) {
            builder.replace(edit.range, edit.newText);
          }
        });
      }
    }),
    vscode.commands.registerCommand("cellscript.selectTargetProfile", async () => {
      const picked = await vscode.window.showQuickPick(
        [
          { label: "spora", description: "Spora artifact profile" },
          { label: "ckb", description: "CKB artifact profile" },
          { label: "portable-cell", description: "Portability policy profile" }
        ],
        { title: "CellScript Target Profile" }
      );
      if (!picked) {
        return;
      }
      await vscode.workspace.getConfiguration("cellscript").update("targetProfile", picked.label, vscode.ConfigurationTarget.Workspace);
      vscode.window.showInformationMessage(`CellScript target profile set to ${picked.label}`);
    })
  );

  context.subscriptions.push(
    vscode.languages.registerDocumentFormattingEditProvider(LANGUAGE_ID, {
      provideDocumentFormattingEdits(document) {
        return buildFormatEdits(document, output, status);
      }
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((document) => scheduleValidation(document, diagnostics, output, status, pending)),
    vscode.workspace.onDidSaveTextDocument((document) => scheduleValidation(document, diagnostics, output, status, pending)),
    vscode.workspace.onDidChangeTextDocument((event) => {
      const config = vscode.workspace.getConfiguration("cellscript", event.document.uri);
      if (config.get("validateOnChange", true)) {
        scheduleValidation(event.document, diagnostics, output, status, pending);
      }
    }),
    vscode.workspace.onDidCloseTextDocument((document) => {
      diagnostics.delete(document.uri);
      const timer = pending.get(document.uri.toString());
      if (timer) {
        clearTimeout(timer);
        pending.delete(document.uri.toString());
      }
    })
  );

  for (const document of vscode.workspace.textDocuments) {
    scheduleValidation(document, diagnostics, output, status, pending);
  }
}

function deactivate() {}

function activeCellScriptDocument() {
  const editor = vscode.window.activeTextEditor;
  if (!editor || editor.document.languageId !== LANGUAGE_ID) {
    vscode.window.showWarningMessage("Open a .cell file first.");
    return null;
  }
  return editor.document;
}

function scheduleValidation(document, diagnostics, output, status, pending) {
  if (document.languageId !== LANGUAGE_ID || document.uri.scheme !== "file") {
    return;
  }

  const config = vscode.workspace.getConfiguration("cellscript", document.uri);
  if (config.get("validationMode", "parse") === "off") {
    diagnostics.delete(document.uri);
    return;
  }

  const key = document.uri.toString();
  const previous = pending.get(key);
  if (previous) {
    clearTimeout(previous);
  }

  const debounceMs = Math.max(config.get("validationDebounceMs", 250), 50);
  const timer = setTimeout(async () => {
    pending.delete(key);
    await validateDocument(document, diagnostics, output, status);
  }, debounceMs);

  pending.set(key, timer);
}

async function validateDocument(document, diagnostics, output, status) {
  const config = vscode.workspace.getConfiguration("cellscript", document.uri);
  const validationMode = config.get("validationMode", "parse");
  if (validationMode === "off") {
    diagnostics.delete(document.uri);
    updateStatus(status, "idle");
    return;
  }

  const command = await resolveCompilerCommand(document);
  if (!command) {
    diagnostics.set(document.uri, [missingCompilerDiagnostic(document)]);
    updateStatus(status, "missing");
    output.appendLine(`[cellscript] no compiler found for ${document.uri.fsPath}`);
    return;
  }

  const plan = buildValidationPlan(document, validationMode, command.cwd);
  updateStatus(status, "running", plan.source);
  const result = await runCommand(command.command, [...command.args, ...plan.args], command.cwd, command.options);
  cleanupScratchOutput(plan);

  if (result.code === 0) {
    diagnostics.delete(document.uri);
    updateStatus(status, "ok", plan.source);
    return;
  }

  const issues = parseDiagnostics(result.stderr || result.stdout || "");
  if (issues.length === 0) {
    const fallback = new vscode.Diagnostic(
      new vscode.Range(0, 0, 0, 1),
      (result.stderr || result.stdout || "CellScript validation failed").trim(),
      vscode.DiagnosticSeverity.Error
    );
    fallback.source = plan.source;
    diagnostics.set(document.uri, [fallback]);
  } else {
    diagnostics.set(document.uri, issues.map((issue) => toDiagnostic(document, issue, plan.source)));
  }
  updateStatus(status, "error", plan.source);
}

async function runCompilerReport(document, output, status, kind) {
  const command = await resolveCompilerCommand(document);
  if (!command) {
    vscode.window.showErrorMessage("CellScript compiler not found. Configure cellscript.compilerPath or install cellc.");
    return;
  }

  const plan = buildReportPlan(document, kind, command.cwd);
  updateStatus(status, "running", plan.source);
  const result = await runCommand(command.command, [...command.args, ...plan.args], command.cwd, command.options);
  cleanupScratchOutput(plan);

  output.clear();
  output.appendLine(`[cellscript] ${plan.source}`);
  output.appendLine(`$ ${command.command} ${[...command.args, ...plan.args].join(" ")}`);
  output.appendLine("");
  if (result.stdout.trim()) {
    output.appendLine(result.stdout.trimEnd());
  }
  if (result.stderr.trim()) {
    output.appendLine(result.stderr.trimEnd());
  }
  output.show(true);

  if (result.code === 0) {
    updateStatus(status, "ok", plan.source);
  } else {
    updateStatus(status, "error", plan.source);
    vscode.window.showErrorMessage(`CellScript ${kind} failed. See the CellScript output channel.`);
  }
}

async function runProductionReport(document, output, status) {
  const command = await resolveCompilerCommand(document);
  if (!command) {
    vscode.window.showErrorMessage("CellScript compiler not found. Configure cellscript.compilerPath or install cellc.");
    return;
  }

  const metadataPlan = buildReportPlan(document, "metadata", command.cwd);
  const constraintsPlan = buildReportPlan(document, "constraints", command.cwd);
  updateStatus(status, "running", "cellc production report");

  const versionResult = await runCommand(command.command, [...command.args, "--version"], command.cwd, command.options);
  const metadataResult = await runCommand(command.command, [...command.args, ...metadataPlan.args], command.cwd, command.options);
  const constraintsResult = await runCommand(command.command, [...command.args, ...constraintsPlan.args], command.cwd, command.options);

  output.clear();
  output.appendLine("[cellscript] production report");
  output.appendLine(`source: ${document.uri.fsPath}`);
  output.appendLine(`target args: ${targetProfileArgs(document).join(" ") || "(default)"}`);
  output.appendLine("");
  appendCommandSection(output, "Compiler Version", command, ["--version"], versionResult);
  appendCommandSection(output, "Artifact Metadata", command, metadataPlan.args, metadataResult);
  appendCommandSection(output, "Constraints", command, constraintsPlan.args, constraintsResult);
  output.appendLine("## Release Audit Boundary");
  output.appendLine("- Verify artifact metadata, compiler version pin, schema hash, constraints hash, and build provenance from the JSON above.");
  output.appendLine("- Audit signatures are release artifacts produced by the release process; this extension displays compiler evidence but does not sign artifacts.");
  output.appendLine("- Chain production readiness still requires Spora/CKB acceptance gates and builder-generated transactions.");
  output.show(true);

  if (versionResult.code === 0 && metadataResult.code === 0 && constraintsResult.code === 0) {
    updateStatus(status, "ok", "cellc production report");
  } else {
    updateStatus(status, "error", "cellc production report");
    vscode.window.showErrorMessage("CellScript production report failed. See the CellScript output channel.");
  }
}

function appendCommandSection(output, title, command, args, result) {
  output.appendLine(`## ${title}`);
  output.appendLine(`$ ${command.command} ${[...command.args, ...args].join(" ")}`);
  output.appendLine(`exit_code: ${result.code}`);
  if (result.stdout.trim()) {
    output.appendLine(result.stdout.trimEnd());
  }
  if (result.stderr.trim()) {
    output.appendLine(result.stderr.trimEnd());
  }
  output.appendLine("");
}

async function buildFormatEdits(document, output, status) {
  if (document.languageId !== LANGUAGE_ID || document.uri.scheme !== "file") {
    return [];
  }

  const command = await resolveCompilerCommand(document);
  if (!command) {
    vscode.window.showErrorMessage("CellScript compiler not found. Configure cellscript.compilerPath or install cellc.");
    updateStatus(status, "missing");
    return [];
  }

  const scratch = writeScratchDocument(document, command.cwd, "format.cell");
  updateStatus(status, "running", "cellc fmt");
  const result = await runCommand(command.command, [...command.args, "fmt", scratch.path], command.cwd, command.options);
  if (result.code !== 0) {
    output.appendLine(`[cellscript] format failed for ${document.uri.fsPath}`);
    output.appendLine(result.stderr || result.stdout || "cellc fmt failed");
    output.show(true);
    cleanupScratchFile(scratch.path);
    updateStatus(status, "error", "cellc fmt");
    return [];
  }

  let formatted;
  try {
    formatted = fs.readFileSync(scratch.path, "utf8");
  } finally {
    cleanupScratchFile(scratch.path);
  }

  updateStatus(status, "ok", "cellc fmt");
  if (formatted === document.getText()) {
    return [];
  }

  return [vscode.TextEdit.replace(fullDocumentRange(document), formatted)];
}

async function resolveCompilerCommand(document) {
  const config = vscode.workspace.getConfiguration("cellscript", document.uri);
  const compilerPath = config.get("compilerPath", "cellc");
  const useCargoRunFallback = config.get("useCargoRunFallback", true);
  const options = {
    timeout: Math.max(config.get("commandTimeoutMs", 15000), 1000),
    maxBuffer: Math.max(config.get("maxOutputBytes", 4 * 1024 * 1024), 64 * 1024)
  };

  if (compilerPath && (await canExecute(compilerPath, ["--version"], undefined, options))) {
    return { command: compilerPath, args: [], cwd: undefined, options };
  }

  if (!useCargoRunFallback) {
    return null;
  }

  const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
  const cwd = workspaceFolder ? workspaceFolder.uri.fsPath : path.dirname(document.uri.fsPath);
  const cargoToml = findCargoWorkspace(cwd);
  if (cargoToml && (await canExecute("cargo", ["run", "-q", "-p", "cellscript", "--", "--version"], cargoToml, options))) {
    return { command: "cargo", args: ["run", "-q", "-p", "cellscript", "--"], cwd: cargoToml, options };
  }

  return null;
}

function findCargoWorkspace(startDir) {
  let current = startDir;
  while (current && current !== path.dirname(current)) {
    if (fs.existsSync(path.join(current, "Cargo.toml"))) {
      return current;
    }
    current = path.dirname(current);
  }
  return null;
}

function canExecute(command, args, cwd, options) {
  return new Promise((resolve) => {
    cp.execFile(command, args, { cwd, timeout: options.timeout, maxBuffer: options.maxBuffer }, (error) => {
      resolve(!error);
    });
  });
}

function runCommand(command, args, cwd, options) {
  return new Promise((resolve) => {
    cp.execFile(command, args, { cwd, timeout: options.timeout, maxBuffer: options.maxBuffer }, (error, stdout, stderr) => {
      resolve({
        code: error && typeof error.code === "number" ? error.code : error ? 1 : 0,
        stdout: stdout || "",
        stderr: stderr || ""
      });
    });
  });
}

function buildValidationPlan(document, mode, cwd) {
  if (mode === "compile-asm") {
    const outputPath = getScratchOutputPath(document, cwd, "validation.s");
    return {
      args: [document.uri.fsPath, "--target", "riscv64-asm", ...targetProfileArgs(document), "-o", outputPath],
      outputPath,
      source: "cellc compile-asm"
    };
  }

  return {
    args: [document.uri.fsPath, "--parse"],
    outputPath: null,
    source: "cellc --parse"
  };
}

function buildReportPlan(document, kind, cwd) {
  if (kind === "metadata") {
    return {
      args: ["metadata", document.uri.fsPath, ...targetProfileArgs(document)],
      outputPath: null,
      source: "cellc metadata"
    };
  }

  if (kind === "constraints") {
    return {
      args: ["constraints", document.uri.fsPath, ...targetProfileArgs(document)],
      outputPath: null,
      source: "cellc constraints"
    };
  }

  const outputPath = getScratchOutputPath(document, cwd, "compile.s");
  return {
    args: [document.uri.fsPath, "--target", "riscv64-asm", ...targetProfileArgs(document), "-o", outputPath],
    outputPath,
    source: "cellc compile"
  };
}

function targetProfileArgs(document) {
  const config = vscode.workspace.getConfiguration("cellscript", document.uri);
  const target = config.get("target", "riscv64-asm");
  const profile = config.get("targetProfile", "spora");
  const args = [];
  if (target) {
    args.push("--target", target);
  }
  if (profile) {
    args.push("--target-profile", profile);
  }
  return args;
}

function writeScratchDocument(document, cwd, suffix) {
  const file = getScratchOutputPath(document, cwd, suffix);
  fs.writeFileSync(file, document.getText(), "utf8");
  return { path: file };
}

function getScratchOutputPath(document, cwd, suffix) {
  const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
  const baseDir = workspaceFolder
    ? path.join(workspaceFolder.uri.fsPath, SCRATCH_DIR)
    : path.join(cwd || path.dirname(document.uri.fsPath) || os.tmpdir(), SCRATCH_DIR);

  fs.mkdirSync(baseDir, { recursive: true });
  const stem = path.basename(document.uri.fsPath, path.extname(document.uri.fsPath));
  return path.join(baseDir, `${stem}.${process.pid}.${Date.now()}.${suffix}`);
}

function cleanupScratchOutput(plan) {
  if (plan.outputPath) {
    cleanupScratchFile(plan.outputPath);
  }
}

function cleanupScratchFile(file) {
  try {
    fs.rmSync(file, { force: true });
  } catch {
    // Scratch cleanup should never hide the compiler result.
  }
}

function parseDiagnostics(text) {
  const lines = text.split(/\r?\n/);
  const issues = [];
  const linePattern = /^error:\s+line\s+(\d+):\s+(.*)$/i;
  const filePattern = /^error:\s+(.+?):(\d+):(?:(\d+):)?\s+(.*)$/i;

  for (const line of lines) {
    const trimmed = line.trim();
    let match = linePattern.exec(trimmed);
    if (match) {
      issues.push({
        line: Math.max(Number(match[1]) - 1, 0),
        character: 0,
        message: match[2].trim()
      });
      continue;
    }

    match = filePattern.exec(trimmed);
    if (match) {
      issues.push({
        file: match[1],
        line: Math.max(Number(match[2]) - 1, 0),
        character: match[3] ? Math.max(Number(match[3]) - 1, 0) : 0,
        message: match[4].trim()
      });
    }
  }

  return issues;
}

function toDiagnostic(document, issue, source) {
  const line = Math.min(issue.line, Math.max(document.lineCount - 1, 0));
  const sourceLine = document.lineAt(line);
  const start = Math.min(issue.character || 0, sourceLine.text.length);
  const end = Math.max(start + 1, sourceLine.text.length || 1);
  const diagnostic = new vscode.Diagnostic(new vscode.Range(line, start, line, end), issue.message, vscode.DiagnosticSeverity.Error);
  diagnostic.source = source;
  return diagnostic;
}

function missingCompilerDiagnostic(document) {
  const diagnostic = new vscode.Diagnostic(
    new vscode.Range(0, 0, Math.max(document.lineCount - 1, 0), 0),
    "CellScript compiler not found. Configure cellscript.compilerPath or install cellc.",
    vscode.DiagnosticSeverity.Warning
  );
  diagnostic.source = "cellscript extension";
  return diagnostic;
}

function fullDocumentRange(document) {
  const lastLine = Math.max(document.lineCount - 1, 0);
  const lastCharacter = document.lineAt(lastLine).text.length;
  return new vscode.Range(0, 0, lastLine, lastCharacter);
}

function updateStatus(status, state, detail) {
  if (state === "running") {
    status.text = "$(sync~spin) CellScript";
    status.tooltip = detail ? `Running ${detail}` : "CellScript is running";
    status.show();
    return;
  }

  if (state === "ok") {
    status.text = "$(check) CellScript";
    status.tooltip = detail ? `${detail} passed` : "CellScript validation passed";
    status.show();
    return;
  }

  if (state === "error") {
    status.text = "$(error) CellScript";
    status.tooltip = detail ? `${detail} failed` : "CellScript validation failed";
    status.show();
    return;
  }

  if (state === "missing") {
    status.text = "$(warning) CellScript";
    status.tooltip = "CellScript compiler not found";
    status.show();
    return;
  }

  status.text = "$(check) CellScript";
  status.tooltip = "Validate the active CellScript file";
  status.show();
}

module.exports = { activate, deactivate };
