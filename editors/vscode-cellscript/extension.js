const vscode = require("vscode");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const cp = require("node:child_process");

function activate(context) {
  const diagnostics = vscode.languages.createDiagnosticCollection("cellscript");
  const output = vscode.window.createOutputChannel("CellScript");
  const pending = new Map();

  context.subscriptions.push(diagnostics, output);

  const validateCurrentFile = vscode.commands.registerCommand("cellscript.validateCurrentFile", async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document.languageId !== "cellscript") {
      return;
    }
    await validateDocument(editor.document, diagnostics, output);
  });

  const onOpen = vscode.workspace.onDidOpenTextDocument((document) => {
    scheduleValidation(document, diagnostics, output, pending);
  });

  const onSave = vscode.workspace.onDidSaveTextDocument((document) => {
    scheduleValidation(document, diagnostics, output, pending);
  });

  const onClose = vscode.workspace.onDidCloseTextDocument((document) => {
    diagnostics.delete(document.uri);
    const timer = pending.get(document.uri.toString());
    if (timer) {
      clearTimeout(timer);
      pending.delete(document.uri.toString());
    }
  });

  context.subscriptions.push(validateCurrentFile, onOpen, onSave, onClose);

  for (const document of vscode.workspace.textDocuments) {
    scheduleValidation(document, diagnostics, output, pending);
  }
}

function deactivate() {}

function scheduleValidation(document, diagnostics, output, pending) {
  if (document.languageId !== "cellscript" || document.uri.scheme !== "file") {
    return;
  }

  const key = document.uri.toString();
  const previous = pending.get(key);
  if (previous) {
    clearTimeout(previous);
  }

  const timer = setTimeout(async () => {
    pending.delete(key);
    await validateDocument(document, diagnostics, output);
  }, 150);

  pending.set(key, timer);
}

async function validateDocument(document, diagnostics, output) {
  const config = vscode.workspace.getConfiguration("cellscript", document.uri);
  const validationMode = config.get("validationMode", "parse");
  if (validationMode === "off") {
    diagnostics.delete(document.uri);
    return;
  }

  const command = await resolveCompilerCommand(document);
  if (!command) {
    diagnostics.delete(document.uri);
    output.appendLine(`[cellscript] no compiler found for ${document.uri.fsPath}`);
    return;
  }

  const plan = buildValidationPlan(document, validationMode, command.cwd);
  const result = await runCommand(command.command, [...command.args, ...plan.args], command.cwd);
  cleanupScratchOutput(plan);

  if (result.code === 0) {
    diagnostics.delete(document.uri);
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
    return;
  }

  diagnostics.set(document.uri, issues.map((issue) => toDiagnostic(document, issue, plan.source)));
}

async function resolveCompilerCommand(document) {
  const config = vscode.workspace.getConfiguration("cellscript", document.uri);
  const compilerPath = config.get("compilerPath", "cellc");
  const useCargoRunFallback = config.get("useCargoRunFallback", true);

  if (compilerPath && (await canExecute(compilerPath, ["--version"]))) {
    return { command: compilerPath, args: [], cwd: undefined };
  }

  if (!useCargoRunFallback) {
    return null;
  }

  const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
  const cwd = workspaceFolder ? workspaceFolder.uri.fsPath : path.dirname(document.uri.fsPath);

  if (fs.existsSync(path.join(cwd, "Cargo.toml")) && (await canExecute("cargo", ["run", "-q", "-p", "cellscript", "--", "--version"], cwd))) {
    return { command: "cargo", args: ["run", "-q", "-p", "cellscript", "--"], cwd };
  }

  return null;
}

function canExecute(command, args, cwd) {
  return new Promise((resolve) => {
    cp.execFile(command, args, { cwd }, (error) => {
      resolve(!error);
    });
  });
}

function runCommand(command, args, cwd) {
  return new Promise((resolve) => {
    cp.execFile(command, args, { cwd }, (error, stdout, stderr) => {
      resolve({
        code: error && typeof error.code === "number" ? error.code : 0,
        stdout: stdout || "",
        stderr: stderr || ""
      });
    });
  });
}

function buildValidationPlan(document, mode, cwd) {
  if (mode === "compile-asm") {
    const outputPath = getScratchOutputPath(document, cwd);
    return {
      args: [document.uri.fsPath, "--target", "riscv64-asm", "-o", outputPath],
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

function getScratchOutputPath(document, cwd) {
  const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
  const baseDir = workspaceFolder
    ? path.join(workspaceFolder.uri.fsPath, ".cellscript-vscode")
    : path.join(cwd || path.dirname(document.uri.fsPath) || os.tmpdir(), ".cellscript-vscode");

  fs.mkdirSync(baseDir, { recursive: true });
  const stem = path.basename(document.uri.fsPath, path.extname(document.uri.fsPath));
  return path.join(baseDir, `${stem}.validation.s`);
}

function cleanupScratchOutput(plan) {
  if (!plan.outputPath) {
    return;
  }

  try {
    fs.rmSync(plan.outputPath, { force: true });
  } catch {
    // ignore scratch cleanup failures
  }
}

function parseDiagnostics(text) {
  const lines = text.split(/\r?\n/);
  const issues = [];
  const linePattern = /^error:\s+line\s+(\d+):\s+(.*)$/i;
  const filePattern = /^error:\s+(.+?):(\d+):\s+(.*)$/i;

  for (const line of lines) {
    const trimmed = line.trim();
    let match = linePattern.exec(trimmed);
    if (match) {
      issues.push({
        line: Math.max(Number(match[1]) - 1, 0),
        message: match[2].trim()
      });
      continue;
    }

    match = filePattern.exec(trimmed);
    if (match) {
      issues.push({
        file: match[1],
        line: Math.max(Number(match[2]) - 1, 0),
        message: match[3].trim()
      });
    }
  }

  return issues;
}

function toDiagnostic(document, issue, source) {
  const line = Math.min(issue.line, Math.max(document.lineCount - 1, 0));
  const sourceLine = document.lineAt(line);
  const range = new vscode.Range(line, 0, line, Math.max(sourceLine.text.length, 1));
  const diagnostic = new vscode.Diagnostic(range, issue.message, vscode.DiagnosticSeverity.Error);
  diagnostic.source = source;
  return diagnostic;
}

module.exports = { activate, deactivate };
