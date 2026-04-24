const vscode = require("vscode");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const cp = require("node:child_process");
const { LanguageClient, TransportKind } = require("vscode-languageclient");

const LANGUAGE_ID = "cellscript";
const OUTPUT_NAME = "CellScript";

/** @type {LanguageClient | undefined} */
let languageClient = undefined;

function activate(context) {
  const output = vscode.window.createOutputChannel(OUTPUT_NAME);
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);

  status.name = "CellScript";
  status.text = "$(check) CellScript";
  status.tooltip = "CellScript Language Server";
  status.show();

  context.subscriptions.push(output, status);

  // ---- Start the LSP language server ----
  startLanguageServer(context, output, status);

  // ---- CLI-backed commands (not covered by LSP) ----
  context.subscriptions.push(
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
}

function deactivate() {
  if (languageClient) {
    return languageClient.stop();
  }
  return undefined;
}

// ============================================================================
// LSP Language Server
// ============================================================================

async function startLanguageServer(context, output, status) {
  const config = vscode.workspace.getConfiguration("cellscript");
  const serverPath = resolveServerPath(config);

  if (!serverPath) {
    status.text = "$(warning) CellScript";
    status.tooltip = "CellScript compiler not found. Configure cellscript.compilerPath or install cellc.";
    output.appendLine("[cellscript] No cellc binary found for language server.");
    return;
  }

  const serverOptions = {
    command: serverPath.command,
    args: [...serverPath.args, "--lsp"],
    transport: TransportKind.stdio,
    options: {
      cwd: serverPath.cwd
    }
  };

  const clientOptions = {
    documentSelector: [{ scheme: "file", language: LANGUAGE_ID }],
    outputChannel: output,
    synchronize: {
      configurationSection: "cellscript"
    }
  };

  languageClient = new LanguageClient(
    LANGUAGE_ID,
    "CellScript Language Server",
    serverOptions,
    clientOptions
  );

  try {
    await languageClient.start();
    status.text = "$(check) CellScript";
    status.tooltip = "CellScript Language Server active";
    output.appendLine("[cellscript] Language server started successfully.");
  } catch (error) {
    status.text = "$(error) CellScript";
    status.tooltip = "CellScript Language Server failed to start";
    output.appendLine(`[cellscript] Language server failed: ${error}`);
  }
}

function resolveServerPath(config) {
  const compilerPath = config.get("compilerPath", "cellc");

  // Direct cellc path.
  if (compilerPath) {
    try {
      cp.execFileSync(compilerPath, ["--version"], { timeout: 5000 });
      return { command: compilerPath, args: [], cwd: undefined };
    } catch {
      // Fall through to cargo fallback.
    }
  }

  // Cargo fallback.
  if (config.get("useCargoRunFallback", true)) {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (workspaceFolder) {
      const cwd = workspaceFolder.uri.fsPath;
      const cargoToml = findCargoWorkspace(cwd);
      if (cargoToml) {
        try {
          cp.execFileSync("cargo", ["run", "-q", "-p", "cellscript", "--", "--version"], { cwd: cargoToml, timeout: 15000 });
          return { command: "cargo", args: ["run", "-q", "-p", "cellscript", "--"], cwd: cargoToml };
        } catch {
          // Fall through.
        }
      }
    }
  }

  return null;
}

// ============================================================================
// CLI-backed report commands (kept for compile, metadata, constraints, production report)
// ============================================================================

function activeCellScriptDocument() {
  const editor = vscode.window.activeTextEditor;
  if (!editor || editor.document.languageId !== LANGUAGE_ID) {
    vscode.window.showWarningMessage("Open a .cell file first.");
    return null;
  }
  return editor.document;
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

async function runCompilerReport(document, output, status, kind) {
  const command = await resolveCompilerCommand(document);
  if (!command) {
    vscode.window.showErrorMessage("CellScript compiler not found. Configure cellscript.compilerPath or install cellc.");
    return;
  }

  const plan = buildReportPlan(document, kind, command.cwd);
  updateStatus(status, "running", plan.source);
  const result = await runCommand(command.command, [...command.args, ...plan.args], command.cwd, command.options);

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

function getScratchOutputPath(document, cwd, suffix) {
  const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
  const baseDir = workspaceFolder
    ? path.join(workspaceFolder.uri.fsPath, ".cellscript-vscode")
    : path.join(cwd || path.dirname(document.uri.fsPath) || os.tmpdir(), ".cellscript-vscode");

  fs.mkdirSync(baseDir, { recursive: true });
  const stem = path.basename(document.uri.fsPath, path.extname(document.uri.fsPath));
  return path.join(baseDir, `${stem}.${process.pid}.${Date.now()}.${suffix}`);
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

  status.text = "$(check) CellScript";
  status.tooltip = "CellScript Language Server";
  status.show();
}

module.exports = { activate, deactivate };
