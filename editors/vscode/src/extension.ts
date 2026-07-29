// OrthoSec VS Code extension.
//
// Thin client over the real OrthoSec scanner: it shells out to the user's installed
// `orthosec` CLI with `--json`, then renders the deterministic findings as inline
// diagnostics (squiggles). No analysis is reimplemented here — the editor shows exactly
// what the scanner produces.
import * as vscode from "vscode";
import { execFile } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

interface Finding {
  file: string;
  line: number;
  severity: string;
  title: string;
  owasp_llm?: string;
  rule_id?: string;
  evidence?: string;
  remediation?: string;
  confidence_tier?: string;
}

const SEVERITY: Record<string, vscode.DiagnosticSeverity> = {
  CRITICAL: vscode.DiagnosticSeverity.Error,
  HIGH: vscode.DiagnosticSeverity.Error,
  MEDIUM: vscode.DiagnosticSeverity.Warning,
  LOW: vscode.DiagnosticSeverity.Information,
  INFO: vscode.DiagnosticSeverity.Hint,
};

const SCANNABLE = new Set([
  "python", "typescript", "typescriptreact", "javascript", "javascriptreact",
  "go", "java", "kotlin", "csharp", "ruby", "php", "rust",
]);

let diagnostics: vscode.DiagnosticCollection;
let output: vscode.OutputChannel;
let status: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection("orthosec");
  output = vscode.window.createOutputChannel("OrthoSec");
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 0);
  status.command = "orthosec.scanWorkspace";
  context.subscriptions.push(diagnostics, output, status);

  context.subscriptions.push(
    vscode.commands.registerCommand("orthosec.scanWorkspace", scanWorkspace),
    vscode.commands.registerCommand("orthosec.scanFile", scanActiveFile),
    vscode.commands.registerCommand("orthosec.clear", () => {
      diagnostics.clear();
      status.hide();
    }),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const cfg = vscode.workspace.getConfiguration("orthosec");
      if (cfg.get<boolean>("scanOnSave", true) && SCANNABLE.has(doc.languageId)) {
        void scanTarget(doc.uri.fsPath, path.dirname(doc.uri.fsPath));
      }
    })
  );
}

export function deactivate(): void {
  diagnostics?.dispose();
}

function scanActiveFile(): void {
  const ed = vscode.window.activeTextEditor;
  if (!ed) {
    void vscode.window.showInformationMessage("OrthoSec: no active file to scan.");
    return;
  }
  void scanTarget(ed.document.uri.fsPath, path.dirname(ed.document.uri.fsPath));
}

function scanWorkspace(): void {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    void vscode.window.showInformationMessage("OrthoSec: open a folder to scan a workspace.");
    return;
  }
  void scanTarget(folder.uri.fsPath, folder.uri.fsPath);
}

async function scanTarget(target: string, root: string): Promise<void> {
  const cfg = vscode.workspace.getConfiguration("orthosec");
  const binConfig = (cfg.get<string>("path", "orthosec") || "orthosec").trim();
  const profile = cfg.get<string>("profile", "appsec");
  const extra = cfg.get<string[]>("extraArgs", []) ?? [];

  // Allow `orthosec.path` to be a multi-word command like "python -m orthosec.cli".
  const parts = binConfig.split(/\s+/);
  const bin = parts[0];
  const jsonPath = path.join(os.tmpdir(), `orthosec-${Date.now()}-${Math.floor(Math.random() * 1e6)}.json`);
  const args = [
    ...parts.slice(1),
    "scan", target,
    "--json", jsonPath,
    "--no-report", "--no-exec",
    "--profile", profile,
    "--fail-on", "none", // never non-zero exit; we render findings, not gate
    ...extra,
  ];

  status.text = "$(sync~spin) OrthoSec scanning…";
  status.show();
  output.appendLine(`$ ${bin} ${args.join(" ")}`);

  execFile(bin, args, { cwd: root, maxBuffer: 64 * 1024 * 1024 }, (err, _stdout, stderr) => {
    let findings: Finding[] = [];
    try {
      const raw = fs.readFileSync(jsonPath, "utf8");
      const data = JSON.parse(raw);
      findings = Array.isArray(data) ? data : data.findings ?? [];
    } catch (readErr) {
      if (err) {
        status.text = "$(error) OrthoSec failed";
        output.appendLine(String(stderr || err));
        void vscode.window.showErrorMessage(
          `OrthoSec could not run '${bin}'. Set "orthosec.path" in Settings (e.g. an absolute path, or "python -m orthosec.cli").`
        );
        return;
      }
    } finally {
      fs.promises.unlink(jsonPath).catch(() => undefined);
    }
    render(findings, root, target);
  });
}

function render(findings: Finding[], root: string, target: string): void {
  // Clear only what we re-scanned: a single file, or (workspace scan) everything.
  const single = fs.existsSync(target) && fs.statSync(target).isFile();
  if (single) {
    diagnostics.delete(vscode.Uri.file(target));
  } else {
    diagnostics.clear();
  }

  const byFile = new Map<string, vscode.Diagnostic[]>();
  for (const f of findings) {
    const abs = path.isAbsolute(f.file) ? f.file : path.resolve(root, f.file);
    const line = Math.max(0, (f.line || 1) - 1);
    const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);
    const tier = f.confidence_tier && f.confidence_tier !== "deterministic" ? ` · ${f.confidence_tier}` : "";
    const owasp = f.owasp_llm ? `[${f.owasp_llm}] ` : "";
    const diag = new vscode.Diagnostic(
      range,
      `${owasp}${f.title}${tier}\n${f.remediation ?? ""}`.trim(),
      SEVERITY[(f.severity || "MEDIUM").toUpperCase()] ?? vscode.DiagnosticSeverity.Warning
    );
    diag.source = "OrthoSec";
    if (f.rule_id) {
      diag.code = f.rule_id;
    }
    const list = byFile.get(abs) ?? [];
    list.push(diag);
    byFile.set(abs, list);
  }
  for (const [abs, list] of byFile) {
    diagnostics.set(vscode.Uri.file(abs), list);
  }

  const total = findings.length;
  status.text = total ? `$(shield) OrthoSec: ${total}` : "$(shield) OrthoSec: clean";
  status.tooltip = "OrthoSec findings — click to re-scan the workspace";
  status.show();
  output.appendLine(`Rendered ${total} finding(s) across ${byFile.size} file(s).`);
}
