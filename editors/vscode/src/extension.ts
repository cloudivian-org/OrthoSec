// OrthoSec VS Code extension.
//
// Thin client over the real OrthoSec scanner: it shells out to the user's installed
// `orthosec` CLI with `--json`, renders the deterministic findings as inline diagnostics
// (squiggles), shows remediation on hover, and offers quick-fixes (apply a verified fix via
// `orthosec remediate --auto`, or suppress inline). No analysis is reimplemented here.
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
const SELECTOR: vscode.DocumentSelector = [...SCANNABLE].map((language) => ({ language, scheme: "file" }));

let diagnostics: vscode.DiagnosticCollection;
let output: vscode.OutputChannel;
let status: vscode.StatusBarItem;
const findingsByFile = new Map<string, Finding[]>();

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
      findingsByFile.clear();
      status.hide();
    }),
    vscode.commands.registerCommand("orthosec.applyFix", applyFix),
    vscode.commands.registerCommand("orthosec.suppress", suppress),
    vscode.languages.registerHoverProvider(SELECTOR, { provideHover }),
    vscode.languages.registerCodeActionsProvider(SELECTOR, new OrthoSecCodeActions(), {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
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

// --- scanning ---------------------------------------------------------------

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

function cliParts(): { bin: string; prefix: string[] } {
  const cfg = vscode.workspace.getConfiguration("orthosec");
  const parts = (cfg.get<string>("path", "orthosec") || "orthosec").trim().split(/\s+/);
  return { bin: parts[0], prefix: parts.slice(1) };
}

async function scanTarget(target: string, root: string): Promise<void> {
  const cfg = vscode.workspace.getConfiguration("orthosec");
  const { bin, prefix } = cliParts();
  const profile = cfg.get<string>("profile", "appsec");
  const extra = cfg.get<string[]>("extraArgs", []) ?? [];
  const jsonPath = path.join(os.tmpdir(), `orthosec-${Date.now()}-${Math.floor(Math.random() * 1e6)}.json`);
  const args = [...prefix, "scan", target, "--json", jsonPath, "--no-report", "--no-exec",
    "--profile", profile, "--fail-on", "none", ...extra];

  status.text = "$(sync~spin) OrthoSec scanning…";
  status.show();
  output.appendLine(`$ ${bin} ${args.join(" ")}`);

  execFile(bin, args, { cwd: root, maxBuffer: 64 * 1024 * 1024 }, (err, _stdout, stderr) => {
    let findings: Finding[] = [];
    let ok = false;
    try {
      const data = JSON.parse(fs.readFileSync(jsonPath, "utf8"));
      findings = Array.isArray(data) ? data : data.findings ?? [];
      ok = true;
    } catch {
      ok = false;
    } finally {
      fs.promises.unlink(jsonPath).catch(() => undefined);
    }
    if (!ok) {
      status.text = "$(error) OrthoSec failed";
      output.appendLine(String(stderr || err));
      void vscode.window.showErrorMessage(
        `OrthoSec could not run '${bin}'. Set "orthosec.path" in Settings (an absolute path, or "python -m orthosec.cli").`
      );
      return;
    }
    render(findings, root, target);
  });
}

function render(findings: Finding[], root: string, target: string): void {
  const single = fs.existsSync(target) && fs.statSync(target).isFile();
  if (single) {
    diagnostics.delete(vscode.Uri.file(target));
    findingsByFile.delete(target);
  } else {
    diagnostics.clear();
    findingsByFile.clear();
  }

  const diagByFile = new Map<string, vscode.Diagnostic[]>();
  for (const f of findings) {
    const abs = path.isAbsolute(f.file) ? f.file : path.resolve(root, f.file);
    const line = Math.max(0, (f.line || 1) - 1);
    const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);
    const tier = f.confidence_tier && f.confidence_tier !== "deterministic" ? ` · ${f.confidence_tier}` : "";
    const owasp = f.owasp_llm ? `[${f.owasp_llm}] ` : "";
    const diag = new vscode.Diagnostic(
      range,
      `${owasp}${f.title}${tier}`,
      SEVERITY[(f.severity || "MEDIUM").toUpperCase()] ?? vscode.DiagnosticSeverity.Warning
    );
    diag.source = "OrthoSec";
    if (f.rule_id) {
      diag.code = f.rule_id;
    }
    diagByFile.get(abs)?.push(diag) ?? diagByFile.set(abs, [diag]);
    findingsByFile.get(abs)?.push(f) ?? findingsByFile.set(abs, [f]);
  }
  for (const [abs, list] of diagByFile) {
    diagnostics.set(vscode.Uri.file(abs), list);
  }

  const total = findings.length;
  status.text = total ? `$(shield) OrthoSec: ${total}` : "$(shield) OrthoSec: clean";
  status.tooltip = "OrthoSec findings — click to re-scan the workspace";
  status.show();
  output.appendLine(`Rendered ${total} finding(s) across ${diagByFile.size} file(s).`);
}

// --- hover ------------------------------------------------------------------

function provideHover(doc: vscode.TextDocument, pos: vscode.Position): vscode.Hover | undefined {
  const here = (findingsByFile.get(doc.uri.fsPath) ?? []).filter((f) => (f.line || 1) - 1 === pos.line);
  if (!here.length) {
    return undefined;
  }
  const md = new vscode.MarkdownString();
  md.isTrusted = true;
  for (const f of here) {
    const owasp = f.owasp_llm ? ` · ${f.owasp_llm}` : "";
    md.appendMarkdown(`**🛡 OrthoSec: ${f.title}**${owasp}\n\n`);
    if (f.remediation) {
      md.appendMarkdown(`_Fix:_ ${f.remediation}\n\n`);
    }
    if (f.rule_id) {
      md.appendMarkdown(`\`${f.rule_id}\`  ·  severity ${f.severity}`);
      if (f.confidence_tier && f.confidence_tier !== "deterministic") {
        md.appendMarkdown(`  ·  ${f.confidence_tier}`);
      }
      md.appendMarkdown("\n\n");
    }
  }
  return new vscode.Hover(md);
}

// --- quick fixes ------------------------------------------------------------

class OrthoSecCodeActions implements vscode.CodeActionProvider {
  provideCodeActions(
    doc: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    ctx: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    for (const diag of ctx.diagnostics) {
      if (diag.source !== "OrthoSec") {
        continue;
      }
      const rule = typeof diag.code === "string" ? diag.code : String(diag.code ?? "");
      const line = diag.range.start.line;

      const fix = new vscode.CodeAction(`OrthoSec: apply fix (${rule || "remediate"})`, vscode.CodeActionKind.QuickFix);
      fix.diagnostics = [diag];
      fix.command = { command: "orthosec.applyFix", title: "Apply OrthoSec fix",
        arguments: [doc.uri, rule] };
      actions.push(fix);

      const sup = new vscode.CodeAction("OrthoSec: suppress this finding", vscode.CodeActionKind.QuickFix);
      sup.diagnostics = [diag];
      sup.command = { command: "orthosec.suppress", title: "Suppress",
        arguments: [doc.uri, line, rule, doc.languageId] };
      actions.push(sup);
    }
    return actions;
  }
}

async function applyFix(uri: vscode.Uri, rule: string): Promise<void> {
  const file = uri.fsPath;
  const { bin, prefix } = cliParts();
  const args = [...prefix, "remediate", file, "--auto"];
  if (rule) {
    args.push("--rule", rule);
  }
  output.appendLine(`$ ${bin} ${args.join(" ")}`);
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: "OrthoSec: applying fix…" },
    () =>
      new Promise<void>((resolve) => {
        execFile(bin, args, { cwd: path.dirname(file), maxBuffer: 32 * 1024 * 1024 }, (err, stdout, stderr) => {
          output.appendLine(String(stdout || ""));
          if (err) {
            output.appendLine(String(stderr || err));
            void vscode.window.showErrorMessage("OrthoSec: could not apply the fix (see Output → OrthoSec). Original backed up to *.orig.");
          } else {
            void vscode.window.showInformationMessage("OrthoSec applied a fix (original backed up to *.orig). Re-scanning…");
          }
          resolve();
        });
      })
  );
  void scanTarget(file, path.dirname(file)); // reflect the result
}

async function suppress(uri: vscode.Uri, line: number, rule: string, langId: string): Promise<void> {
  const token = langId === "python" || langId === "ruby" ? "#" : "//";
  const doc = await vscode.workspace.openTextDocument(uri);
  const text = doc.lineAt(line).text;
  const suffix = `  ${token} orthosec: ignore${rule ? " " + rule : ""}`;
  const edit = new vscode.WorkspaceEdit();
  edit.insert(uri, new vscode.Position(line, text.length), suffix);
  await vscode.workspace.applyEdit(edit);
  await doc.save();
}
