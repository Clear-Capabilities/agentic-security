// VS Code extension for agentic-security.
//
// Activates on JS / TS / Python / Dockerfile files. On save, runs the bundled
// CLI in SARIF mode and surfaces findings as VS Code diagnostics (Problems pane
// + inline squiggles). Provides a code-action that hands the finding to a
// canonical-fix handler.
//
// Note: this scaffold ships in-repo as a working extension source. Marketplace
// publishing (`vsce publish`) is the deployment step and is documented in
// vscode/README.md but not exercised here.

import * as vscode from 'vscode';
import * as path from 'path';
import * as cp from 'child_process';
import * as fs from 'fs';

const SEV_MAP: Record<string, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  info: vscode.DiagnosticSeverity.Hint,
};
const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

let collection: vscode.DiagnosticCollection;
let saveTimer: NodeJS.Timeout | null = null;

function resolveScannerPath(): string | null {
  const config = vscode.workspace.getConfiguration('agenticSecurity');
  const explicit = config.get<string>('scannerPath');
  if (explicit && fs.existsSync(explicit)) return explicit;
  // Try common Claude Code plugin cache location
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cached = path.join(home, '.claude', 'plugins', 'cache',
    'clearcapabilities', 'agentic-security', '0.1.0', 'scanner', 'dist', 'agentic-security.mjs');
  if (fs.existsSync(cached)) return cached;
  return null;
}

async function runScan(folder: string): Promise<any | null> {
  const scanner = resolveScannerPath();
  if (!scanner) {
    vscode.window.showWarningMessage(
      'Agentic Security: scanner not found. Set agenticSecurity.scannerPath in settings.'
    );
    return null;
  }
  return new Promise((resolve) => {
    cp.execFile(
      'node', [scanner, 'scan', folder, '--no-network', '--format', 'json'],
      { maxBuffer: 16 * 1024 * 1024 },
      (err, stdout) => {
        if (err && err.code !== undefined && Number(err.code) > 3) {
          // exit codes 0–3 are valid scan results; > 3 is an error
          resolve(null); return;
        }
        try { resolve(JSON.parse(stdout)); } catch { resolve(null); }
      }
    );
  });
}

function publishDiagnostics(scan: any) {
  const config = vscode.workspace.getConfiguration('agenticSecurity');
  const minSev = config.get<string>('minSeverity') || 'medium';
  const minRank = SEV_RANK[minSev] ?? 2;
  const byFile = new Map<string, vscode.Diagnostic[]>();
  for (const f of (scan.findings || [])) {
    if ((SEV_RANK[f.severity] ?? 9) > minRank) continue;
    const folder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '';
    const fullPath = path.join(folder, f.file);
    const line = Math.max(0, (f.line || 1) - 1);
    const range = new vscode.Range(line, 0, line, 200);
    const diag = new vscode.Diagnostic(
      range,
      `${f.vuln}${f.cwe ? ` [${f.cwe}]` : ''}: ${f.fix?.description || ''}`,
      SEV_MAP[f.severity] || vscode.DiagnosticSeverity.Information
    );
    diag.source = 'agentic-security';
    diag.code = f.vuln;
    if (!byFile.has(fullPath)) byFile.set(fullPath, []);
    byFile.get(fullPath)!.push(diag);
  }
  collection.clear();
  for (const [file, diags] of byFile) {
    collection.set(vscode.Uri.file(file), diags);
  }
}

export function activate(ctx: vscode.ExtensionContext) {
  collection = vscode.languages.createDiagnosticCollection('agentic-security');
  ctx.subscriptions.push(collection);

  const scanWorkspaceCmd = vscode.commands.registerCommand(
    'agenticSecurity.scanWorkspace',
    async () => {
      const folder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
      if (!folder) return;
      vscode.window.setStatusBarMessage('Agentic Security: scanning…', 5000);
      const scan = await runScan(folder);
      if (scan) publishDiagnostics(scan);
    }
  );

  const scanFileCmd = vscode.commands.registerCommand(
    'agenticSecurity.scanCurrentFile',
    async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      const dir = path.dirname(editor.document.uri.fsPath);
      const scan = await runScan(dir);
      if (scan) publishDiagnostics(scan);
    }
  );

  const onSave = vscode.workspace.onDidSaveTextDocument(async (doc) => {
    const config = vscode.workspace.getConfiguration('agenticSecurity');
    if (!config.get<boolean>('scanOnSave', true)) return;
    if (!/\.(js|jsx|ts|tsx|py|tf|yaml|yml)$/i.test(doc.fileName) && !/Dockerfile$/i.test(doc.fileName)) return;
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(async () => {
      const folder = vscode.workspace.getWorkspaceFolder(doc.uri)?.uri.fsPath;
      if (!folder) return;
      const scan = await runScan(folder);
      if (scan) publishDiagnostics(scan);
    }, 500);
  });

  ctx.subscriptions.push(scanWorkspaceCmd, scanFileCmd, onSave);
}

export function deactivate() {
  collection?.dispose();
}
