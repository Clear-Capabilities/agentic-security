# Agentic Security — VS Code extension

Surfaces SAST / SCA / Secret findings as VS Code diagnostics (Problems pane + inline squiggles). Powered by the `agentic-security` CLI.

## Status

**Scaffold + working source.** The extension activates, runs the scanner on save, and produces diagnostics. Not yet published to the VS Code Marketplace — that's the `vsce publish` step (see Deployment below).

## Install (developer mode)

```bash
cd vscode
npm install
npm run build
# In VS Code: Cmd-Shift-P → "Developer: Install Extension from Location" → pick this folder
```

## Configuration

| Setting | Default | Description |
|---|---|---|
| `agenticSecurity.scannerPath` | (auto-discovered) | Path to `agentic-security.mjs`. Leave empty to use the Claude Code plugin cache copy. |
| `agenticSecurity.scanOnSave` | `true` | Re-scan on save (debounced 500ms). |
| `agenticSecurity.minSeverity` | `medium` | Minimum severity to surface as a diagnostic. |

## Commands

- **Agentic Security: Scan workspace** — full scan, publish diagnostics to all files
- **Agentic Security: Scan current file** — scan the parent directory of the active file

## Deployment (out of scope for this repo)

```bash
npm run package        # → agentic-security-0.1.0.vsix
vsce publish           # requires Marketplace publisher credentials (clearcapabilities)
```

The Marketplace token + publish step requires Clear Capabilities Inc. credentials and is not run from the open-source repo.
