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
npm run package                       # → agentic-security-0.1.0.vsix
npx --yes @vscode/vsce@4.1.1 publish  # requires Marketplace publisher credentials (clearcapabilities)
```

`vsce` is run on demand at a pinned version instead of being a dev dependency: every published `picomatch` release (which it pulls in through `tinyglobby` and `secretlint`) carries a high-severity ReDoS advisory with no fixed version, and the release gate allows no vulnerable package in this tree. The packaging tool is only ever run by hand, never in CI.

The Marketplace token + publish step requires Clear Capabilities Inc. credentials and is not run from the open-source repo.

## Haskell and Nix

The plugin also serves Haskell, Cabal and Nix files (`*.hs`, `*.lhs`, `*.nix`, `*.cabal`, `cabal.project*`, `stack.yaml*`,
`package.yaml`, `flake.lock`). On save it analyses the file with its imported modules as context and reports findings for that
file only; a code action is offered only for a fix that passed the same gates as `agentic-security fix`. Support status per
capability: `docs/language-support.md`.
