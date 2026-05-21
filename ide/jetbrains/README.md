# agentic-security — JetBrains plugin

A thin JetBrains plugin (IntelliJ IDEA, PyCharm, GoLand, WebStorm, RubyMine,
PhpStorm) that surfaces agentic-security findings inline by attaching to
the bundled LSP server.

## Architecture

The plugin uses [LSP4IJ](https://github.com/redhat-developer/lsp4ij), the
generic LSP client for JetBrains IDEs, to spawn `agentic-security-lsp` on
project open and route `textDocument/publishDiagnostics` to the IDE's
problem markers. Findings appear as squiggles + Problems-tool-window entries.

No JetBrains-platform plumbing in this plugin — all the security logic lives
in the scanner. The plugin is < 100 LoC of Kotlin + a plugin.xml manifest.

## Building

```bash
# Requires JDK 17 + Gradle.
cd ide/jetbrains
./gradlew buildPlugin
# Output: build/distributions/agentic-security-jetbrains-*.zip
```

Install via Settings → Plugins → ⚙ → Install Plugin from Disk.

## Configuration

The plugin reads the LSP server path from the `agentic-security.lspCommand`
setting (defaults to `npx agentic-security-lsp`). If the scanner isn't on
PATH, set this to an absolute path.

## Limitations (intentional)

This scaffolding gives you **inline findings only**. The full feature set —
inline `/fix` code actions, exploitability tooltip hover, attack-chain
gutter icons — is future work that requires extending the LSP server to
implement `textDocument/codeAction`, `textDocument/hover`, and
`textDocument/codeLens`. The current server only emits diagnostics.
