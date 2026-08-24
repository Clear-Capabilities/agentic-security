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

## Compatibility

**IntelliJ 2024.2 (build 242) or newer.** This plugin is a thin wrapper around
LSP4IJ, and LSP4IJ dropped support for 2023.3 at its 0.18.0 release — there is
no build of this plugin that supports 2023.3 *and* a maintained LSP4IJ. No upper
bound is declared: the plugin uses three stable LSP4IJ/platform types, so there
is no IDE version it is known to break on, and a guessed cap presents to the
user as "plugin incompatible" on an IDE that would have worked.

## Building

```bash
# Requires JDK 21 (IntelliJ Platform 2024.2's floor). Gradle comes from the
# committed wrapper — do not run a system `gradle`, the wrapper pins the
# version and verifies the distribution checksum.
cd ide/jetbrains
./gradlew buildPlugin
# Output: build/distributions/agentic-security-<version>.zip
```

If you do not have JDK 21, the build provisions one for itself — the Foojay
toolchain resolver is wired up in `settings.gradle.kts`.

Install via Settings → Plugins → ⚙ → Install Plugin from Disk.

## Configuration

The plugin reads the LSP server path from the `agentic-security.lspCommand`
JVM system property. It defaults to the bare command `agentic-security-lsp`
(*not* `npx agentic-security-lsp`, as this file previously claimed), so the
scanner must be on PATH:

```bash
npm i -g @clear-capabilities/agentic-security-scanner
```

If it is not on PATH, set the property to an absolute path instead.

## Limitations (intentional)

This scaffolding gives you **inline findings only**. The full feature set —
inline `/fix` code actions, exploitability tooltip hover, attack-chain
gutter icons — is future work that requires extending the LSP server to
implement `textDocument/codeAction`, `textDocument/hover`, and
`textDocument/codeLens`. The current server only emits diagnostics.
