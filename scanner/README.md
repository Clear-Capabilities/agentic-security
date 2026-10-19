# @clear-capabilities/agentic-security-scanner

The scan engine behind [Agentic Security](https://github.com/Clear-Capabilities/agentic-security), an autonomous security assurance platform (a Claude Code plugin and CLI) that pairs deterministic analysis with security agents and never treats an incomplete scan as a clean one. See [how it works](https://github.com/Clear-Capabilities/agentic-security/blob/main/docs/how-it-works/assurance-lifecycle.md) and [trust and limitations](https://github.com/Clear-Capabilities/agentic-security/blob/main/docs/trust/trust-and-limitations.md). The engine provides: SAST, SCA with function-level reachability and CISA KEV, secrets, IaC, prompt-injection and MCP/agent-tool audit, auth/authZ analysis, SBOM/AI-BOM, and compliance evidence.

```bash
npx @clear-capabilities/agentic-security-scanner scan .
```

## Languages

JavaScript/TypeScript, Python, Java, Kotlin, Go, Ruby, PHP, C#, Rust, **Haskell** and **Nix/NixOS**.

- **Haskell** (`.hs`, `.lhs`, `.hs-boot`, `.hsc`, Cabal and Stack): SAST, taint, web routes and auth, privacy lineage, dependency inventory and SBOM, verified fixes.
- **Nix and NixOS** (`.nix`, flakes, NixOS and Home Manager modules): effective-configuration analysis, host hardening, secrets and build-trust checks, dependency inventory and SBOM, verified fixes.

Both are scanned with no compiler, no `nix` binary and no network. Each capability is reported **supported** only from measured evidence of its own kind, and **blocked** when it needs a tool the measurement did not have; the corpus behind the figures is synthetic, so they describe robustness over those shapes, not arbitrary real-world code. Read the [Haskell guide](https://github.com/Clear-Capabilities/agentic-security/blob/main/docs/guides/haskell.md), the [Nix and NixOS guide](https://github.com/Clear-Capabilities/agentic-security/blob/main/docs/guides/nix-nixos.md), [installing on NixOS](https://github.com/Clear-Capabilities/agentic-security/blob/main/docs/guides/nixos-install.md) and the [support record](https://github.com/Clear-Capabilities/agentic-security/blob/main/docs/language-support.md).

The repository's Nix flake packages the scanner with `agentic-security`, `agentic-security-mcp` and `agentic-security-lsp` binaries, and ships NixOS VM tests (`checks.<system>.nixos-host`).

## More

Full documentation, the plugin, and the IDE integrations are in the [repository README](https://github.com/Clear-Capabilities/agentic-security#readme). License: PolyForm Internal Use 1.0.0.
