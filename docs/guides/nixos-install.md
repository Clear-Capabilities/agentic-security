# Installing and running on NixOS

This page is about running the **scanner itself** on a NixOS host. Scanning NixOS configuration files is a separate
subject, covered in [Nix and NixOS](nix-nixos.md): it needs no Nix and no NixOS at all.

**Not verified here.** The checks that run the packaged scanner on a real NixOS host, and the flake, package and dev-shell
commands below, **could not be executed on the machine this release was built on** (no `nix`, no NixOS). They are written
from how the scanner is packaged and what it needs, not from a captured NixOS run. The support table marks `nixos-host` as
`blocked` for exactly this reason (see [Haskell and Nix support](../language-support.md)). Treat the commands as a starting
point, and report what differs.

## What the scanner needs

| Need | Detail |
|---|---|
| Node.js | version 24 or newer (`engines.node` in the package) |
| Runtime assets | all shipped inside the package: the bundled CLI (`dist/agentic-security.mjs`), the SHA-256-pinned Haskell and Nix grammar tables, the option catalogs. Nothing is downloaded at scan time. |
| Network | none for a default scan. Advisory feeds are snapshots you provide; evaluation is opt-in and offline. |
| Optional | `nix` (isolated evaluation), `ghc` (compile verification of a fix), `python3` (a better Python parse; a regex fallback is used without it) |
| Writable state | `.agentic-security/` inside the project being scanned (`--no-state` writes nothing) |

## Run it

The simplest way is a shell that provides Node 24 and runs the published package:

```bash
nix shell nixpkgs#nodejs_24 --command npx @clear-capabilities/agentic-security-scanner scan .
```

`nodejs_24` is the attribute name to use if your pinned nixpkgs carries it; check with `nix eval nixpkgs#nodejs_24.version`.
A development shell for working on a project that uses the scanner:

```nix
# flake.nix (untested example)
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { self, nixpkgs }:
    let pkgs = nixpkgs.legacyPackages.x86_64-linux;
    in { devShells.x86_64-linux.default = pkgs.mkShell { packages = [ pkgs.nodejs_24 ]; }; };
}
```

```bash
nix develop --command npx @clear-capabilities/agentic-security-scanner scan .
```

The repository root carries a `flake.nix` that packages the scanner: it copies the self-contained bundle and wraps it with Node 24 by
store path (no `npm install`, no native build, no download, no `/usr/bin/env`), and provides a dev shell and `agentic-security`,
`agentic-security-mcp` and `agentic-security-lsp` wrappers:

```bash
nix build .#default --offline
nix develop --command node --version
```

**This flake has not been built or run**: no `nix` was available where it was written, and `flake.lock` for it is not committed.
Run `nix flake lock` to pin nixpkgs by revision before relying on it. `scanner/test/nix/nixos-host-runtime.test.js`
(`npm run test:nixos-host`) is the suite that would confirm it on a NixOS host; here its Nix-dependent criteria fail, and only the
MCP and LSP framing checks pass.

## Offline use

Everything a default scan reads is local. To scan with no network at all, install the package once while online
(`npm install --save-dev @clear-capabilities/agentic-security-scanner`) and run the installed binary. Add `--no-network` to
skip the OSV and registry lookups of other ecosystems, and provide the advisory snapshots for Hackage and Nix yourself
(`AGENTIC_SECURITY_HACKAGE_ADVISORIES`, `AGENTIC_SECURITY_NIX_ADVISORIES`).

## Architecture matrix

| Platform | Scanner | Optional evaluation sandbox | Status |
|---|---|---|---|
| x86_64-linux (NixOS or any Linux) | Node 24 | Linux namespaces | the hosted CI jobs exercise Linux; the NixOS-specific job is informational |
| aarch64-linux | Node 24 | Linux namespaces | not exercised in CI |
| aarch64-darwin | Node 24 | `sandbox-exec` | the development host of this release (no Nix installed) |
| x86_64-darwin | Node 24 | `sandbox-exec` | not exercised |

The recorded tool versions are in `docs/language-toolchain.json`; hosted CI pins Node 24, GHC 9.4.8, cabal 3.10.2.1 and
Nix 2.24.10.

## What the NixOS-specific checks are

The CI job `nixos-runtime` installs a pinned Nix on a hosted Linux runner and runs the isolated-evaluation harness against a
real evaluator. It is **informational**, because the installer and any channel fetch are network events. A full NixOS host or
VM check (the complete scanner on a NixOS machine) is requirement NIX-012 and was not run for this release.
