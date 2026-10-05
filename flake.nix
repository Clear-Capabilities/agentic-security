# Packaging for the scanner on Nix and NixOS (NIX-012).
#
# BUILT AND CHECKED on aarch64-linux only (Nix 2.35.2 in a nixos/nix container: `nix flake lock`, `nix build .#agentic-security`,
# `nix flake check --no-build`, and the built wrapper answered --version and scanned a directory). x86_64-linux and aarch64-darwin
# are declared but were NOT built (x86_64-darwin is dropped: current nixpkgs no longer supports it). flake.lock pins nixpkgs by revision. Nothing here has run on a NixOS host:
# scanner/test/nix/nixos-host-runtime.test.js is what confirms that, and it requires /etc/NIXOS.
#
# The scanner's CLI is a self-contained bundle (dist/agentic-security.mjs plus its chunks), so the package copies files and wraps them
# with Node 24: there is no npm install, no native build and no download at build or run time, and therefore no npm dependency hash to
# keep in step. The wrapper names Node by its store path, so nothing assumes /usr/bin/env or an FHS loader.
{
  description = "agentic-security scanner";

  # Pin nixpkgs by revision with `nix flake lock` (committed as flake.lock) so the build is reproducible.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      # The package source is exactly what the package installs, so the same files in another checkout (the NixOS VM test's copy) hash to
      # the same store path and the same derivation, and an offline `nix build` there finds the output already built.
      scannerSrc = pkgs: pkgs.lib.fileset.toSource {
        root = ./scanner;
        fileset = pkgs.lib.fileset.unions [ ./scanner/dist ./scanner/bin ./scanner/src ./scanner/package.json ];
      };
    in {
      packages = forAll (pkgs: rec {
        agentic-security = pkgs.stdenvNoCC.mkDerivation {
          pname = "agentic-security-scanner";
          version = (builtins.fromJSON (builtins.readFile ./scanner/package.json)).version;
          src = scannerSrc pkgs;
          nativeBuildInputs = [ pkgs.makeWrapper ];
          dontBuild = true;
          installPhase = ''
            runHook preInstall
            mkdir -p $out/lib/agentic-security $out/bin
            cp -r dist bin src package.json $out/lib/agentic-security/
            [ -d vendor ] && cp -r vendor $out/lib/agentic-security/ || true
            makeWrapper ${pkgs.nodejs_24}/bin/node $out/bin/agentic-security \
              --add-flags $out/lib/agentic-security/dist/agentic-security.mjs
            # MCP and LSP run from the bundle, not bin/*.js: those import src/, which needs the npm dependencies this package does not ship.
            makeWrapper ${pkgs.nodejs_24}/bin/node $out/bin/agentic-security-mcp \
              --add-flags "$out/lib/agentic-security/dist/agentic-security.mjs mcp"
            makeWrapper ${pkgs.nodejs_24}/bin/node $out/bin/agentic-security-lsp \
              --add-flags "$out/lib/agentic-security/dist/agentic-security.mjs lsp"
            runHook postInstall
          '';
          meta = {
            description = "Static application security scanner (Haskell, Nix and more)";
            mainProgram = "agentic-security";
            platforms = systems;
          };
        };
        default = agentic-security;
      });

      apps = forAll (pkgs: {
        default = { type = "app"; meta.description = "Run the scanner"; program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.default}/bin/agentic-security"; };
      });

      # A controlled NixOS VM test (NIX-012): boots a real NixOS guest (so /etc/NIXOS exists), installs the package, and runs the repo's own
      # nixos-host-runtime suite INSIDE the guest. The VM is a throwaway QEMU machine; nothing here ever runs `nixos-rebuild` or activates
      # a configuration on a host. The guest has no network; nixpkgs is placed in its store so the suite's offline `nix build` can resolve
      # the locked input. Linux only (a NixOS guest), x86_64 with KVM on hosted runners, aarch64 where an arm runner or emulation exists.
      checks = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          repo = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./flake.nix ./flake.lock ./examples
              ./scanner/dist ./scanner/bin ./scanner/src ./scanner/package.json
              ./scanner/test/nix/nixos-host-runtime.test.js
            ];
          };
        in {
          nixos-host = pkgs.testers.runNixOSTest {
            name = "agentic-security-nixos-host";
            nodes.machine = { pkgs, ... }: {
              environment.systemPackages = [ self.packages.${system}.default pkgs.nodejs_24 pkgs.git pkgs.which ];
              nix.settings.experimental-features = [ "nix-command" "flakes" ];
              nix.settings.flake-registry = "";
              virtualisation.memorySize = 3072;
              virtualisation.diskSize = 4096;
              virtualisation.additionalPaths = [ nixpkgs.outPath self.packages.${system}.default self.devShells.${system}.default pkgs.nodejs_24 ];
            };
            testScript = ''
              machine.wait_for_unit("multi-user.target", timeout=3600)
              machine.succeed("test -f /etc/NIXOS")
              machine.succeed("agentic-security version")
              machine.succeed("cp -r ${repo} /tmp/repo && chmod -R u+w /tmp/repo")
              machine.succeed("cd /tmp/repo && git init -q && git add -A && git -c user.email=t@t -c user.name=t commit -qm t")
              machine.succeed("cd /tmp/repo/scanner && node --test test/nix/nixos-host-runtime.test.js", timeout=3600)
            '';
          };
        });

      # Noninteractive by design: use `nix develop --command <cmd>`; nothing here prompts or activates a configuration.
      devShells = forAll (pkgs: {
        default = pkgs.mkShell { packages = [ pkgs.nodejs_24 ]; };
      });
    };
}
