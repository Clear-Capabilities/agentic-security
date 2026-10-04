# Packaging for the scanner on Nix and NixOS (NIX-012).
#
# NOT BUILT OR RUN where this file was written: no nix binary was available. It is written from how the package is laid out and what
# it needs, and the checks in scanner/test/nix/nixos-host-runtime.test.js are what would confirm it on a Nix host.
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
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in {
      packages = forAll (pkgs: rec {
        agentic-security = pkgs.stdenvNoCC.mkDerivation {
          pname = "agentic-security-scanner";
          version = (builtins.fromJSON (builtins.readFile ./scanner/package.json)).version;
          src = ./scanner;
          nativeBuildInputs = [ pkgs.makeWrapper ];
          dontBuild = true;
          installPhase = ''
            runHook preInstall
            mkdir -p $out/lib/agentic-security $out/bin
            cp -r dist bin src package.json $out/lib/agentic-security/
            [ -d vendor ] && cp -r vendor $out/lib/agentic-security/ || true
            makeWrapper ${pkgs.nodejs_24}/bin/node $out/bin/agentic-security \
              --add-flags $out/lib/agentic-security/dist/agentic-security.mjs
            makeWrapper ${pkgs.nodejs_24}/bin/node $out/bin/agentic-security-mcp \
              --add-flags $out/lib/agentic-security/bin/agentic-security-mcp.js
            makeWrapper ${pkgs.nodejs_24}/bin/node $out/bin/agentic-security-lsp \
              --add-flags $out/lib/agentic-security/bin/agentic-security-lsp.js
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
        default = { type = "app"; program = "${self.packages.${pkgs.system}.default}/bin/agentic-security"; };
      });

      # Noninteractive by design: use `nix develop --command <cmd>`; nothing here prompts or activates a configuration.
      devShells = forAll (pkgs: {
        default = pkgs.mkShell { packages = [ pkgs.nodejs_24 ]; };
      });
    };
}
