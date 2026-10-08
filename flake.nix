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
          # The NixOS test driver waits at most 10 x 30 s for a guest's shell. A guest emulated in software (an aarch64 guest on an
          # x86_64 host) boots slower than that, so the wait is stretched; a guest on KVM is unaffected, it is simply ready sooner.
          hostPkgs = import nixpkgs {
            inherit system;
            overlays = [ (final: prev: {
              # makeOverridable keeps `.override` (which the test framework calls) on the patched package
              nixos-test-driver = final.lib.makeOverridable (args: (prev.nixos-test-driver.override args).overridePythonAttrs (old: {
                postPatch = (old.postPatch or "") + "\n  f=$(find . -path '*test_driver/machine/__init__.py' | head -1)\n  sed -i 's/for _ in range(10):/for _ in range(180):/' \"$f\"\n  grep -q 'range(180)' \"$f\" || { echo 'driver patch did not apply'; exit 1; }\n";
              })) { };
            }) ];
          };
          pkgs = hostPkgs;
          repo = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./flake.nix ./flake.lock ./examples
              ./scanner/dist ./scanner/bin ./scanner/src ./scanner/package.json
              ./scanner/test/nix/nixos-host-runtime.test.js
            ];
          };
          # `guest` is the guest's architecture; when it differs from the host the guest is emulated (qemu TCG), which the criterion
          # NIX-012.AC03 calls "actual tested emulation".
          #
          # An EMULATED guest differs from a native or KVM one only in speed, and every fixed budget in this test is a race against that speed.
          # So the emulated variant, and only it, gets: a bound on each guest command (`succeed` has no timeout by default, so a wedged
          # guest would otherwise hold the runner until the job deadline, with no message saying which command it was), a wait for the Nix
          # daemon socket the suite's `nix build --offline` depends on, two vCPUs and more memory (one emulated core is what makes a nixpkgs
          # evaluation slow enough to brush the suite's own 15 minute build budget), a longer bound on the suite itself, and a scale factor
          # the suite applies to ITS own timeouts (scanner/test/nix/nixos-host-runtime.test.js). Every one of these is bounded. The native
          # variant runs the same commands with the same limits as before.
          mkHostTest = guest:
            let
              emulated = guest != system;
              scale = 6;
              succeedTimeout = if emulated then ", timeout=3600" else "";
              daemonWait = if emulated then ''machine.wait_for_unit("nix-daemon.socket", timeout=3600)'' else "";
              scalePrefix = if emulated then "AGENTIC_SECURITY_TEST_TIMEOUT_SCALE=${toString scale} " else "";
              suiteTimeout = if emulated then 10800 else 5400;
            in hostPkgs.testers.runNixOSTest {
            name = "agentic-security-nixos-host-${guest}";
            node.pkgs = nixpkgs.lib.mkForce nixpkgs.legacyPackages.${guest};
            nodes.machine = { pkgs, ... }: {
              environment.systemPackages = [ self.packages.${guest}.default pkgs.nodejs_24 pkgs.git pkgs.which ];
              nix.settings.experimental-features = [ "nix-command" "flakes" ];
              nix.settings.flake-registry = "";
              virtualisation.memorySize = if emulated then 4096 else 3072;
              virtualisation.cores = nixpkgs.lib.mkIf emulated 2;
              virtualisation.diskSize = 4096;
              virtualisation.additionalPaths = [ nixpkgs.outPath self.packages.${guest}.default self.devShells.${guest}.default pkgs.nodejs_24 ];
            };
            testScript = ''
              machine.wait_for_unit("multi-user.target", timeout=3600)
              ${daemonWait}
              machine.succeed("test -f /etc/NIXOS"${succeedTimeout})
              # the leg's name is a claim about the guest; check it (an "aarch64" leg that was really x86 would be a false label)
              machine.succeed("test \"$(uname -m)\" = \"${if guest == "aarch64-linux" then "aarch64" else "x86_64"}\""${succeedTimeout})
              machine.succeed("agentic-security version"${succeedTimeout})
              machine.succeed("cp -r ${repo} /tmp/repo && chmod -R u+w /tmp/repo"${succeedTimeout})
              machine.succeed("cd /tmp/repo && git init -q && git add -A && git -c user.email=t@t -c user.name=t commit -qm t"${succeedTimeout})
              # The suite runs INSIDE the guest with a TAP reporter; its output is copied out so a verifier can read per-test results.
              status, _ = machine.execute("cd /tmp/repo/scanner && ${scalePrefix}node --test --test-reporter=tap test/nix/nixos-host-runtime.test.js > /tmp/nixos-host-${guest}.tap 2>&1", timeout=${toString suiteTimeout})
              machine.copy_from_machine("/tmp/nixos-host-${guest}.tap")
              assert status == 0, "the NIX-012 suite failed inside the guest (see nixos-host-${guest}.tap)"
            '';
          };
        in {
          nixos-host = mkHostTest system;
        } // (if system == "x86_64-linux" then { nixos-host-aarch64-emulated = mkHostTest "aarch64-linux"; } else { }));

      # Noninteractive by design: use `nix develop --command <cmd>`; nothing here prompts or activates a configuration.
      devShells = forAll (pkgs: {
        default = pkgs.mkShell { packages = [ pkgs.nodejs_24 ]; };
      });
    };
}
