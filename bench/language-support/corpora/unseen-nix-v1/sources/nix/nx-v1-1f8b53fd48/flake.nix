{
  description = "Pipeline runner";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/3f0c6d1a9b2e8f7c4d5a6b7c8d9e0f1a2b3c4d5e";

  outputs = { self, nixpkgs }: {
    nixosConfigurations.ci-worker = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ({ pkgs, lib, ... }: {
          networking.hostName = "ci-worker";
          nix.settings = {
            experimental-features = [ "nix-command" "flakes" ];
            extra-plugin-files = [ ];
          };
          services.buildbot-worker.enable = true;
        })
      ];
    };
  };
}
