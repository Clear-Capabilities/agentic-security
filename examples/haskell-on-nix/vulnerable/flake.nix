{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
  outputs = { self, nixpkgs }:
    let pkgs = nixpkgs.legacyPackages.x86_64-linux;
    in {
      packages.x86_64-linux.default = pkgs.haskellPackages.callCabal2nix "notes-api" ./. { };
      nixosModules.default = { config, pkgs, ... }: {
        systemd.services.notes-api = {
          wantedBy = [ "multi-user.target" ];
          serviceConfig.ExecStart = "${self.packages.x86_64-linux.default}/bin/notes-api";
          serviceConfig.User = "root";
        };
      };
    };
}
