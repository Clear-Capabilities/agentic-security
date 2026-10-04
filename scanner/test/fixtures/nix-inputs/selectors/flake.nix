{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
  outputs = { self, nixpkgs }: {
    nixosConfigurations.host = nixpkgs.lib.nixosSystem {
      modules = [ ./configuration.nix ];
    };
  };
}
