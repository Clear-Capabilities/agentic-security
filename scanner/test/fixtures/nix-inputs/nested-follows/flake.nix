{
  description = "nested follows and a nonflake input";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
    home-manager = {
      url = "github:nix-community/home-manager/release-24.05";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.utils.follows = "flake-utils";
    };
    tools.url = "github:example/tools";
    legacy-src = {
      url = "github:example/legacy-src";
      flake = false;
    };
  };
  outputs = { self, nixpkgs, home-manager, ... }: {
    packages.x86_64-linux.default = nixpkgs.legacyPackages.x86_64-linux.hello;
    nixosConfigurations.host = nixpkgs.lib.nixosSystem {
      modules = [ home-manager.nixosModules.home-manager ];
    };
    devShells.x86_64-linux.default = nixpkgs.legacyPackages.x86_64-linux.mkShell { };
  };
}
