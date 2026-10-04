{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
  outputs = { self, nixpkgs }: { packages.x86_64-linux.default = nixpkgs.legacyPackages.x86_64-linux.hello; };
}
