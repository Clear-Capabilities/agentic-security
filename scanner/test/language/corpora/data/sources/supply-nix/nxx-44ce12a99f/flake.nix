{
  inputs = {
    disko.url = "github:example/disko";
    nixpkgs.url = "github:example/nixpkgs";
    flake-utils.url = "github:example/flake-utils";
  };
  outputs = { self, ... }: { };
}
