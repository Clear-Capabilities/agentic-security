{
  inputs = {
    nixpkgs.url = "github:example/nixpkgs";
    flake-utils.url = "github:example/flake-utils";
    disko.url = "github:example/disko";
  };
  outputs = { self, ... }: { };
}
