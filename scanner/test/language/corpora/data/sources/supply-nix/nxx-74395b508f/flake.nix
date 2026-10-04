{
  inputs = {
    flake-utils.url = "github:example/flake-utils";
    disko.url = "github:example/disko";
    disko.inputs.flake-utils.follows = "flake-utils";
    nixpkgs.url = "github:example/nixpkgs";
  };
  outputs = { self, ... }: { };
}
