{
  inputs = {
    impermanence.url = "github:example/impermanence";
    home-manager.url = "github:example/home-manager";
    home-manager.inputs.impermanence.follows = "impermanence";
    sops-nix.url = "github:example/sops-nix";
  };
  outputs = { self, ... }: { };
}
