{
  inputs = {
    sops-nix.url = "github:example/sops-nix";
    impermanence.url = "github:example/impermanence";
    home-manager.url = "github:example/home-manager";
  };
  outputs = { self, ... }: { };
}
