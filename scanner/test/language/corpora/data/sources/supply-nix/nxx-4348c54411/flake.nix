{
  inputs = {
    home-manager.url = "github:example/home-manager";
    sops-nix.url = "github:example/sops-nix";
    impermanence.url = "github:example/impermanence";
  };
  outputs = { self, ... }: { };
}
