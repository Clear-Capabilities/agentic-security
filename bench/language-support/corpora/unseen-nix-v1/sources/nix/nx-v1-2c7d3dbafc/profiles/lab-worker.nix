{ config, lib, pkgs, ... }:
{
  nix = {
    package = pkgs.nixVersions.stable;
    binaryCaches = [ "https://cache.nixos.org" "https://builds.lab.example" ];
    binaryCachePublicKeys = [
      "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
      "builds.lab.example-1:Qm9yZWFsIHRyYWRlcyBpbiB0aGUgc3VtbWVyIG1pc3Q="
    ];
    gc = {
      automatic = true;
      dates = "weekly";
      options = "--delete-older-than 14d";
    };
  };

  environment.systemPackages = with pkgs; [ nix-output-monitor nix-tree ];
}
