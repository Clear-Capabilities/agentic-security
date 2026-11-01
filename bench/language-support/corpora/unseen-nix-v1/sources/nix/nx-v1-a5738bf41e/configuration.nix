{ config, pkgs, ... }:
{
  imports = [ ./hardware-configuration.nix ];

  networking.hostName = "dev-bench";

  nix.settings = {
    experimental-features = [ "nix-command" "flakes" ];
    substituters = [ "https://cache.nixos.org" "https://cache.internal.example" ];
    trusted-public-keys = [
      "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
      "cache.internal.example-1:d2luZCBvdmVyIHRoZSBoaWxscyBhdCBkYXduIGZhbGw="
    ];
  };

  environment.systemPackages = with pkgs; [ git direnv ];

  system.stateVersion = "24.05";
}
