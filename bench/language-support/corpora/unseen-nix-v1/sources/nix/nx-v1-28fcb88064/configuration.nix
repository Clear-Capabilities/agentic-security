{ config, pkgs, ... }:
{
  imports = [ ./hardware-configuration.nix ];

  networking.hostName = "shared-desk";

  users.users.mara = { isNormalUser = true; extraGroups = [ "wheel" ]; };
  users.users.tomas = { isNormalUser = true; extraGroups = [ "wheel" ]; };

  nix.settings = {
    experimental-features = [ "nix-command" "flakes" ];
    auto-optimise-store = true;
    trusted-users = [ "root" "@wheel" ];
  };

  system.stateVersion = "24.05";
}
