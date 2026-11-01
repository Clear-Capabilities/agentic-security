{ config, lib, pkgs, ... }:
{
  imports = [ ../modules/base.nix ];
  networking.hostName = "build-desk";

  users.users.mara = { isNormalUser = true; extraGroups = [ "wheel" ]; };
  users.users.tomas = { isNormalUser = true; extraGroups = [ "wheel" ]; };

  nix.settings = {
    experimental-features = [ "nix-command" "flakes" ];
    auto-optimise-store = true;
    trusted-users = [ "root" ];
    allowed-users = [ "@wheel" ];
  };
}
