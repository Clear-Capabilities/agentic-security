{ config, lib, pkgs, ... }:
{
  imports = [ ../modules/base.nix ];
  networking.hostName = "office-desk";

  users.users.priya = {
    isNormalUser = true;
    extraGroups = [ "wheel" "networkmanager" ];
  };

  security.sudo = {
    enable = true;
    wheelNeedsPassword = false;
    execWheelOnly = true;
  };

  services.printing.enable = true;
}
