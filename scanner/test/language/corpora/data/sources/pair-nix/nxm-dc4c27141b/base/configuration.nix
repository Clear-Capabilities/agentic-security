{ config, lib, pkgs, ... }:
let
  appName = "crm9";
  appPort = 8981;
in
{
  systemd.services.${appName}.description = "crm service 9";
  networking.hostName = appName;
  nix.settings.trusted-users = lib.mkForce [ "root" ];
}
