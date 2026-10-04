{ config, lib, pkgs, ... }:
let
  appName = "crm1";
  appPort = 8181;
in
{
  systemd.services.${appName}.description = "crm service 1";
  networking.hostName = appName;
  nix.settings.trusted-users = lib.mkForce [ "root" ];
}
