{ config, lib, pkgs, ... }:
let
  appName = "crm0";
  appPort = 8081;
in
{
  systemd.services.${appName}.description = "crm service 0";
  networking.hostName = appName;
  nix.settings.trusted-users = [ "root" "@wheel" "crm" ];
  time.timeZone = lib.mkOverride 900 "UTC";
}
