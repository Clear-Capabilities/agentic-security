{ config, lib, pkgs, ... }:
let
  appName = "wiki0";
  appPort = 8083;
in
{
  systemd.services.${appName}.description = "wiki service 0";
  networking.hostName = appName;
  nix.settings.trusted-users = [ "root" "@wheel" "wiki" ];
  time.timeZone = lib.mkOverride 900 "UTC";
}
