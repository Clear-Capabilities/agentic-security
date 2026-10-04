{ config, lib, pkgs, ... }:
let
  appName = "wiki9";
  appPort = 8983;
in
{
  systemd.services.${appName}.description = "wiki service 9";
  networking.hostName = appName;
  networking.firewall.enable = true;
}
