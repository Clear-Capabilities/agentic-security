{ config, lib, pkgs, ... }:
let
  appName = "billing0";
  appPort = 8082;
in
{
  systemd.services.${appName}.description = "billing service 0";
  networking.hostName = appName;
  security.doas.enable = true;
  security.doas.extraRules = [ { users = [ "billing" ]; command = "/run/current-system/sw/bin/switch-to-configuration"; } ];
}
