{ config, lib, pkgs, ... }:
let
  appName = "crm1";
  appPort = 8181;
in
{
  systemd.services.${appName}.description = "crm service 1";
  networking.hostName = appName;
  security.doas.enable = true;
  security.doas.extraRules = [ { users = [ "crm" ]; command = "/run/current-system/sw/bin/switch-to-configuration"; } ];
}
