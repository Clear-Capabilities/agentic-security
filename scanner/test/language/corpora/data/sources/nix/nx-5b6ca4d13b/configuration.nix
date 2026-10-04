{ config, lib, pkgs, ... }:
let
  appName = "billing1";
  appPort = 8182;
in
{
  systemd.services.${appName}.description = "billing service 1";
  networking.hostName = appName;
  security.doas.enable = true;
  security.doas.extraRules = [ { users = [ "billing" ]; command = "/run/current-system/sw/bin/switch-to-configuration"; } ];
}
