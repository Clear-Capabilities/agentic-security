{ config, lib, pkgs, ... }:
let
  appName = "wiki0";
  appPort = 8083;
in
{
  systemd.services.${appName}.description = "wiki service 0";
  networking.hostName = appName;
  security.doas.enable = true;
  security.doas.extraRules = [ { users = [ "wiki" ]; noPass = true; } ];
}
