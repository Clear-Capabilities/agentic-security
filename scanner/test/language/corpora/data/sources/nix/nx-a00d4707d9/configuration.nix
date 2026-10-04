{ config, lib, pkgs, ... }:
let
  appName = "wiki1";
  appPort = 8183;
in
{
  systemd.services.${appName}.description = "wiki service 1";
  networking.hostName = appName;
  security.doas.enable = true;
  security.doas.extraRules = [ { users = [ "wiki" ]; noPass = true; } ];
}
