{ config, lib, pkgs, ... }:
let
  appName = "mailer0";
  appPort = 8084;
in
{
  systemd.services.${appName}.description = "mailer service 0";
  networking.hostName = appName;
  security.doas.enable = true;
  security.doas.extraRules = [ { users = [ "mailer" ]; noPass = true; } ];
}
