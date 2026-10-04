{ config, lib, pkgs, ... }:
let
  appName = "mailer0";
  appPort = 8084;
in
{
  systemd.services.${appName}.description = "mailer service 0";
  networking.hostName = appName;
  nix.settings.sandbox = true;
  nix.settings.extra-sandbox-paths = [ "/etc/mailer-ca" ];
}
