{ config, lib, pkgs, ... }:
let
  appName = "mailer1";
  appPort = 8184;
in
{
  systemd.services.${appName}.description = "mailer service 1";
  networking.hostName = appName;
  nix.settings.extra-sandbox-paths = [ "/home/mailer" ];
  nix.settings.sandbox = "relaxed";
}
