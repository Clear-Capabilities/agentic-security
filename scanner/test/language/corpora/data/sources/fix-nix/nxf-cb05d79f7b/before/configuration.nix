{ config, lib, pkgs, ... }:
let
  appName = "mailer7";
  appPort = 8784;
in
{
  systemd.services.${appName}.description = "mailer service 7";
  networking.hostName = appName;
  nix.settings.sandbox = false;
}
