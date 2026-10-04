{ config, lib, pkgs, ... }:
let
  appName = "mailer0";
  appPort = 8084;
in
{
  systemd.services.${appName}.description = "mailer service 0";
  networking.hostName = appName;
  nix.settings.require-sigs = false;
  users.motd = lib.mkIf (config.networking.hostName != "") "mailer";
}
