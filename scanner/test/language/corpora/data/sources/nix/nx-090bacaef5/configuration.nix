{ config, lib, pkgs, ... }:
let
  appName = "billing0";
  appPort = 8082;
in
{
  systemd.services.${appName}.description = "billing service 0";
  networking.hostName = appName;
  nix.settings.require-sigs = false;
  users.motd = lib.mkIf (config.networking.hostName != "") "billing";
}
