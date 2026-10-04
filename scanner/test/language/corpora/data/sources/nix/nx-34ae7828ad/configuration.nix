{ config, lib, pkgs, ... }:
let
  appName = "tracker1";
  appPort = 8185;
in
{
  systemd.services.${appName}.description = "tracker service 1";
  networking.hostName = appName;
  nix.settings.plugin-files = [ ];
}
