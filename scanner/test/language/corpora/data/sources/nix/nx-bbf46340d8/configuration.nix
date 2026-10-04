{ config, lib, pkgs, ... }:
let
  appName = "tracker0";
  appPort = 8085;
in
{
  systemd.services.${appName}.description = "tracker service 0";
  networking.hostName = appName;
  nix.settings.plugin-files = [ "/opt/tracker/plugin0.so" ];
}
