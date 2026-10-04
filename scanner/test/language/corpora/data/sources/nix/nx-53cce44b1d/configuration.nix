{ config, lib, pkgs, ... }:
let
  appName = "tracker0";
  appPort = 8085;
in
{
  systemd.services.${appName}.description = "tracker service 0";
  networking.hostName = appName;
  systemd.services."${appName}-env".serviceConfig.EnvironmentFile = "/run/secrets/tracker-0.env";
}
