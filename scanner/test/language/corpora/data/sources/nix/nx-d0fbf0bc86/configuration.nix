{ config, lib, pkgs, ... }:
let
  appName = "tracker0";
  appPort = 8085;
in
{
  systemd.services.${appName}.description = "tracker service 0";
  networking.hostName = appName;
  systemd.services."${appName}-job".script = "backup ${config.services.tracker.target}";
  networking.domain = lib.mkDefault "tracker.example.org";
}
