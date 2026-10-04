{ config, lib, pkgs, ... }:
let
  appName = "tracker0";
  appPort = 8085;
in
{
  systemd.services.${appName}.description = "tracker service 0";
  networking.hostName = appName;
  services.tracker.password = "example-placeholder-tracker-0";
  boot.kernelModules = lib.mkIf config.virtualisation.docker.enable [ "br_netfilter" ];
}
