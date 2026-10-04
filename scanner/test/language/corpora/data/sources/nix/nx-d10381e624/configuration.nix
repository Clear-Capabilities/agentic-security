{ config, lib, pkgs, ... }:
let
  appName = "wiki0";
  appPort = 8083;
in
{
  systemd.services.${appName}.description = "wiki service 0";
  networking.hostName = appName;
  networking.firewall.enable = false;
  boot.kernelModules = lib.mkIf config.virtualisation.docker.enable [ "br_netfilter" ];
}
