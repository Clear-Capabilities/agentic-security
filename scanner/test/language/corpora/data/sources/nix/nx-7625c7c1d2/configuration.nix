{ config, lib, pkgs, ... }:
let
  appName = "crm0";
  appPort = 8081;
in
{
  systemd.services.${appName}.description = "crm service 0";
  networking.hostName = appName;
  services.crm.password = "example-placeholder-crm-0";
  boot.kernelModules = lib.mkIf config.virtualisation.docker.enable [ "br_netfilter" ];
}
