{ config, lib, pkgs, ... }:
let
  appName = "crm1";
  appPort = 8181;
in
{
  systemd.services.${appName}.description = "crm service 1";
  networking.hostName = appName;
  services.nginx.enable = true;
  services.nginx.virtualHosts."crm.example.org".forceSSL = false;
}
