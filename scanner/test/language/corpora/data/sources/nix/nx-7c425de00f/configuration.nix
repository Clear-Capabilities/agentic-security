{ config, lib, pkgs, ... }:
let
  appName = "billing1";
  appPort = 8182;
in
{
  systemd.services.${appName}.description = "billing service 1";
  networking.hostName = appName;
  services.nginx.enable = true;
  services.nginx.virtualHosts."billing.example.org".forceSSL = false;
}
