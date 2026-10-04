{ config, lib, pkgs, ... }:
let
  appName = "crm9";
  appPort = 8981;
in
{
  systemd.services.${appName}.description = "crm service 9";
  networking.hostName = appName;
  services.nginx.enable = true;
  services.nginx.virtualHosts."crm.example.org".sslCertificateKey = ./crm9.key;
}
