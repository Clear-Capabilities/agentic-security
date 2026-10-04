{ config, lib, pkgs, ... }:
let
  appName = "crm7";
  appPort = 8781;
in
{
  systemd.services.${appName}.description = "crm service 7";
  networking.hostName = appName;
  services.nginx.enable = true;
  services.nginx.virtualHosts."crm.example.org".sslCertificateKey = ./crm7.key;
}
