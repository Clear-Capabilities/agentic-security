{ config, lib, pkgs, ... }:
let
  appName = "crm0";
  appPort = 8081;
in
{
  systemd.services.${appName}.description = "crm service 0";
  networking.hostName = appName;
  services.nginx.enable = true;
  services.nginx.virtualHosts."crm.example.org".sslCertificateKey = "/run/credentials/crm0.key";
}
