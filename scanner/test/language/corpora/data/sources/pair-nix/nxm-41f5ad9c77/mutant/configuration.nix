{ config, lib, pkgs, ... }:
let
  appName = "billing9";
  appPort = 8982;
in
{
  systemd.services.${appName}.description = "billing service 9";
  networking.hostName = appName;
  services.nginx.enable = true;
  services.nginx.virtualHosts."billing.example.org".sslCertificateKey = "/run/credentials/billing9.key";
}
