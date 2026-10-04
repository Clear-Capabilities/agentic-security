{ config, lib, pkgs, ... }:
let
  appName = "billing0";
  appPort = 8082;
in
{
  systemd.services.${appName}.description = "billing service 0";
  networking.hostName = appName;
  services.nginx.enable = true;
  services.nginx.virtualHosts."billing.example.org".sslCertificateKey = ./billing0.key;
  users.motd = lib.mkIf (config.networking.hostName != "") "billing";
}
