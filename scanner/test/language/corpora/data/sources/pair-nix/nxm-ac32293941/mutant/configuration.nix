{ config, lib, pkgs, ... }:
let
  appName = "wiki9";
  appPort = 8983;
in
{
  systemd.services.${appName}.description = "wiki service 9";
  networking.hostName = appName;
  services.nginx.enable = true;
  services.nginx.virtualHosts."wiki.example.org".sslCertificateKey = ./wiki9.key;
}
