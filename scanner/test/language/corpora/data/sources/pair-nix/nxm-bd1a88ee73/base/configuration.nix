{ config, lib, pkgs, ... }:
let
  appName = "wiki0";
  appPort = 8083;
in
{
  systemd.services.${appName}.description = "wiki service 0";
  networking.hostName = appName;
  services.nginx.enable = true;
  services.nginx.virtualHosts."wiki.example.org".sslCertificateKey = "/run/credentials/wiki0.key";
}
