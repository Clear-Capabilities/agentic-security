{ config, lib, pkgs, ... }:
let
  appName = "mailer0";
  appPort = 8084;
in
{
  systemd.services.${appName}.description = "mailer service 0";
  networking.hostName = appName;
  services.nginx.enable = true;
  services.nginx.virtualHosts."mailer.example.org".sslCertificateKey = ./mailer0.key;
}
