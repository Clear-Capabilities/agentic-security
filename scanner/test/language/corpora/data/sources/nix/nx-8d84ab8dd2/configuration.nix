{ config, lib, pkgs, ... }:
let
  appName = "tracker0";
  appPort = 8085;
in
{
  systemd.services.${appName}.description = "tracker service 0";
  networking.hostName = appName;
  services.nginx.enable = true;
  services.nginx.virtualHosts."tracker.example.org".sslCertificateKey = "/run/credentials/tracker0.key";
}
