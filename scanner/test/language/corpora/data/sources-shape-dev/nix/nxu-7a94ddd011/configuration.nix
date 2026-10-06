{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  services.nginx.enable = true;
  services.nginx.virtualHosts."crm.example.org".sslCertificateKey = "/run/secrets/crm-u0.pem";
}
