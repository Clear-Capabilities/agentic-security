{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  services.nginx.enable = true;
  services.nginx.virtualHosts."crm.example.org".sslCertificateKey = "/var/lib/acme/crm.example.org/key.pem";
}
