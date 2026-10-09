{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  services.nginx.enable = true;
  services.nginx.virtualHosts."billing.example.org".sslCertificateKey = "/var/lib/acme/billing.example.org/key.pem";
}
