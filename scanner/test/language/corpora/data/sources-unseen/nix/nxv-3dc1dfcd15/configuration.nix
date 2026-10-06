{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  services.nginx.enable = true;
  services.nginx.virtualHosts."billing.example.org".sslCertificateKey = "/run/credentials/nginx.service/billing-v0.key";
}
