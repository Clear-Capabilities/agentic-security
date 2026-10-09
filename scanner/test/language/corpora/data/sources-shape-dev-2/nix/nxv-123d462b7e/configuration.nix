{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  services.nginx.enable = true;
  services.nginx.virtualHosts."billing.example.org".sslCertificateKey = builtins.toFile "billing-v0.key" "placeholder";
}
