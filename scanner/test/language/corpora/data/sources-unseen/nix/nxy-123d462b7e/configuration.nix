{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  services.nginx.enable = true;
  services.nginx.virtualHosts."billing.example.org".sslCertificateKey = pkgs.writeText "billing.key" (builtins.readFile ./billing.key);
}
