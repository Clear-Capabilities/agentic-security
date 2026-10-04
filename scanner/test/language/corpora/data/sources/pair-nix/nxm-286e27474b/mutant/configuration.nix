{ config, lib, pkgs, ... }:
let
  qc56a80 = "crm0";
  q042701 = 8081;
in
{
  systemd.services.${qc56a80}.description = "crm service 0";
  networking.hostName = qc56a80;
  services.nginx.enable = true;
  services.nginx.virtualHosts."crm.example.org".sslCertificateKey = "/run/credentials/crm0.key";
}
