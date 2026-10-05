{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  services.nginx.enable = true;
  services.nginx.virtualHosts."crm.example.org" = { forceSSL = false; enableACME = false; };
}
