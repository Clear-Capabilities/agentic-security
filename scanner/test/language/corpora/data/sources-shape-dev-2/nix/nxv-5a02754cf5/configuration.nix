{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  services.nginx.enable = true;
  services.nginx.virtualHosts."crm.example.org".forceSSL = true;
}
