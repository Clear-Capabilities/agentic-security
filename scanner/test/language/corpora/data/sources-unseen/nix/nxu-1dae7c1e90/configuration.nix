{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  networking.firewall = { enable = true; allowedTCPPorts = [ 443 ]; };
}
