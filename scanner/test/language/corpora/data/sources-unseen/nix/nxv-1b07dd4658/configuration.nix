{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPorts = [ 80 443 ];
}
