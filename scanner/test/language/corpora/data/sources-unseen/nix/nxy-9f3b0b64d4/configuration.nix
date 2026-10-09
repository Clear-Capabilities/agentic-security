{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
  everything = { from = 1; to = 65535; };
in
{
  networking.hostName = "crm-y0";
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPortRanges = [ everything ];
}
