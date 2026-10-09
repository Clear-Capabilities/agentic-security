{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
  everything = { from = 1; to = 65535; };
in
{
  networking.hostName = "billing-y0";
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPortRanges = [ everything ];
}
