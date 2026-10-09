{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPortRanges = [ { from = 1; to = 65535; } ];
}
