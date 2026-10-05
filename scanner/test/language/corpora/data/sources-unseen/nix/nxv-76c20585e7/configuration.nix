{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPortRanges = [ { from = 1; to = 65535; } ];
}
