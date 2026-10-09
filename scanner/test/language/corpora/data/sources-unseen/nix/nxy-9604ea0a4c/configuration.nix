{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPortRanges = [ { from = 8000; to = 8010; } ];
  networking.firewall.allowedUDPPortRanges = [ { from = 60000; to = 60010; } ];
}
