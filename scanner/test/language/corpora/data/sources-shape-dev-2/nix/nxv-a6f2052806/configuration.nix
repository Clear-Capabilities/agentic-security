{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPorts = [ 80 443 ];
}
