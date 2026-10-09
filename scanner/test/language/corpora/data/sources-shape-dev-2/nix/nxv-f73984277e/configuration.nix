{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  networking.firewall.enable = true;
  services.mysql.enable = true;
  networking.firewall.allowedTCPPorts = [ 3306 ];
}
