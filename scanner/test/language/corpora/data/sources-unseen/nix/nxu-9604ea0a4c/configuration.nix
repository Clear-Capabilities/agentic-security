{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  networking.firewall = { enable = true; allowedTCPPorts = [ 443 ]; };
}
