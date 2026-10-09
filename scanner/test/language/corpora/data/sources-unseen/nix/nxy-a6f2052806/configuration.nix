{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPorts = [ 443 ] ++ lib.optionals cfg.enableHttp [ 80 ];
}
