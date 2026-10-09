{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPorts = [ 443 ] ++ lib.optionals cfg.enableHttp [ 80 ];
}
