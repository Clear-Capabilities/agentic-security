{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  systemd.services.crm.serviceConfig.ExecStart = "${pkgs.hello}/bin/hello";
  systemd.services.crm.serviceConfig.User = "crm-svc";
  systemd.services.crm.serviceConfig.CapabilityBoundingSet = [ "" ];
}
