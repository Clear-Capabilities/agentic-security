{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  systemd.services.billing.serviceConfig.ExecStart = "${pkgs.hello}/bin/hello";
  systemd.services.billing.serviceConfig.User = "billing-svc";
  systemd.services.billing.serviceConfig.CapabilityBoundingSet = [ "" ];
}
