{ config, lib, pkgs, ... }:
let
  appName = "billing0";
  appPort = 8082;
in
{
  systemd.services.${appName}.description = "billing service 0";
  networking.hostName = appName;
  systemd.services.billing.wantedBy = [ "multi-user.target" ];
  systemd.services.billing.serviceConfig.ExecStart = "${pkgs.hello}/bin/hello";
  systemd.services.billing.serviceConfig.User = "billing-svc";
  systemd.services.billing.serviceConfig.AmbientCapabilities = [ "CAP_SYS_ADMIN" ];
}
