{ config, lib, pkgs, ... }:
let
  appName = "crm0";
  appPort = 8081;
in
{
  systemd.services.${appName}.description = "crm service 0";
  networking.hostName = appName;
  systemd.services.crm.wantedBy = [ "multi-user.target" ];
  systemd.services.crm.serviceConfig.ExecStart = "${pkgs.hello}/bin/hello";
  systemd.services.crm.serviceConfig.User = "crm-svc";
  systemd.services.crm.serviceConfig.AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
}
