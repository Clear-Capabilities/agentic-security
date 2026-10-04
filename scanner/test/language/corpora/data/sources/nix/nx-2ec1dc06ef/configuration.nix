{ config, lib, pkgs, ... }:
let
  appName = "tracker1";
  appPort = 8185;
in
{
  systemd.services.${appName}.description = "tracker service 1";
  networking.hostName = appName;
  systemd.services.tracker.wantedBy = [ "multi-user.target" ];
  systemd.services.tracker.serviceConfig.ExecStart = "${pkgs.hello}/bin/hello";
  systemd.services.tracker.serviceConfig.User = "tracker-svc";
  systemd.services.tracker.serviceConfig.AmbientCapabilities = [ "CAP_SYS_ADMIN" ];
}
