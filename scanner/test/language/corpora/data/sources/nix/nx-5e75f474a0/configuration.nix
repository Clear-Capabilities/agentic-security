{ config, lib, pkgs, ... }:
let
  appName = "tracker0";
  appPort = 8085;
in
{
  systemd.services.${appName}.description = "tracker service 0";
  networking.hostName = appName;
  systemd.services.tracker.wantedBy = [ "multi-user.target" ];
  systemd.services.tracker.serviceConfig.ExecStart = "${pkgs.hello}/bin/hello";
  systemd.services.tracker.serviceConfig.DynamicUser = true;
}
