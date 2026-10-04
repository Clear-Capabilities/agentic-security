{ config, lib, pkgs, ... }:
let
  appName = "wiki9";
  appPort = 8983;
in
{
  systemd.services.${appName}.description = "wiki service 9";
  networking.hostName = appName;
  systemd.services.wiki.wantedBy = [ "multi-user.target" ];
  systemd.services.wiki.serviceConfig.ExecStart = "${pkgs.hello}/bin/hello";
  systemd.services.wiki.serviceConfig.DynamicUser = true;
}
