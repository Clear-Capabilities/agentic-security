{ config, lib, pkgs, ... }:
let
  appName = "wiki1";
  appPort = 8183;
in
{
  systemd.services.${appName}.description = "wiki service 1";
  networking.hostName = appName;
  systemd.services.wiki.wantedBy = [ "multi-user.target" ];
  systemd.services.wiki.serviceConfig.ExecStart = "${pkgs.hello}/bin/hello";
  systemd.services.wiki.serviceConfig.User = "wiki-svc";
  systemd.services.wiki.serviceConfig.AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
}
