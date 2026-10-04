{ config, lib, pkgs, ... }:
let
  appName = "wiki0";
  appPort = 8083;
in
{
  systemd.services.${appName}.description = "wiki service 0";
  networking.hostName = appName;
  systemd.services.wiki.wantedBy = [ "multi-user.target" ];
  systemd.services.wiki.serviceConfig.ExecStart = "${pkgs.hello}/bin/hello";
  systemd.services.wiki.serviceConfig.User = "root";
  networking.domain = lib.mkDefault "wiki.example.org";
}
