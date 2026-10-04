{ config, lib, pkgs, ... }:
let
  appName = "mailer0";
  appPort = 8084;
in
{
  systemd.services.${appName}.description = "mailer service 0";
  networking.hostName = appName;
  systemd.services.mailer.wantedBy = [ "multi-user.target" ];
  systemd.services.mailer.serviceConfig.ExecStart = "${pkgs.hello}/bin/hello";
  systemd.services.mailer.serviceConfig.User = "root";
  time.timeZone = lib.mkOverride 900 "UTC";
}
