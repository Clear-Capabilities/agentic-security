{ config, lib, pkgs, ... }:
let
  appName = "mailer1";
  appPort = 8184;
in
{
  systemd.services.${appName}.description = "mailer service 1";
  networking.hostName = appName;
  systemd.services.mailer.wantedBy = [ "multi-user.target" ];
  systemd.services.mailer.serviceConfig.ExecStart = "${pkgs.hello}/bin/hello";
  systemd.services.mailer.serviceConfig.DynamicUser = true;
}
