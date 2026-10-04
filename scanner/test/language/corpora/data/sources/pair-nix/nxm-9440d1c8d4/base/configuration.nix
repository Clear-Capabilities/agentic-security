{ config, lib, pkgs, ... }:
let
  appName = "billing9";
  appPort = 8982;
in
{
  systemd.services.${appName}.description = "billing service 9";
  networking.hostName = appName;
  systemd.services.billing.wantedBy = [ "multi-user.target" ];
  systemd.services.billing.serviceConfig.ExecStart = "${pkgs.hello}/bin/hello";
  systemd.services.billing.serviceConfig.User = "root";
}
