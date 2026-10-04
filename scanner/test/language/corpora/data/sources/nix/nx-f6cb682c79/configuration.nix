{ config, lib, pkgs, ... }:
let
  appName = "billing1";
  appPort = 8182;
in
{
  systemd.services.${appName}.description = "billing service 1";
  networking.hostName = appName;
  systemd.services.billing.wantedBy = [ "multi-user.target" ];
  systemd.services.billing.serviceConfig.ExecStart = "${pkgs.hello}/bin/hello";
  systemd.services.billing.serviceConfig.User = "root";
}
