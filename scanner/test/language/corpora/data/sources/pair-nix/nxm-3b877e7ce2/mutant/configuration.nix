{ config, lib, pkgs, ... }:
let
  appName = "crm9";
  appPort = 8981;
in
{
  systemd.services.${appName}.description = "crm service 9";
  networking.hostName = appName;
  systemd.services.crm.wantedBy = [ "multi-user.target" ];
  systemd.services.crm.serviceConfig.ExecStart = "${pkgs.hello}/bin/hello";
  systemd.services.crm.serviceConfig.User = "root";
}
