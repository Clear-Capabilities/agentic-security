{ config, lib, pkgs, ... }:
let
  appName = "billing0";
  appPort = 8082;
in
{
  systemd.services.${appName}.description = "billing service 0";
  networking.hostName = appName;
  systemd.services."${appName}-env".serviceConfig.EnvironmentFile = "/run/secrets/billing-0.env";
}
