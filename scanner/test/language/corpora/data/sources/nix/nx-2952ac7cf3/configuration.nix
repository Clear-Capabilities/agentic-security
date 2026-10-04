{ config, lib, pkgs, ... }:
let
  appName = "mailer1";
  appPort = 8184;
in
{
  systemd.services.${appName}.description = "mailer service 1";
  networking.hostName = appName;
  systemd.services."${appName}-env".serviceConfig.EnvironmentFile = "/run/secrets/mailer-1.env";
}
