{ config, lib, pkgs, ... }:
let
  appName = "mailer1";
  appPort = 8184;
in
{
  systemd.services.${appName}.description = "mailer service 1";
  networking.hostName = appName;
  environment.variables.API_KEY = "example-placeholder-mailer-1";
}
