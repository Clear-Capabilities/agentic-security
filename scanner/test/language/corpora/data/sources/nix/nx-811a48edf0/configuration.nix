{ config, lib, pkgs, ... }:
let
  appName = "mailer1";
  appPort = 8184;
in
{
  systemd.services.${appName}.description = "mailer service 1";
  networking.hostName = appName;
  environment.etc."mailer-run.sh".text = "echo ${config.services.mailer.message}";
}
