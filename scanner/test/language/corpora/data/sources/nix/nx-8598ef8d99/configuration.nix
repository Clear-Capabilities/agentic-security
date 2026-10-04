{ config, lib, pkgs, ... }:
let
  appName = "mailer0";
  appPort = 8084;
in
{
  systemd.services.${appName}.description = "mailer service 0";
  networking.hostName = appName;
  environment.etc."mailer-run.sh".text = "echo ${lib.escapeShellArg config.services.mailer.message}";
}
