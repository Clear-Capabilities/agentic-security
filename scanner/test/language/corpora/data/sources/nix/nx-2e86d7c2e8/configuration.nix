{ config, lib, pkgs, ... }:
let
  appName = "tracker0";
  appPort = 8085;
in
{
  systemd.services.${appName}.description = "tracker service 0";
  networking.hostName = appName;
  environment.etc."tracker-run.sh".text = "echo ${lib.escapeShellArg config.services.tracker.message}";
}
