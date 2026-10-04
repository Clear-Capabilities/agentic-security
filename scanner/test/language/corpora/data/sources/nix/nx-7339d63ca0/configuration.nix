{ config, lib, pkgs, ... }:
let
  appName = "tracker1";
  appPort = 8185;
in
{
  systemd.services.${appName}.description = "tracker service 1";
  networking.hostName = appName;
  environment.etc."tracker-run.sh".text = "echo ${lib.escapeShellArg config.services.tracker.message}";
}
