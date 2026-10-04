{ config, lib, pkgs, ... }:
let
  appName = "wiki0";
  appPort = 8083;
in
{
  systemd.services.${appName}.description = "wiki service 0";
  networking.hostName = appName;
  systemd.services."${appName}-job".script = "backup ${lib.escapeShellArg config.services.wiki.target}";
}
