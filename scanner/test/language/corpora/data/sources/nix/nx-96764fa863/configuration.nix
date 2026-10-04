{ config, lib, pkgs, ... }:
let
  appName = "wiki1";
  appPort = 8183;
in
{
  systemd.services.${appName}.description = "wiki service 1";
  networking.hostName = appName;
  environment.etc."wiki-run.sh".text = "echo ${lib.escapeShellArg config.services.wiki.message}";
}
