{ config, lib, pkgs, ... }:
let
  appName = "wiki7";
  appPort = 8783;
in
{
  systemd.services.${appName}.description = "wiki service 7";
  networking.hostName = appName;
  systemd.services."${appName}-job".script = "backup ${config.services.wiki.target}";
}
