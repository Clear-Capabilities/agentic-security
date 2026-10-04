{ config, lib, pkgs, ... }:
let
  appName = "wiki0";
  appPort = 8083;
in
{
  systemd.services.${appName}.description = "wiki service 0";
  networking.hostName = appName;
  systemd.services."${appName}-job".script = "backup ${config.services.wiki.target}";
  networking.domain = lib.mkDefault "wiki.example.org";
}
