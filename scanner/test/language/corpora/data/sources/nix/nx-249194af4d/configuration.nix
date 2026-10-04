{ config, lib, pkgs, ... }:
let
  appName = "wiki0";
  appPort = 8083;
in
{
  systemd.services.${appName}.description = "wiki service 0";
  networking.hostName = appName;
  nix.settings.sandbox = true;
  nix.settings.extra-sandbox-paths = [ "/etc/wiki-ca" ];
}
