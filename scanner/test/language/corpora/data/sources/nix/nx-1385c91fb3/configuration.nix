{ config, lib, pkgs, ... }:
let
  appName = "wiki1";
  appPort = 8183;
in
{
  systemd.services.${appName}.description = "wiki service 1";
  networking.hostName = appName;
  nix.settings.sandbox = true;
  nix.settings.extra-sandbox-paths = [ "/etc/wiki-ca" ];
}
