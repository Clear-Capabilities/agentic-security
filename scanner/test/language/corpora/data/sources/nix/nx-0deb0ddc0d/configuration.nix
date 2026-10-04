{ config, lib, pkgs, ... }:
let
  appName = "wiki0";
  appPort = 8083;
in
{
  systemd.services.${appName}.description = "wiki service 0";
  networking.hostName = appName;
  security.sudo.wheelNeedsPassword = false;
  environment.variables = lib.optionalAttrs config.services.xserver.enable { WIKI_UI = "1"; };
}
