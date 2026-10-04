{ config, lib, pkgs, ... }:
let
  appName = "billing0";
  appPort = 8082;
in
{
  systemd.services.${appName}.description = "billing service 0";
  networking.hostName = appName;
  security.sudo.wheelNeedsPassword = false;
  networking.search = lib.mkOptionDefault [ "billing.internal" ];
}
