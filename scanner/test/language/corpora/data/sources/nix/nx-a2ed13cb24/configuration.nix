{ config, lib, pkgs, ... }:
let
  appName = "crm0";
  appPort = 8081;
in
{
  systemd.services.${appName}.description = "crm service 0";
  networking.hostName = appName;
  security.sudo.wheelNeedsPassword = false;
  environment.variables = lib.optionalAttrs config.services.xserver.enable { CRM_UI = "1"; };
}
