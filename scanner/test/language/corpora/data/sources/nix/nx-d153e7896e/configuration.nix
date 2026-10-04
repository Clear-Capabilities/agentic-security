{ config, lib, pkgs, ... }:
let
  appName = "billing0";
  appPort = 8082;
in
{
  systemd.services.${appName}.description = "billing service 0";
  networking.hostName = appName;
  nix.settings.sandbox = false;
  environment.variables = lib.optionalAttrs config.services.xserver.enable { BILLING_UI = "1"; };
}
