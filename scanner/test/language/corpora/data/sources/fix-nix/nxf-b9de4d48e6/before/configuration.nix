{ config, lib, pkgs, ... }:
let
  appName = "billing7";
  appPort = 8782;
in
{
  systemd.services.${appName}.description = "billing service 7";
  networking.hostName = appName;
  nix.settings.sandbox = false;
}
