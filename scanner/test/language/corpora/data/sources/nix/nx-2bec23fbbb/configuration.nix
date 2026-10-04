{ config, lib, pkgs, ... }:
let
  appName = "crm0";
  appPort = 8081;
in
{
  systemd.services.${appName}.description = "crm service 0";
  networking.hostName = appName;
  nix.settings.allow-unsafe-native-code-during-evaluation = true;
  environment.etc."crm.extra".source = import ./extra-crm.nix;
}
