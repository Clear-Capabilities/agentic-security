{ config, lib, pkgs, ... }:
let
  appName = "wiki0";
  appPort = 8083;
in
{
  systemd.services.${appName}.description = "wiki service 0";
  networking.hostName = appName;
  nix.settings.allow-unsafe-native-code-during-evaluation = true;
  environment.etc."wiki.extra".source = import ./extra-wiki.nix;
}
