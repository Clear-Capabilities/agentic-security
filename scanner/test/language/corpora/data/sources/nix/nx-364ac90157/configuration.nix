{ config, lib, pkgs, ... }:
let
  appName = "billing1";
  appPort = 8182;
in
{
  systemd.services.${appName}.description = "billing service 1";
  networking.hostName = appName;
  nix.settings.sandbox = true;
  nix.settings.extra-sandbox-paths = [ "/etc/billing-ca" ];
}
