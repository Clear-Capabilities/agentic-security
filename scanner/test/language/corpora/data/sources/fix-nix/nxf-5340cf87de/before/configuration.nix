{ config, lib, pkgs, ... }:
let
  appName = "crm7";
  appPort = 8781;
in
{
  systemd.services.${appName}.description = "crm service 7";
  networking.hostName = appName;
  environment.etc."crm.src".source = pkgs.fetchurl { url = "https://example.org/crm-7.tar.gz"; };
}
