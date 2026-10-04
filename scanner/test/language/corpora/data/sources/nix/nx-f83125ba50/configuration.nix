{ config, lib, pkgs, ... }:
let
  appName = "crm1";
  appPort = 8181;
in
{
  systemd.services.${appName}.description = "crm service 1";
  networking.hostName = appName;
  environment.etc."crm.src".source = pkgs.fetchurl { url = "https://example.org/crm-1.tar.gz"; };
}
