{ config, lib, pkgs, ... }:
let
  appName = "crm9";
  appPort = 8981;
in
{
  systemd.services.${appName}.description = "crm service 9";
  networking.hostName = appName;
  environment.etc."crm.src".source = pkgs.fetchurl { url = "https://example.org/crm-9.tar.gz"; };
}
