{ config, lib, pkgs, ... }:
let
  appName = "billing0";
  appPort = 8082;
in
{
  systemd.services.${appName}.description = "billing service 0";
  networking.hostName = appName;
  environment.etc."billing.src".source = pkgs.fetchurl { url = "https://example.org/billing-0.tar.gz"; };
  networking.search = lib.mkOptionDefault [ "billing.internal" ];
}
