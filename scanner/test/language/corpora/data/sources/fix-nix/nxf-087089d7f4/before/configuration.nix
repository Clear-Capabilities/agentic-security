{ config, lib, pkgs, ... }:
let
  appName = "billing7";
  appPort = 8782;
in
{
  systemd.services.${appName}.description = "billing service 7";
  networking.hostName = appName;
  environment.etc."billing.src".source = pkgs.fetchurl { url = "https://example.org/billing-7.tar.gz"; };
}
