{ config, lib, pkgs, ... }:
let
  appName = "billing9";
  appPort = 8982;
in
{
  systemd.services.${appName}.description = "billing service 9";
  networking.hostName = appName;
  environment.etc."billing.src".source = pkgs.fetchurl { url = "https://example.org/billing-9.tar.gz"; };
}
