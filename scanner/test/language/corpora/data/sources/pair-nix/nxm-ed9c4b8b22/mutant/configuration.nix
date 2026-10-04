{ config, lib, pkgs, ... }:
let
  appName = "wiki9";
  appPort = 8983;
in
{
  systemd.services.${appName}.description = "wiki service 9";
  networking.hostName = appName;
  environment.etc."wiki.src".source = pkgs.fetchurl { url = "https://example.org/wiki-9.tar.gz"; };
}
