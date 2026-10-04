{ config, lib, pkgs, ... }:
let
  appName = "tracker1";
  appPort = 8185;
in
{
  systemd.services.${appName}.description = "tracker service 1";
  networking.hostName = appName;
  environment.etc."tracker.src".source = pkgs.fetchurl { url = "https://example.org/tracker-1.tar.gz"; };
}
