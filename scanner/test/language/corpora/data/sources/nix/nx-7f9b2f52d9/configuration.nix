{ config, lib, pkgs, ... }:
let
  appName = "tracker0";
  appPort = 8085;
in
{
  systemd.services.${appName}.description = "tracker service 0";
  networking.hostName = appName;
  environment.etc."tracker.src".source = pkgs.fetchurl { url = "https://example.org/tracker-0.tar.gz"; };
  environment.variables = lib.optionalAttrs config.services.xserver.enable { TRACKER_UI = "1"; };
}
