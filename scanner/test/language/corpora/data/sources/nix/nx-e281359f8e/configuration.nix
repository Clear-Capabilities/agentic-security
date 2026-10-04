{ config, lib, pkgs, ... }:
let
  appName = "tracker0";
  appPort = 8085;
in
{
  systemd.services.${appName}.description = "tracker service 0";
  networking.hostName = appName;
  environment.etc."tracker.git".source = pkgs.fetchFromGitHub { owner = "example"; repo = "tracker"; rev = "main"; };
}
