{ config, lib, pkgs, ... }:
let
  appName = "wiki1";
  appPort = 8183;
in
{
  systemd.services.${appName}.description = "wiki service 1";
  networking.hostName = appName;
  environment.etc."wiki.git".source = pkgs.fetchFromGitHub { owner = "example"; repo = "wiki"; rev = "main"; };
}
