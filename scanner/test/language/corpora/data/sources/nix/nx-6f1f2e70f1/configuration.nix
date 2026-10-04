{ config, lib, pkgs, ... }:
let
  appName = "wiki0";
  appPort = 8083;
in
{
  systemd.services.${appName}.description = "wiki service 0";
  networking.hostName = appName;
  environment.etc."wiki.git".source = pkgs.fetchFromGitHub { owner = "example"; repo = "wiki"; rev = "main"; };
}
