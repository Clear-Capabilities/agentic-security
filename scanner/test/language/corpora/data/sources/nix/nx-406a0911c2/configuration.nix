{ config, lib, pkgs, ... }:
let
  appName = "billing0";
  appPort = 8082;
in
{
  systemd.services.${appName}.description = "billing service 0";
  networking.hostName = appName;
  environment.etc."billing.git".source = pkgs.fetchFromGitHub { owner = "example"; repo = "billing"; rev = "main"; };
}
