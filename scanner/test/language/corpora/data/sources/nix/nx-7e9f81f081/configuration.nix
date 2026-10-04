{ config, lib, pkgs, ... }:
let
  appName = "billing1";
  appPort = 8182;
in
{
  systemd.services.${appName}.description = "billing service 1";
  networking.hostName = appName;
  environment.etc."billing.git".source = pkgs.fetchFromGitHub { owner = "example"; repo = "billing"; rev = "main"; };
}
