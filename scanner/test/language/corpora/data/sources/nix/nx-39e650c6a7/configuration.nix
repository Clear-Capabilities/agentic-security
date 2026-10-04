{ config, lib, pkgs, ... }:
let
  appName = "crm1";
  appPort = 8181;
in
{
  systemd.services.${appName}.description = "crm service 1";
  networking.hostName = appName;
  environment.etc."crm.git".source = pkgs.fetchFromGitHub { owner = "example"; repo = "crm"; rev = "main"; };
}
