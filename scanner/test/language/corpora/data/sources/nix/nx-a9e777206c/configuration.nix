{ config, lib, pkgs, ... }:
let
  appName = "crm1";
  appPort = 8181;
in
{
  systemd.services.${appName}.description = "crm service 1";
  networking.hostName = appName;
  environment.etc."crm.git".source = pkgs.fetchFromGitHub { owner = "example"; repo = "crm"; rev = "c223ce04f941b54dd5817a19f87d55d3c3a7cea2"; hash = "sha256-OQpWXFTEdxDK8znY9CCEXOXEjG5TuQQBJ+KyQtMr4f8="; };
}
