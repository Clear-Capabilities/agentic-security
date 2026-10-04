{ config, lib, pkgs, ... }:
let
  appName = "crm0";
  appPort = 8081;
in
{
  systemd.services.${appName}.description = "crm service 0";
  networking.hostName = appName;
  environment.etc."crm.git".source = pkgs.fetchFromGitHub { owner = "example"; repo = "crm"; rev = "e06738b256fabb60e68ae8b96a4c01268ed8cbc7"; hash = "sha256-KhFC/pUAgHnuUs0yj5NrY8fsy1w24/f+xXd7iYSQH2k="; };
}
