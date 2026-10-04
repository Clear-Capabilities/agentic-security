{ config, lib, pkgs, ... }:
let
  appName = "billing1";
  appPort = 8182;
in
{
  systemd.services.${appName}.description = "billing service 1";
  networking.hostName = appName;
  environment.etc."billing.git".source = pkgs.fetchFromGitHub { owner = "example"; repo = "billing"; rev = "34fa2be3e98976366bae204ed33c1ae9c4f0e194"; hash = "sha256-uEfseIu5or+Qhn4B+Dm/xV6K3srA8vczXsLtk08TMos="; };
}
