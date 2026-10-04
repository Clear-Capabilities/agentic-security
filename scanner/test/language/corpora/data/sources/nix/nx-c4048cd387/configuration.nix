{ config, lib, pkgs, ... }:
let
  appName = "wiki1";
  appPort = 8183;
in
{
  systemd.services.${appName}.description = "wiki service 1";
  networking.hostName = appName;
  environment.etc."wiki.git".source = pkgs.fetchFromGitHub { owner = "example"; repo = "wiki"; rev = "d6a443c447971e025f81bce56dd8419dd41c9c04"; hash = "sha256-RlYeOeQ7SM+KqIPBdiHr8CDu74xXcBWGuuy0wQKNhe0="; };
}
