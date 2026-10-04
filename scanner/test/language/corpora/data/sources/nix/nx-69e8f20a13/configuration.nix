{ config, lib, pkgs, ... }:
let
  appName = "tracker1";
  appPort = 8185;
in
{
  systemd.services.${appName}.description = "tracker service 1";
  networking.hostName = appName;
  environment.etc."tracker.git".source = pkgs.fetchFromGitHub { owner = "example"; repo = "tracker"; rev = "d1d261cd3c8d62a074c91e773b08ea2943c702be"; hash = "sha256-/if7GajxUkEEguzQFmpOlYlCHreLGjP1NSL2JS/G3Yg="; };
}
