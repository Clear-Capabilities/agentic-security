{ config, lib, pkgs, ... }:
let
  appName = "mailer1";
  appPort = 8184;
in
{
  systemd.services.${appName}.description = "mailer service 1";
  networking.hostName = appName;
  environment.etc."mailer.git".source = pkgs.fetchFromGitHub { owner = "example"; repo = "mailer"; rev = "eb2888bf7700f0d58e72da54b782afb3179510dd"; hash = "sha256-N0mevBnC093GDjmgjZzFficgJOHeDW3u4+Er9B3Ab/Q="; };
}
