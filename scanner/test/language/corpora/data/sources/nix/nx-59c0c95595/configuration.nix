{ config, lib, pkgs, ... }:
let
  appName = "mailer0";
  appPort = 8084;
in
{
  systemd.services.${appName}.description = "mailer service 0";
  networking.hostName = appName;
  environment.etc."mailer.git".source = pkgs.fetchFromGitHub { owner = "example"; repo = "mailer"; rev = "5b46df492011f219b03d06929f428e285912a123"; hash = "sha256-gBziDuBDAgwuEkTeZFcxi40ml9r+YQPOziOTsFWO4wc="; };
}
