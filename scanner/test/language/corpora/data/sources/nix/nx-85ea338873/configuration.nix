{ config, lib, pkgs, ... }:
let
  appName = "mailer0";
  appPort = 8084;
in
{
  systemd.services.${appName}.description = "mailer service 0";
  networking.hostName = appName;
  environment.etc."mailer.src".source = pkgs.fetchurl { url = "https://example.org/mailer-0.tar.gz"; };
}
