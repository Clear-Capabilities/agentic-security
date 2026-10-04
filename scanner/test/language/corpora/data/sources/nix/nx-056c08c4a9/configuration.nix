{ config, lib, pkgs, ... }:
let
  appName = "mailer1";
  appPort = 8184;
in
{
  systemd.services.${appName}.description = "mailer service 1";
  networking.hostName = appName;
  environment.etc."mailer.src".source = pkgs.fetchurl { url = "https://example.org/mailer-1.tar.gz"; };
}
