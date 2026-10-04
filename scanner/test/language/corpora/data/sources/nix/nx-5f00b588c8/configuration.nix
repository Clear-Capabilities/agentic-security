{ config, lib, pkgs, ... }:
let
  appName = "mailer0";
  appPort = 8084;
in
{
  systemd.services.${appName}.description = "mailer service 0";
  networking.hostName = appName;
  services.mailer.password = "example-placeholder-mailer-0";
  environment.etc."mailer.extra".source = import ./extra-mailer.nix;
}
