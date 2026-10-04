{ config, lib, pkgs, ... }:
let
  appName = "mailer0";
  appPort = 8084;
in
{
  systemd.services.${appName}.description = "mailer service 0";
  networking.hostName = appName;
  services.postgresql.enable = true;
  services.postgresql.settings.listen_addresses = lib.mkForce "localhost";
}
