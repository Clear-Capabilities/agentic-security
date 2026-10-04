{ config, lib, pkgs, ... }:
let
  appName = "tracker1";
  appPort = 8185;
in
{
  systemd.services.${appName}.description = "tracker service 1";
  networking.hostName = appName;
  services.postgresql.enable = true;
  services.postgresql.settings.listen_addresses = lib.mkForce "localhost";
}
