{ config, lib, pkgs, ... }:
let
  appName = "billing0";
  appPort = 8082;
in
{
  systemd.services.${appName}.description = "billing service 0";
  networking.hostName = appName;
  services.postgresql.enable = true;
  services.postgresql.settings.listen_addresses = lib.mkForce "localhost";
}
