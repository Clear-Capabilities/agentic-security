{ config, lib, pkgs, ... }:
let
  appName = "billing1";
  appPort = 8182;
in
{
  systemd.services.${appName}.description = "billing service 1";
  networking.hostName = appName;
  services.postgresql.enable = true;
  services.postgresql.settings.listen_addresses = lib.mkForce "*";
}
