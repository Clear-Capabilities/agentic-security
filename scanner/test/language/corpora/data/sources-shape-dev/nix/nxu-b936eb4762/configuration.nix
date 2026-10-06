{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  services.postgresql.enable = true;
  services.postgresql.settings.listen_addresses = "127.0.0.1";
}
