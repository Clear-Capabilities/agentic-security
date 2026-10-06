{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  services.postgresql.enable = true;
  services.postgresql.authentication = "local all all peer";
}
