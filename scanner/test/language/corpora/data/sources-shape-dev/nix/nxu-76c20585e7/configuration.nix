{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  services.postgresql.enable = true;
  services.postgresql.authentication = "host all all 0.0.0.0/0 trust";
}
