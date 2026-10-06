{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  services.postgresql.enable = true;
  services.postgresql.authentication = "local all all peer";
}
