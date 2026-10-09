{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  systemd.services.crm.environment.DATABASE_PASSWORD = "p@ssw0rd-crm-prod";
}
