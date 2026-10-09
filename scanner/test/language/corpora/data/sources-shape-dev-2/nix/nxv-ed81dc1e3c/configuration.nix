{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  systemd.services.crm.serviceConfig.EnvironmentFile = "/run/secrets/crm.env";
}
