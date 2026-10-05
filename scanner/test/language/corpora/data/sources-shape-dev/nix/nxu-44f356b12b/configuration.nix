{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  services.crm.settings.passwordFile = "/run/secrets/crm-u0";
}
