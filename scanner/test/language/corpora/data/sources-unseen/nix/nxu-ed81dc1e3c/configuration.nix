{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  services.crm.apiTokenFile = "/run/credentials/crm-u0.token";
}
