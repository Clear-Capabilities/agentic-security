{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  services.crm.apiToken = "example-placeholder-crm-u0";
}
