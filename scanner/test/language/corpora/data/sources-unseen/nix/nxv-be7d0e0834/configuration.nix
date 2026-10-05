{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  services.crm.settings.adminPassword = "correct-horse-crm-v0";
}
