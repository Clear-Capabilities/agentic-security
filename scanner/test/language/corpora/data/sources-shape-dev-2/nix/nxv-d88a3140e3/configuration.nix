{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  environment.variables.CRM_API_KEY = "correct-horse-crm-v0";
}
