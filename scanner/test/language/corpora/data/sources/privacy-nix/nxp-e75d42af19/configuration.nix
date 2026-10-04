{ config, lib, pkgs, ... }:
{
  environment.variables.CRM = "${builtins.hashString "sha256" config.services.crm.ipAddress}";
}
