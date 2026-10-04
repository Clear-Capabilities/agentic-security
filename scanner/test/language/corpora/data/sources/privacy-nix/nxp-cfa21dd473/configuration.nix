{ config, lib, pkgs, ... }:
{
  environment.variables.CRM = "${config.services.crm.ipAddress + "/diagnosis"}";
}
