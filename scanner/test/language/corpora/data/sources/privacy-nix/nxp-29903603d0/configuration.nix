{ config, lib, pkgs, ... }:
{
  environment.variables.CRM = "${(if config.services.crm.passport == "" then "none" else "set")}";
}
