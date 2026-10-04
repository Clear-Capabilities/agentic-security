{ config, lib, pkgs, ... }:
{
  environment.variables.CRM = "${(if config.services.crm.ssn == "" then "none" else "set")}";
}
