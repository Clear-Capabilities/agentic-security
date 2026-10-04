{ config, lib, pkgs, ... }:
{
  environment.variables.CRM = "${(if config.services.crm.dob != "" then "set" else "none")}";
}
