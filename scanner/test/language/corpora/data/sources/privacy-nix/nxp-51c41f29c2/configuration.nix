{ config, lib, pkgs, ... }:
{
  environment.variables.CRM = "${(if config.services.crm.salary != "" then "set" else "none")}";
}
