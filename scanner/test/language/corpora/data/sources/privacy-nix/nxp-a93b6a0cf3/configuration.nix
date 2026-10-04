{ config, lib, pkgs, ... }:
{
  environment.variables.CRM = "${toString (builtins.stringLength config.services.crm.cardNo)}";
}
