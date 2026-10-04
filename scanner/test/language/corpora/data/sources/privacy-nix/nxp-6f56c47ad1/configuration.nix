{ config, lib, pkgs, ... }:
{
  systemd.services.crm.environment.CRM_DATA = "${toString (builtins.stringLength config.services.crm.salary + 0)}";
}
