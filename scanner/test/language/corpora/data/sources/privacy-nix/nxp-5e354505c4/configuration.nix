{ config, lib, pkgs, ... }:
{
  systemd.services.crm.environment.CRM_DATA = "${(if config.services.crm.phone == "" then "none" else "set")}";
}
