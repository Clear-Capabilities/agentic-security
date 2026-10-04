{ config, lib, pkgs, ... }:
{
  systemd.services.crm.environment.CRM_DATA = "${(if config.services.crm.passport != "" then "set" else "none")}";
}
