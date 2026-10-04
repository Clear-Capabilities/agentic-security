{ config, lib, pkgs, ... }:
{
  systemd.services.crm.environment.CRM_DATA = "${(if config.services.crm.ssn != "" then "set" else "none")}";
}
