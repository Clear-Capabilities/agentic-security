{ config, lib, pkgs, ... }:
{
  systemd.services.crm.environment.CRM_DATA = "${config.services.crm.passport}";
}
