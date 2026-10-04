{ config, lib, pkgs, ... }:
{
  systemd.services.crm.environment.CRM_DATA = "${(if config.services.crm.cardNo == "" then "none" else "set")}";
}
