{ config, lib, pkgs, ... }:
{
  services.syslog.extraConfig = "${(if config.services.crm.ipAddress == "" then "none" else "set")}";
}
