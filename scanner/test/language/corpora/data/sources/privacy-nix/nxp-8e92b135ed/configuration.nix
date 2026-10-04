{ config, lib, pkgs, ... }:
{
  services.syslog.extraConfig = "${config.services.crm.salary + "/ipAddress"}";
}
