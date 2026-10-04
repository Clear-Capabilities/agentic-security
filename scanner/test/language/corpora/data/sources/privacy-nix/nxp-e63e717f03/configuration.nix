{ config, lib, pkgs, ... }:
{
  services.syslog.extraConfig = "${config.services.crm.address + "/phone"}";
}
