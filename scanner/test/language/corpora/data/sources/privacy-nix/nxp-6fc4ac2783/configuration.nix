{ config, lib, pkgs, ... }:
{
  services.syslog.extraConfig = "${(if config.services.crm.phone != "" then "set" else "none")}";
}
