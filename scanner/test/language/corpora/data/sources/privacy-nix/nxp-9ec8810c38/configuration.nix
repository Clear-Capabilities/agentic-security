{ config, lib, pkgs, ... }:
{
  services.syslog.extraConfig = "${(if config.services.crm.cardNo != "" then "set" else "none")}";
}
