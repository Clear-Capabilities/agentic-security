{ config, lib, pkgs, ... }:
{
  services.syslog.extraConfig = "${(if config.services.crm.email == "" then "none" else "set")}";
}
