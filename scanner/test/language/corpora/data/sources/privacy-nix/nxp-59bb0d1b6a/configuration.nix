{ config, lib, pkgs, ... }:
{
  services.journald.extraConfig = "Storage=${(if config.services.crm.ipAddress == "" then "none" else "set")}";
}
