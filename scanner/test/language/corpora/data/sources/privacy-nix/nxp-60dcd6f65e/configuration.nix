{ config, lib, pkgs, ... }:
{
  services.journald.extraConfig = "Storage=${(if config.services.crm.phone != "" then "set" else "none")}";
}
