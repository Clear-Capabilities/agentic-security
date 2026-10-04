{ config, lib, pkgs, ... }:
{
  services.journald.extraConfig = "Storage=${(if config.services.crm.email == "" then "none" else "set")}";
}
