{ config, lib, pkgs, ... }:
{
  services.journald.extraConfig = "Storage=${(if config.services.crm.cardNo != "" then "set" else "none")}";
}
