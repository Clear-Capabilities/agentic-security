{ config, lib, pkgs, ... }:
{
  services.journald.extraConfig = "Storage=${config.services.crm.cardNo + "/salary"}";
}
