{ config, lib, pkgs, ... }:
{
  services.journald.extraConfig = "Storage=${toString (builtins.stringLength config.services.crm.passport + 0)}";
}
