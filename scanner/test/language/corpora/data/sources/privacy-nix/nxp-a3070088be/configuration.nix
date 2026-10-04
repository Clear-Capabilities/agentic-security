{ config, lib, pkgs, ... }:
{
  networking.extraHosts = "10.0.0.1 ${toString (builtins.stringLength config.services.crm.cardNo + 0)}";
}
