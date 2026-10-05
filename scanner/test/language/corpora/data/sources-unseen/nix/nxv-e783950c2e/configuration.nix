{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  nix.settings.plugin-files = [ "/opt/crm/hook-v0.so" ];
}
