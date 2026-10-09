{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  nix.settings.extra-plugin-files = [ "/opt/crm/hook-v0.so" ];
}
