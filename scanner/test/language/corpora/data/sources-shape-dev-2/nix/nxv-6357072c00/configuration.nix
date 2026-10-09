{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  nix.extraOptions = ''
    plugin-files = /opt/crm/v0.so
  '';
}
