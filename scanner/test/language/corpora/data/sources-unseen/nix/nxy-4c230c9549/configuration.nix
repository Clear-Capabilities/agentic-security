{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
  admins = [ "@wheel" "@admin" ];
in
{
  networking.hostName = "crm-y0";
  nix.settings.trusted-users = [ "root" ] ++ admins;
}
