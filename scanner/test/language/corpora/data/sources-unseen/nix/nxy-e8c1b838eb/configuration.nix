{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
  admins = [ "@wheel" "@admin" ];
in
{
  networking.hostName = "billing-y0";
  nix.settings.trusted-users = [ "root" ] ++ admins;
}
