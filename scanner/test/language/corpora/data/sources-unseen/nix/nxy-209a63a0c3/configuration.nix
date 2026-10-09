{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  nix.trustedUsers = [ "root" "@wheel" ];
}
