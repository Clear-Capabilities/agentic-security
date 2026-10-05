{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  nix.settings.substituters = [ "https://cache.nixos.org" "https://cache.internal.example.org" ];
}
