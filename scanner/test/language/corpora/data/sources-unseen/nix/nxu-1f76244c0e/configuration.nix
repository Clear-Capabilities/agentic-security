{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  nix.settings.substituters = [ "https://cache.nixos.org" "https://cache.internal.example.org" ];
}
