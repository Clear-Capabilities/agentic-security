{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  nix.settings.substituters = [ "https://cache.nixos.org" "http://cache.internal.example.org" ];
}
