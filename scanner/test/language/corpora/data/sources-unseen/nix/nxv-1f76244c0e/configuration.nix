{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  nix.settings.substituters = lib.mkForce [ "https://mirror.example.org/cache" ];
}
