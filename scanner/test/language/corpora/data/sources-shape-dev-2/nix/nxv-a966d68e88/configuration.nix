{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  nix.settings.substituters = lib.mkForce [ "http://mirror.example.org/cache" ];
}
