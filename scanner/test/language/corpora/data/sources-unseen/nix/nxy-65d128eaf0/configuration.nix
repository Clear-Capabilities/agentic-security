{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  nix.binaryCaches = [ "http://cache.billing.example.org" ];
}
