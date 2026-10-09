{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  nix.extraOptions = ''
    plugin-files = /opt/billing/v0.so
  '';
}
