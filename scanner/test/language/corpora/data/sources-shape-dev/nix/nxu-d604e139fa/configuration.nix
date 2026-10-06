{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  nix.settings.plugin-files = [ "/opt/billing/u0.so" ];
}
