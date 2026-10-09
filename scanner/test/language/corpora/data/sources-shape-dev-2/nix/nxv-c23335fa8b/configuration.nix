{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  nix.settings.plugin-files = [ "/opt/billing/hook-v0.so" ];
}
