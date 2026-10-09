{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  nix.settings.extra-plugin-files = [ "/opt/billing/hook-v0.so" ];
}
