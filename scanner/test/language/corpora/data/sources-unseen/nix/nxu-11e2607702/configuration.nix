{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  services.billing.settings.password = "example-placeholder-billing-u0";
}
