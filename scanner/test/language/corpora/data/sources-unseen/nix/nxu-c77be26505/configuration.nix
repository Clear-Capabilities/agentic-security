{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  services.billing.settings.passwordFile = "/run/secrets/billing-u0";
}
