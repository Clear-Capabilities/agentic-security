{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  services.billing.passwordFile = config.sops.secrets."billing/db-password".path;
}
