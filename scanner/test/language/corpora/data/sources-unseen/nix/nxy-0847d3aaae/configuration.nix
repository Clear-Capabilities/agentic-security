{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  services.billing.passwordFile = pkgs.writeText "billing-pass" "swordfish-billing";
}
