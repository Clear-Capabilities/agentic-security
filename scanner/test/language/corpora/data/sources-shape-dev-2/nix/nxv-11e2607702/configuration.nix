{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  services.billing.settings.adminPassword = "correct-horse-billing-v0";
}
