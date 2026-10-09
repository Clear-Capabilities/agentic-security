{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  environment.variables.BILLING_API_KEY = "correct-horse-billing-v0";
}
