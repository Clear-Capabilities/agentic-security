{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  environment.etc."billing.json".source = builtins.fetchurl "https://example.org/billing-v0.json";
}
