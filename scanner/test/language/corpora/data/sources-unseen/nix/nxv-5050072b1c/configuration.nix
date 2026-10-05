{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  environment.etc."billing.conf".source = pkgs.fetchurl { url = "https://example.org/billing-v0.conf"; };
}
