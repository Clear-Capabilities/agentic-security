{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  environment.etc."billing.conf".source = pkgs.fetchurl { url = "https://example.org/billing-v0.conf"; hash = "sha256-VIBY7S6N+TmP4g83acdHWN7na2wh3Y/G8ploPZ9iAtU="; };
}
