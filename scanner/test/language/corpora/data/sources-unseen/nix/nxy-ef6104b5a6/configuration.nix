{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  environment.etc."billing.tar".source = builtins.fetchTarball "https://example.org/billing-v0.tar.gz";
}
