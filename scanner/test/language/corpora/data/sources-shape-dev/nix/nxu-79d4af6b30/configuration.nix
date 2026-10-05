{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  environment.etc."billing.tar".source = builtins.fetchTarball "https://example.org/billing-u0.tar.gz";
}
