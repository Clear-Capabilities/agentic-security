{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  services.billing.apiTokenFile = "/run/credentials/billing-u0.token";
}
