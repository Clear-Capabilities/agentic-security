{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  systemd.services.billing.serviceConfig.EnvironmentFile = "/run/secrets/billing.env";
}
