{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  systemd.services.billing.environment.DATABASE_PASSWORD = "p@ssw0rd-billing-prod";
}
