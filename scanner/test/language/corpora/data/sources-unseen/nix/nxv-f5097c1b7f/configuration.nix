{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  users.users.billing-svc.hashedPasswordFile = "/run/secrets/billing-svc.hash";
}
