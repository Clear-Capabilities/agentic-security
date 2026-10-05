{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  security.sudo = { wheelNeedsPassword = false; };
}
