{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  networking.wireless.networks."billing-net".psk = "example-placeholder-billing-u0";
}
