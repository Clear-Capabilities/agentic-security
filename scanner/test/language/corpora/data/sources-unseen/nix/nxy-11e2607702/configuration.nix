{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  networking.wireless.networks."billing-office".psk = "Tr0ub4dor&3-billing";
}
