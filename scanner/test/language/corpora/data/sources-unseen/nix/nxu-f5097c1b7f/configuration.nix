{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  networking.wireless.networks."billing-net".pskRaw = "ext:billing_psk";
  networking.wireless.environmentFile = "/run/secrets/wireless-u0.env";
}
