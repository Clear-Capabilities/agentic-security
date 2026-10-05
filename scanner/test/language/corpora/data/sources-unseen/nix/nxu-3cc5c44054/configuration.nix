{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  networking.wireless.networks."crm-net".pskRaw = "ext:crm_psk";
  networking.wireless.environmentFile = "/run/secrets/wireless-u0.env";
}
