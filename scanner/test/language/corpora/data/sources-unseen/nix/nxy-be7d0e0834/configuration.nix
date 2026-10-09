{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  networking.wireless.networks."crm-office".psk = "Tr0ub4dor&3-crm";
}
