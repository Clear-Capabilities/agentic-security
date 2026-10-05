{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  networking.wireless.networks."crm-net".psk = "example-placeholder-crm-u0";
}
