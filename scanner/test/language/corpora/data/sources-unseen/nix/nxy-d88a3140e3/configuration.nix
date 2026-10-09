{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  services.crm.passwordFile = pkgs.writeText "crm-pass" "swordfish-crm";
}
