{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  networking.firewall = { enable = false; allowPing = true; };
}
