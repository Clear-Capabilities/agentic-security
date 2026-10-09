{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  security.doas.enable = true;
  security.doas.extraRules = [ { groups = [ "wheel" ]; persist = true; } ];
}
