{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  security.doas.enable = true;
  security.doas.extraRules = [ { groups = [ "wheel" ]; noPass = true; } ];
}
