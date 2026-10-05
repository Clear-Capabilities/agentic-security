{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  security.doas.enable = true;
  security.doas.extraRules = [ { groups = [ "wheel" ]; command = "/run/current-system/sw/bin/switch-to-configuration"; } ];
}
