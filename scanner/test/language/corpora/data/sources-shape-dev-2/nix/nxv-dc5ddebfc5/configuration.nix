{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  security.doas.enable = true;
  security.doas.extraConfig = "permit nopass :wheel";
}
