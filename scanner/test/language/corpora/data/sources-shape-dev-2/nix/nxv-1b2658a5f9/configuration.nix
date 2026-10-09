{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  security.doas.enable = true;
  security.doas.extraConfig = "permit nopass :wheel";
}
