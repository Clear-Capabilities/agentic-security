{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  security.sudo.extraConfig = ''
    Defaults !authenticate
  '';
}
