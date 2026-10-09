{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  security.sudo.extraConfig = ''
    Defaults timestamp_timeout=5
    Defaults lecture=always
  '';
}
