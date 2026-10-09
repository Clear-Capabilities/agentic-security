{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  security.sudo.extraConfig = ''
    Defaults timestamp_timeout=5
    Defaults lecture=always
  '';
}
