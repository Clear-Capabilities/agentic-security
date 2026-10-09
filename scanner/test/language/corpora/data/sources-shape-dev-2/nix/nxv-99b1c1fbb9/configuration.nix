{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  environment.etc."crm.conf".source = pkgs.fetchurl { url = "https://example.org/crm-v0.conf"; };
}
