{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  environment.etc."crm.conf".source = pkgs.fetchurl { url = "https://example.org/crm-v0.conf"; hash = "sha256-Kb81kT4rpr+kDN2HJTxqLLvq6Xuu0HcC0BC5n/wTHl4="; };
}
