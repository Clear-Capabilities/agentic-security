{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  environment.etc."crm.json".source = builtins.fetchurl "https://example.org/crm-v0.json";
}
