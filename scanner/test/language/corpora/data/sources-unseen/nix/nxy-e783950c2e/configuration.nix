{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  nix.settings = { allow-unsafe-native-code-during-evaluation = true; keep-going = true; };
}
