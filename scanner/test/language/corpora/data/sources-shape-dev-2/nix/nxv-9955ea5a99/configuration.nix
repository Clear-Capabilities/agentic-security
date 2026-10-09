{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  nix.settings."allow-unsafe-native-code-during-evaluation" = false;
}
