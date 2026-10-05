{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  nix.settings = { allow-unsafe-native-code-during-evaluation = true; };
}
