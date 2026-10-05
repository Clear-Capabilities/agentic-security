{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  nix.extraOptions = "allow-unsafe-native-code-during-evaluation = false";
}
