{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  nix.extraOptions = ''
    allow-unsafe-native-code-during-evaluation = false
  '';
}
