{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  nix.settings = { allow-unsafe-native-code-during-evaluation = true; keep-going = true; };
}
