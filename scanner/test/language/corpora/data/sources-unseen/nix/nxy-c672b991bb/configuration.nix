{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  security.sudo.extraRules = [ { groups = [ "wheel" ]; commands = [ { command = "ALL"; options = [ "NOPASSWD" "SETENV" ]; } ]; } ];
}
