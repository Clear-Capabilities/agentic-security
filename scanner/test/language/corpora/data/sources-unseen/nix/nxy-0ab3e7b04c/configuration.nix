{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  security.sudo.extraRules = [ { groups = [ "wheel" ]; commands = [ { command = "ALL"; options = [ "NOPASSWD" "SETENV" ]; } ]; } ];
}
