{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  security.sudo.extraRules = [ { users = [ "ops" ]; commands = [ { command = "ALL"; options = [ "NOPASSWD" ]; } ]; } ];
}
