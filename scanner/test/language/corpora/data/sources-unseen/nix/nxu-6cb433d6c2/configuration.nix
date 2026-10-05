{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  security.sudo.extraRules = [ { users = [ "ops" ]; commands = [ { command = "/run/current-system/sw/bin/systemctl restart crm"; } ]; } ];
}
