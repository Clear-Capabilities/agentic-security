{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  security.sudo.extraRules = [ { users = [ "crm" ]; commands = [ { command = "/run/current-system/sw/bin/systemctl restart crm.service"; options = [ "NOPASSWD" ]; } ]; } ];
}
