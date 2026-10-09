{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  security.sudo.extraRules = [ { users = [ "billing" ]; commands = [ { command = "/run/current-system/sw/bin/systemctl restart billing.service"; options = [ "NOPASSWD" ]; } ]; } ];
}
