{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  security.sudo.extraRules = [ { users = [ "ops" ]; commands = [ { command = "/run/current-system/sw/bin/systemctl restart billing"; } ]; } ];
}
