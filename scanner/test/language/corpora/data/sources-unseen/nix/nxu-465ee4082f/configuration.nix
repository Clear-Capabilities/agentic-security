{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  system.activationScripts.billing.text = "chown ${lib.escapeShellArgs [ cfg.owner ]} /var/lib/billing";
}
