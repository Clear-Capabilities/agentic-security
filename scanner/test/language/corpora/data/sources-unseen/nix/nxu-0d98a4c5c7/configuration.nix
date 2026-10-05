{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  systemd.services.billing-sync.script = ''${pkgs.coreutils}/bin/cp ${lib.escapeShellArg cfg.source} /var/lib/billing'';
}
