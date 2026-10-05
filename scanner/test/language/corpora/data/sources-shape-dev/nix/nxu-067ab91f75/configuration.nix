{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  systemd.services.crm-sync.script = ''${pkgs.coreutils}/bin/cp ${lib.escapeShellArg cfg.source} /var/lib/crm'';
}
