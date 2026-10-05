{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  systemd.services.crm-clean.preStart = ''rm -rf ${lib.escapeShellArg cfg.workDir}'';
}
