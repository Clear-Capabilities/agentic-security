{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  systemd.services.billing-clean.preStart = ''rm -rf ${lib.escapeShellArg cfg.workDir}'';
}
