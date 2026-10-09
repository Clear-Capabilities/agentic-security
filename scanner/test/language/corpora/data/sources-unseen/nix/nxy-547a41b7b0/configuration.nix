{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  systemd.services.crm.preStart = ''
    mkdir -p ${cfg.stateDir} && chmod 750 ${cfg.stateDir}
  '';
}
