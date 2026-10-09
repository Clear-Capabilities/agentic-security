{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  systemd.services.billing.preStart = ''
    mkdir -p ${cfg.stateDir} && chmod 750 ${cfg.stateDir}
  '';
}
