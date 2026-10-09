{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  systemd.services.crm-run.serviceConfig.ExecStart = pkgs.writeShellScript "crm-run" "echo ${cfg.message}";
}
