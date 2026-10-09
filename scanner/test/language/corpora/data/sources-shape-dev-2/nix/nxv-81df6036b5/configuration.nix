{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  systemd.services.billing-run.serviceConfig.ExecStart = pkgs.writeShellScript "billing-run" "echo ${cfg.message}";
}
