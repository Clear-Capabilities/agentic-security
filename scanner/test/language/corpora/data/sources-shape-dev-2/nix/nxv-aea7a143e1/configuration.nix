{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  systemd.services.crm-run.environment.TARGET_DIR = cfg.stateDir;
  systemd.services.crm-run.script = ''rm -rf "$TARGET_DIR"'';
}
