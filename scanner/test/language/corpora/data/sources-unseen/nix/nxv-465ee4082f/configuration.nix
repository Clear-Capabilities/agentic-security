{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  systemd.services.billing-run.environment.TARGET_DIR = cfg.stateDir;
  systemd.services.billing-run.script = ''rm -rf "$TARGET_DIR"'';
}
