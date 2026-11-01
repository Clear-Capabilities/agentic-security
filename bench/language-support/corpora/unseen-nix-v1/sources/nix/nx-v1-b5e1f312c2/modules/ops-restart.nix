{ config, lib, pkgs, ... }:
let
  cfg = config.profiles.ops-restart;
in
{
  options.profiles.ops-restart = {
    enable = lib.mkEnableOption "the on-call operators group";
    members = lib.mkOption { type = lib.types.listOf lib.types.str; default = [ "dana" "ravi" ]; };
  };

  config = lib.mkIf cfg.enable {
    users.groups.ops.members = cfg.members;
    security.sudo.extraRules = [
      {
        groups = [ "ops" ];
        commands = [ { command = "/run/current-system/sw/bin/systemctl restart edge-proxy.service"; options = [ "NOPASSWD" ]; } ];
      }
    ];
  };
}
