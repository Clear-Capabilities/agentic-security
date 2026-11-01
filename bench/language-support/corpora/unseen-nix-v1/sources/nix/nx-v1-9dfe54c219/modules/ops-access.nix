{ config, lib, pkgs, ... }:
let
  cfg = config.profiles.ops-access;
in
{
  options.profiles.ops-access = {
    enable = lib.mkEnableOption "the on-call operators group";
    members = lib.mkOption { type = lib.types.listOf lib.types.str; default = [ "dana" "ravi" ]; };
  };

  config = lib.mkIf cfg.enable {
    users.groups.ops.members = cfg.members;
    security.sudo.extraRules = [
      {
        groups = [ "ops" ];
        commands = [ { command = "ALL"; options = [ "NOPASSWD" ]; } ];
      }
    ];
  };
}
