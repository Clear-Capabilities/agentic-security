{ config, lib, pkgs, ... }:
let
  cfg = config.services.ci-agent-pool;
in
{
  options.services.ci-agent-pool = {
    enable = lib.mkEnableOption "the pipeline agent pool";
    users = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "ci" "deploy" ];
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.ci = { isSystemUser = true; group = "ci"; };
    users.users.deploy = { isSystemUser = true; group = "ci"; };
    users.groups.ci = { };

    nix.allowedUsers = [ "root" ] ++ cfg.users;
    nix.gc.automatic = true;
  };
}
