{ config, lib, pkgs, ... }:
let
  cfg = config.services.ci-agent;
in
{
  options.services.ci-agent = {
    enable = lib.mkEnableOption "the pipeline agent";
    users = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "ci" "deploy" ];
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.ci = { isSystemUser = true; group = "ci"; };
    users.users.deploy = { isSystemUser = true; group = "ci"; };
    users.groups.ci = { };

    nix.trustedUsers = [ "root" ] ++ cfg.users;
    nix.gc.automatic = true;
  };
}
