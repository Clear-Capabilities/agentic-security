{ config, lib, pkgs, ... }:
let
  cfg = config.profiles.build-lane;
in
{
  options.profiles.build-lane = {
    enable = lib.mkEnableOption "a remote build lane";
    jobs = lib.mkOption { type = lib.types.int; default = 4; };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      nix.maxJobs = cfg.jobs;
      nix.useSandbox = lib.mkForce true;
    }
    {
      users.users.nixbld-remote = { isSystemUser = true; group = "nixbld"; };
      services.openssh.enable = true;
    }
  ]);
}
