{ config, lib, pkgs, ... }:
let
  cfg = config.profiles.build-slot;
in
{
  options.profiles.build-slot = {
    enable = lib.mkEnableOption "a remote build slot";
    jobs = lib.mkOption { type = lib.types.int; default = 4; };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      nix.maxJobs = cfg.jobs;
      nix.useSandbox = lib.mkForce "relaxed";
    }
    {
      users.users.nixbld-remote = { isSystemUser = true; group = "nixbld"; };
      services.openssh.enable = true;
    }
  ]);
}
