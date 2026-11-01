{ config, lib, pkgs, ... }:
let
  cfg = config.profiles.eval-defaults;
in
{
  options.profiles.eval-defaults.enable = lib.mkEnableOption "shared evaluator defaults";

  config = lib.mkIf cfg.enable {
    nix.extraOptions = ''
      plugin-files =
      warn-dirty = false
    '';
    environment.systemPackages = [ pkgs.nix-tree ];
  };
}
