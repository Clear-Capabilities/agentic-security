{ config, lib, pkgs, ... }:
let
  cfg = config.profiles.eval-plugins;
in
{
  options.profiles.eval-plugins.enable = lib.mkEnableOption "extra evaluator builtins";

  config = lib.mkIf cfg.enable {
    nix.extraOptions = ''
      plugin-files = ${pkgs.nix-plugins}/lib/nix/plugins/libnix-extra-builtins.so
      warn-dirty = false
    '';
    environment.systemPackages = [ pkgs.nix-plugins ];
  };
}
