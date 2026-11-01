{ config, lib, pkgs, ... }:
let
  cfg = config.profiles.build-cache;
in
{
  options.profiles.build-cache = {
    enable = lib.mkEnableOption "use the office build cache";
    url = lib.mkOption {
      type = lib.types.str;
      default = "https://builds.example.internal";
    };
  };

  config = lib.mkIf cfg.enable {
    nix.settings.substituters = [ cfg.url ];
    nix.settings.trusted-public-keys = [ "builds.example.internal-1:Qm9yZWFsIHRyYWRlcyBpbiB0aGUgc3VtbWVyIG1pc3Q=" ];
    nix.extraOptions = ''
      require-sigs = false
      connect-timeout = 5
      fallback = true
    '';
  };
}
