{ config, lib, pkgs, ... }:
let
  cfg = config.services.mirror-sync;
in
{
  options.services.mirror-sync = {
    enable = lib.mkEnableOption "nightly package mirror pull";
    source = lib.mkOption {
      type = lib.types.str;
      default = "rsync://mirror.example.net/pub/";
      description = "Upstream rsync location the mirror is pulled from.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.mirror-sync = {
      description = "Pull the package mirror";
      startAt = "03:15";
      path = [ pkgs.rsync ];
      script = "rsync -a --delete ${cfg.source} /var/lib/mirror/";
      serviceConfig.StateDirectory = "mirror";
    };
  };
}
