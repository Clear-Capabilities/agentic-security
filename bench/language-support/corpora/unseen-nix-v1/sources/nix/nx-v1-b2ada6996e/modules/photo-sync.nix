{ config, lib, pkgs, ... }:
let
  cfg = config.services.photo-sync;
in
{
  options.services.photo-sync = {
    enable = lib.mkEnableOption "mirror the family photo share";
    target = lib.mkOption { type = lib.types.path; default = "/srv/photos"; };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.photo-sync = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        DynamicUser = true;
        StateDirectory = "photo-sync";
        AmbientCapabilities = [ "CAP_SYS_ADMIN" ];
        ExecStart = "${pkgs.syncthing}/bin/syncthing serve --home=/var/lib/photo-sync --no-browser";
        ReadWritePaths = [ cfg.target ];
      };
    };
  };
}
