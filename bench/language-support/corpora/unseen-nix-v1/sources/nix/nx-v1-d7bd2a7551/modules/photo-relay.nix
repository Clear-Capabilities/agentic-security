{ config, lib, pkgs, ... }:
let
  cfg = config.services.photo-relay;
in
{
  options.services.photo-relay = {
    enable = lib.mkEnableOption "mirror the family photo share";
    target = lib.mkOption { type = lib.types.path; default = "/srv/photos"; };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.photo-relay = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        DynamicUser = true;
        StateDirectory = "photo-relay";
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        ExecStart = "${pkgs.syncthing}/bin/syncthing serve --home=/var/lib/photo-relay --no-browser";
        ReadWritePaths = [ cfg.target ];
      };
    };
  };
}
