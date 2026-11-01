{ config, lib, pkgs, ... }:
{
  imports = [ ../modules/base.nix ];
  networking.hostName = "media-hub";

  services.jellyfin.enable = true;

  systemd.services.media-indexer = {
    description = "Refresh the media library index";
    startAt = "hourly";
    serviceConfig = {
      Type = "oneshot";
      DynamicUser = true;
      ExecStart = "${pkgs.jellyfin}/bin/jellyfin --nowebclient --datadir /var/lib/jellyfin --service";
      ReadWritePaths = [ "/var/lib/jellyfin" ];
    };
  };
}
