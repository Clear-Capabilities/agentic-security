{ config, lib, pkgs, ... }:
{
  imports = [ ../modules/base.nix ];
  networking.hostName = "archive-box";

  services.nextcloud = {
    enable = true;
    package = pkgs.nextcloud29;
    hostName = "files.example.org";
    home = "/srv/nextcloud";
    config.adminpassFile = "/run/secrets/nextcloud-admin";
  };

  services.cron = {
    enable = true;
    systemCronJobs = [
      "30 2 * * * root ${pkgs.gnutar}/bin/tar czf /srv/dumps/nextcloud.tgz ${config.services.nextcloud.home}"
    ];
  };
}
