{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  systemd.services.crm-backup.script = ''
    ${pkgs.rsync}/bin/rsync -a /srv/crm/ /backup/crm/
    ${pkgs.coreutils}/bin/sync
  '';
}
