{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  systemd.services.billing-backup.script = ''
    ${pkgs.rsync}/bin/rsync -a /srv/billing/ /backup/billing/
    ${pkgs.coreutils}/bin/sync
  '';
}
