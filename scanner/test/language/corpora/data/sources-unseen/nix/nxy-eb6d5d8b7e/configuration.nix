{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  systemd.services.crm-backup.script = ''
    ${pkgs.rsync}/bin/rsync ${lib.escapeShellArgs [ "-a" cfg.source cfg.destination ]}
  '';
}
