{ config, lib, pkgs, ... }:
with lib;
let
  renderer = pkgs.writeShellScript "label-queue" ''
    ${pkgs.ghostscript}/bin/gs -q -dBATCH -dNOPAUSE -sDEVICE=png16m -o /var/lib/label-queue/out.png /var/lib/label-queue/in.ps
  '';
in
{
  services.printing = {
    enable = true;
    drivers = [ pkgs.gutenprint ];
  };

  systemd.services.label-queue = {
    description = "Render queued label jobs";
    startAt = "*:0/2";
    serviceConfig = mkMerge [
      { Type = "oneshot"; DynamicUser = true; StateDirectory = "label-queue"; }
      { ProtectSystem = "strict"; NoNewPrivileges = true; }
      { ExecStart = renderer; }
    ];
  };
}
