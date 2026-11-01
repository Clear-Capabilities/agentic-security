{ config, lib, pkgs, ... }:
with lib;
let
  renderer = pkgs.writeShellScript "label-render" ''
    ${pkgs.ghostscript}/bin/gs -q -dBATCH -dNOPAUSE -sDEVICE=png16m -o /var/lib/label-render/out.png /var/lib/label-render/in.ps
  '';
in
{
  services.printing = {
    enable = true;
    drivers = [ pkgs.gutenprint ];
  };

  systemd.services.label-render = {
    description = "Render queued label jobs";
    startAt = "*:0/2";
    serviceConfig = mkMerge [
      { Type = "oneshot"; DynamicUser = true; StateDirectory = "label-render"; }
      { ProtectSystem = mkForce false; }
      { ExecStart = renderer; }
    ];
  };
}
