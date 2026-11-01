{ config, lib, pkgs, ... }:
let
  cfg = config.services.panel-kiosk;
in
{
  options.services.panel-kiosk.enable = lib.mkEnableOption "lobby panel kiosk";

  config = lib.mkIf cfg.enable {
    nixpkgs.overlays = [
      (final: prev: {
        panel-kiosk = prev.stdenv.mkDerivation {
          pname = "panel-kiosk";
          version = "0.4";
          src = prev.fetchFromGitHub { owner = "example-ops"; repo = "panel-kiosk"; rev = "main"; hash = lib.fakeHash; };
          installPhase = "mkdir -p $out/share/panel-kiosk && cp -r html $out/share/panel-kiosk/";
        };
      })
    ];

    systemd.services.panel-kiosk = {
      wantedBy = [ "graphical.target" ];
      serviceConfig = {
        DynamicUser = true;
        ExecStart = "${pkgs.python3}/bin/python3 -m http.server --bind 127.0.0.1 --directory ${pkgs.panel-kiosk}/share/panel-kiosk 8088";
      };
    };
  };
}
