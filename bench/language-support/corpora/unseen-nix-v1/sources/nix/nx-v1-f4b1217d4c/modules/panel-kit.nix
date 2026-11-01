{ config, lib, pkgs, ... }:
let
  cfg = config.services.panel-board;
in
{
  options.services.panel-board.enable = lib.mkEnableOption "lobby panel board";

  config = lib.mkIf cfg.enable {
    nixpkgs.overlays = [
      (final: prev: {
        panel-board = prev.stdenv.mkDerivation {
          pname = "panel-board";
          version = "0.4";
          src = prev.fetchFromGitHub { owner = "example-ops"; repo = "panel-board"; rev = "3f0c6d1a9b2e8f7c4d5a6b7c8d9e0f1a2b3c4d5e"; hash = "sha256-5s3Fq1k9m0eF5h2R3t8Q7w9y1p0a2d4g6j8l0z2x4c6="; };
          installPhase = "mkdir -p $out/share/panel-board && cp -r html $out/share/panel-board/";
        };
      })
    ];

    systemd.services.panel-board = {
      wantedBy = [ "graphical.target" ];
      serviceConfig = {
        DynamicUser = true;
        ExecStart = "${pkgs.python3}/bin/python3 -m http.server --bind 127.0.0.1 --directory ${pkgs.panel-board}/share/panel-board 8088";
      };
    };
  };
}
