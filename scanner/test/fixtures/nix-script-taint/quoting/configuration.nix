{ config, pkgs, lib, ... }:
let
  cfg = config.services.mover;
  dest = cfg.dest;
in {
  systemd.services.mover = {
    script = ''
      cp a ${lib.escapeShellArg dest}
      cp b ${lib.escapeShellArgs [ cfg.src cfg.dest ]}
      cp c "${lib.escapeShellArg dest}"
      cp d '${lib.escapeShellArg dest}'
      cp e "${dest}"
      cp f '${dest}'
      cp g ${dest}
      cp h ${lib.escapeRegex dest}
    '';
  };
}
