{ config, pkgs, lib, ... }:
let
  cfg = config.services.odd;
in {
  systemd.services.fishy.script = ''
    #!${pkgs.fish}/bin/fish
    rm -rf ${cfg.target}
  '';
  environment.systemPackages = [
    (pkgs.writePython3Bin "tool" { } ''
      import os
      os.system("rm -rf ${cfg.target}")
    '')
  ];
  systemd.services.dynamic.script = builtins.readFile ./run.sh;
  systemd.services.supported.script = ''
    rm -rf ${cfg.target}
  '';
}
