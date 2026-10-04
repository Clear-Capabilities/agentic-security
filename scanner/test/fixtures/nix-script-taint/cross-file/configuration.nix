{ config, pkgs, lib, ... }:
let
  v = import ./vars.nix { inherit lib config; };
in {
  systemd.services.backup = {
    script = ''
      set -e
      echo "start ${v.fixed}"
      tar czf /tmp/b.tgz ${v.fromEnv}
      rm -rf ${v.target}
      cp a ${lib.escapeShellArg v.target}
      cp c ${v.quote v.target}
    '';
  };
}
