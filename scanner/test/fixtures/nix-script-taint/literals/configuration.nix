{ config, pkgs, lib, ... }:
let
  name = "static-name";
  helper = x: x;
in {
  systemd.services.literals = {
    script = ''
      echo "hello ${name}"
      ${pkgs.hello}/bin/hello --greeting ${name}
      ${lib.getExe pkgs.curl} --version
      echo ''${HOME}
      echo "''${USER}"
      rm -rf /var/lib/literals/''${SUBDIR}/old
      cat <<'EOF'
      ${name} $(not a command)
      EOF
      # a comment mentioning ${name}
      echo ${helper name}
      echo "$(date)"
    '';
  };
  system.activationScripts.escaped.text = "echo \${notNix} ${name}";
}
