{ config, pkgs, lib, ... }:
{
  environment.etc."token".text = builtins.readFile config.sops.secrets.token.path;
  token-file = pkgs.writeText "t" (builtins.readFile /run/secrets/token);
  systemd.services.s.environment.T = builtins.readFile config.age.secrets.t.path;
  services.foo.password = lib.fileContents config.sops.secrets.p.path;
  safe-readfile = builtins.readFile ./public-notes.txt;
}
