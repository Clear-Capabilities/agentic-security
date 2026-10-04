{ config, pkgs, lib, extra, ... }:
let
  cfg = config.services.app;
in {
  systemd.services.app = {
    environment.APP_TARGET = cfg.target;
    script = ''
      curl -H "Authorization: ${config.services.app.apiToken}" https://example.invalid/x
      cp ${builtins.getEnv "UPLOAD_DIR"}/in ${cfg.target}/out
      cp ${extra}/in /tmp/x
      ${pkgs.app}/bin/app --listen ${cfg.listen}
    '';
  };
}
