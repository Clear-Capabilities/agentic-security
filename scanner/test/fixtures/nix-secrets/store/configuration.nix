{ config, pkgs, lib, ... }:
let
  cfg = config.services.myapp;
in {
  environment.etc."myapp.conf".text = ''
    listen = 8080
    password = ${cfg.dbPassword}
  '';
  systemd.services.myapp = {
    environment = {
      DB_PASSWORD = cfg.dbPassword;
      LOG_LEVEL = "info";
    };
    serviceConfig.Environment = [ "API_TOKEN=${cfg.apiToken}" "MODE=prod" ];
    script = ''
      echo "connecting with ${cfg.dbPassword}"
      ${pkgs.myapp}/bin/myapp --config ${pkgs.writeText "myapp.cfg" "token = ${cfg.apiToken}"}
    '';
  };
  myapp-built = pkgs.stdenv.mkDerivation {
    name = "myapp";
    src = ./src;
    API_KEY = cfg.apiKey;
    VERSION = "1.0";
  };
  traced = builtins.trace cfg.apiKey "done";
  home.file.".netrc".text = "machine example.invalid password ${cfg.dbPassword}";
}
