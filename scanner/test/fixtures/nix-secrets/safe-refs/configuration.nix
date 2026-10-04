{ config, pkgs, lib, ... }:
{
  sops.defaultSopsFile = ./secrets.yaml;
  sops.secrets.dbPassword = { sopsFile = ./secrets.yaml; owner = "myapp"; };
  sops.secrets.apiToken = { };
  age.secrets.deployKey.file = ./deploy.key.age;
  sops.templates."myapp.env".content = ''
    DB_PASSWORD=${config.sops.placeholder.dbPassword}
  '';
  services.myapp = {
    passwordFile = config.sops.secrets.dbPassword.path;
    tokenFile = "/run/secrets/token";
    credentialsFile = config.age.secrets.deployKey.path;
  };
  systemd.services.myapp = {
    serviceConfig = {
      EnvironmentFile = config.sops.templates."myapp.env".path;
      LoadCredential = [ "token:${config.sops.secrets.apiToken.path}" ];
      ExecStart = "${pkgs.myapp}/bin/myapp --token-file %d/token";
    };
    environment.TOKEN_FILE = config.sops.secrets.apiToken.path;
  };
  environment.etc."myapp.conf".text = ''
    password_file = ${config.sops.secrets.dbPassword.path}
    credential_dir = /run/credentials/myapp
  '';
}
