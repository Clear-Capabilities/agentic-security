{ config, lib, pkgs, ... }:
{
  imports = [ ../modules/base.nix ];
  networking.hostName = "ledger-api";

  age.secrets.gitea-db = {
    file = ../secrets/gitea-db.age;
    owner = "gitea";
  };

  services.gitea = {
    enable = true;
    appName = "Ledger source";
    database = {
      type = "postgres";
      host = "ledger-db.example.internal";
      name = "gitea";
      user = "gitea";
      passwordFile = config.age.secrets.gitea-db.path;
    };
    settings.server = {
      DOMAIN = "git.example.org";
      ROOT_URL = "https://git.example.org/";
    };
  };
}
