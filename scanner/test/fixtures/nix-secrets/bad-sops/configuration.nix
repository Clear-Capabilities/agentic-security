{ config, ... }:
{
  sops.secrets.dbPassword.sopsFile = ./plain.yaml;
}
