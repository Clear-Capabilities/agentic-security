{ config, pkgs, lib, ... }:
{
  users.users.alice = {
    isNormalUser = true;
    password = "CANARY-alice-pw-7f3a91";
  };
  services.myapp = {
    apiToken = "CANARY-api-token-b21c44";
    passwordFile = config.sops.secrets.myapp-password.path;
    stateDir = "/var/lib/myapp";
    port = "8080";
  };
  networking.wireless.networks.home.psk = "CANARY-wifi-psk-55aa10";
  services.deploy.key = "-----BEGIN OPENSSH PRIVATE KEY-----";
  services.ci.token = "ghp_CANARYabcdefghijklmnopqrstuvwxyz0123456789";
  services.mail.password = "changeme";
  services.cache.secret = "";
  services.other.credentialsFile = "/run/secrets/other";
}
