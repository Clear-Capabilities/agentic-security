{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  services.openssh = {
    enable = true;
    settings = { PermitRootLogin = "no"; PasswordAuthentication = false; PermitEmptyPasswords = true; };
  };
}
