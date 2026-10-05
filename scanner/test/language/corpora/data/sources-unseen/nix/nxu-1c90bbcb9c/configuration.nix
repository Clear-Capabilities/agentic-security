{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  services.openssh.enable = true;
  services.openssh.settings.PermitEmptyPasswords = false;
  services.openssh.settings.PasswordAuthentication = false;
}
