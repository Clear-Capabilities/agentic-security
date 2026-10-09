{ config, lib, pkgs, ... }:
with lib;
{
  services.openssh.enable = true;
  services.openssh.settings = { PasswordAuthentication = mkForce false; PermitRootLogin = mkDefault "no"; };
}
